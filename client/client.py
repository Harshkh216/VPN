"""
client.py - VPN Client Core (Definitive Fix)
Single reader thread owns the socket. File transfer uses an event queue.
"""
from __future__ import annotations
import ssl, socket, threading, json, os, time, base64, queue
from .encryption import (encrypt_message, decrypt_message, b64_to_key, encrypt_bytes)

BUFFER_SIZE = 65536
CHUNK_SIZE  = 16384

class VPNClient:
    def __init__(self, host="127.0.0.1", port=9443):
        self.host          = host
        self.port          = port
        self.ssl_sock      = None
        self.aes_key       = None
        self.username      = None
        self.token         = None
        self.connected     = False
        self.bytes_sent    = 0
        self.bytes_recv    = 0

        # All incoming decrypted messages go into this queue
        self._msg_queue    = queue.Queue()
        # When True, dispatch thread skips and send_file reads queue directly
        self._file_mode    = False

        self.on_message    = None
        self.on_system     = None
        self.on_file_done  = None
        self.on_disconnect = None

    # ── Connect ───────────────────────────────────────────────────────────────

    def connect(self, username: str, password: str, action: str = "login") -> dict:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        raw           = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssl_sock = ctx.wrap_socket(raw, server_hostname=self.host)
        self.ssl_sock.connect((self.host, self.port))

        # --- Auth phase: read directly (no threads yet) ----------------------
        key_msg      = json.loads(self._read_line_direct())
        self.aes_key = b64_to_key(key_msg["key"])

        self._send_encrypted(json.dumps({
            "action": action, "username": username, "password": password
        }))

        if action == "register":
            ack = json.loads(decrypt_message(self.aes_key, self._read_line_direct()))
            if ack.get("status") != "ok":
                return ack
            self._send_encrypted(json.dumps({
                "action": "login", "username": username, "password": password
            }))

        resp = json.loads(decrypt_message(self.aes_key, self._read_line_direct()))

        if resp.get("status") == "ok":
            self.username  = username
            self.token     = resp.get("token")
            self.connected = True
            # Start reader and dispatcher AFTER auth
            threading.Thread(target=self._reader_thread,   daemon=True).start()
            threading.Thread(target=self._dispatch_thread, daemon=True).start()

        return resp

    # ── Disconnect ────────────────────────────────────────────────────────────

    def disconnect(self):
        if self.connected:
            try:
                self._send_encrypted(json.dumps({"type": "disconnect"}))
            except Exception:
                pass
        self.connected = False
        try:
            self.ssl_sock.close()
        except Exception:
            pass
        self._msg_queue.put(None)   # Unblock any waiting get()
        if self.on_disconnect:
            self.on_disconnect()

    # ── Chat ──────────────────────────────────────────────────────────────────

    def send_message(self, text: str):
        self._send_encrypted(json.dumps({"type": "chat", "text": text}))

    # ── File transfer ─────────────────────────────────────────────────────────

    def send_file(self, filepath: str, progress_cb=None) -> bool:
        """
        File transfer flow:
          1. Set _file_mode = True  (dispatch thread stops processing)
          2. Send file_start
          3. Read file_ready directly from queue
          4. Send chunks
          5. Send file_end
          6. Read file_done directly from queue
          7. Set _file_mode = False (dispatch resumes)
        """
        filename   = os.path.basename(filepath)
        total_size = os.path.getsize(filepath)

        self._file_mode = True
        try:
            # Announce
            self._send_encrypted(json.dumps({
                "type": "file_start", "filename": filename, "size": total_size
            }))

            # Wait for file_ready
            resp = self._queue_get(timeout=15)
            if resp is None or resp.get("type") != "file_ready":
                return False

            # Send chunks
            sent = 0
            idx  = 0
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    enc   = encrypt_bytes(self.aes_key, chunk)
                    b64   = base64.b64encode(enc).decode()
                    self._send_encrypted(json.dumps({
                        "type": "file_chunk", "index": idx,
                        "data": b64, "size": len(chunk)
                    }))
                    sent += len(chunk)
                    idx  += 1
                    self.bytes_sent += len(b64)
                    if progress_cb:
                        progress_cb(int(sent / total_size * 100))

            # End signal
            self._send_encrypted(json.dumps({
                "type": "file_end", "filename": filename, "total_chunks": idx
            }))

            # Wait for confirmation
            done = self._queue_get(timeout=30)
            if done and self.on_file_done:
                self.on_file_done(done.get("msg", "File sent."))

            return True

        except Exception as e:
            if self.on_system:
                self.on_system(f"File transfer error: {e}")
            return False

        finally:
            self._file_mode = False

    # ── Reader thread: ONLY thread that touches the socket after auth ─────────

    def _reader_thread(self):
        """
        Reads raw bytes from SSL socket, splits on newline,
        decrypts each line, and pushes the parsed dict into _msg_queue.
        This is the ONLY place ssl_sock.recv() is called after login.
        """
        buf = b""
        while self.connected:
            try:
                chunk = self.ssl_sock.recv(BUFFER_SIZE)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        text = decrypt_message(self.aes_key, line.decode("utf-8"))
                        data = json.loads(text)
                        self.bytes_recv += len(line)
                        self._msg_queue.put(data)
                    except Exception:
                        pass   # Bad frame — skip it
            except Exception:
                break

        self.connected = False
        self._msg_queue.put(None)   # Sentinel to unblock dispatch/file threads
        if self.on_disconnect:
            self.on_disconnect()

    # ── Dispatch thread: routes queue messages to callbacks ───────────────────

    def _dispatch_thread(self):
        """
        Pulls dicts from _msg_queue and calls the right callback.
        Skips (re-queues) messages when _file_mode is True so
        send_file() can read them directly.
        """
        held = []   # Messages held while in file_mode
        while self.connected:
            try:
                data = self._msg_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            if data is None:
                break   # Sentinel — shutdown

            if self._file_mode:
                # Hold chat/system messages; file responses go back to queue
                t = data.get("type", "")
                if t in ("file_ready", "file_done"):
                    self._msg_queue.put(data)   # send_file will read this
                else:
                    held.append(data)           # Replay after transfer
                continue

            # Re-queue any held messages first
            while held:
                self._dispatch(held.pop(0))

            self._dispatch(data)

        # Flush held messages on exit
        for d in held:
            self._dispatch(d)

    def _dispatch(self, data: dict):
        t = data.get("type", "")
        if t == "chat":
            if self.on_message:
                self.on_message(data.get("sender", "?"),
                                data.get("text", ""),
                                data.get("timestamp", ""))
        elif t == "system":
            if self.on_system:
                self.on_system(data.get("msg", ""))
        elif t == "file_done":
            if self.on_file_done:
                self.on_file_done(data.get("msg", ""))

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _queue_get(self, timeout: float = 30.0) -> dict | None:
        """Block until a message arrives in the queue or timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data = self._msg_queue.get(timeout=0.5)
                if data is None:
                    return None
                return data
            except queue.Empty:
                continue
        return None

    def _send_encrypted(self, plaintext: str):
        token = encrypt_message(self.aes_key, plaintext)
        self.ssl_sock.sendall((token + "\n").encode("utf-8"))

    def _read_line_direct(self) -> str:
        """Read one raw line directly — only used before reader thread starts."""
        buf = b""
        while True:
            chunk = self.ssl_sock.recv(BUFFER_SIZE)
            if not chunk:
                raise ConnectionError("Server closed connection.")
            buf += chunk
            if b"\n" in buf:
                line, _ = buf.split(b"\n", 1)
                return line.decode("utf-8")

    def ping(self):
        try:
            self._send_encrypted(json.dumps({"type": "ping"}))
        except Exception:
            pass
