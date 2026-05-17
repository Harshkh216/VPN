"""
server.py - VPN Server Core (Fixed file transfer to use JSON chunks)
"""
from __future__ import annotations
import ssl, socket, threading, json, os, time, base64
from datetime import datetime
from .encryption import (generate_aes_key, encrypt_message, decrypt_message,
                          key_to_b64, b64_to_key, encrypt_bytes, decrypt_bytes)
from .auth import AuthManager, AuthError
from . import database as db
from .logger import get_logger

log = get_logger("server")

HOST        = "0.0.0.0"
PORT        = 9443
CERT_FILE   = os.path.join(os.path.dirname(__file__), '..', 'certificates', 'server.crt')
KEY_FILE    = os.path.join(os.path.dirname(__file__), '..', 'certificates', 'server.key')
BUFFER_SIZE = 65536
MAX_MSG_LEN = 10 * 1024

_clients: dict[str, "ClientHandler"] = {}
_clients_lock = threading.Lock()

on_client_connect    = None
on_client_disconnect = None
on_message           = None
on_stats_update      = None


class ClientHandler(threading.Thread):
    def __init__(self, ssl_sock, addr):
        super().__init__(daemon=True)
        self.ssl_sock     = ssl_sock
        self.ip           = addr[0]
        self.port         = addr[1]
        self.username     = None
        self.token        = None
        self.aes_key      = generate_aes_key()
        self.conn_id      = None
        self.bytes_sent   = 0
        self.bytes_recv   = 0
        self.connected_at = time.time()

    def run(self):
        log.info(f"New connection from {self.ip}:{self.port}")
        try:
            self._key_exchange()
            self._authenticate()
            self._message_loop()
        except (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError):
            log.warning(f"Client {self.ip} disconnected abruptly.")
        except Exception as exc:
            log.error(f"Client error [{self.ip}]: {exc}")
        finally:
            self._cleanup()

    def _key_exchange(self):
        payload = json.dumps({"type": "KEY", "key": key_to_b64(self.aes_key)})
        self._send_raw(payload)

    def _authenticate(self):
        raw  = self._recv_encrypted()
        data = json.loads(raw)
        action   = data.get("action")
        username = data.get("username", "")
        password = data.get("password", "")

        if action == "register":
            try:
                AuthManager.register(username, password)
                self._send_encrypted(json.dumps({"status": "ok", "msg": "Registration successful."}))
                raw2 = self._recv_encrypted()
                data = json.loads(raw2)
                username = data.get("username", "")
                password = data.get("password", "")
            except AuthError as e:
                self._send_encrypted(json.dumps({"status": "error", "msg": str(e)}))
                raise

        try:
            self.token    = AuthManager.login(username, password, self.ip)
            self.username = username
        except AuthError as e:
            self._send_encrypted(json.dumps({"status": "error", "msg": str(e)}))
            raise

        self.conn_id = db.log_connection(username, self.ip)
        self._send_encrypted(json.dumps({
            "status": "ok",
            "msg":    f"Welcome {username}!",
            "token":  self.token
        }))

        with _clients_lock:
            _clients[username] = self
        log.info(f"User '{username}' authenticated from {self.ip}")
        if on_client_connect:
            on_client_connect(username, self.ip)
        self._broadcast(json.dumps({"type": "system",
                                     "msg":  f"🔒 {username} joined."}),
                         exclude_self=True)

    def _message_loop(self):
        while True:
            raw = self._recv_encrypted()
            if raw is None:
                break
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                continue

            msg_type = data.get("type", "chat")

            if msg_type == "chat":
                self._handle_chat(data)
            elif msg_type == "file_start":
                self._handle_file_receive(data)
            elif msg_type == "ping":
                self._send_encrypted(json.dumps({"type": "pong"}))
            elif msg_type == "disconnect":
                break

    def _handle_chat(self, data):
        text      = data.get("text", "")[:MAX_MSG_LEN]
        timestamp = datetime.now().strftime("%H:%M:%S")
        envelope  = json.dumps({
            "type":      "chat",
            "sender":    self.username,
            "text":      text,
            "timestamp": timestamp,
        })
        log.info(f"[CHAT] {self.username}: {text}")
        if on_message:
            on_message(self.username, text)
        self._broadcast(envelope)

    def _handle_file_receive(self, meta):
        """
        Receive file chunks sent as base64-encoded JSON messages.
        Protocol:
          CLIENT → {type: file_start, filename, size}
          SERVER → {type: file_ready}
          CLIENT → {type: file_chunk, index, data (b64), size} x N
          CLIENT → {type: file_end, filename, total_chunks}
          SERVER → {type: file_done, msg}
        """
        filename = os.path.basename(meta.get("filename", "upload.bin"))
        log.info(f"File transfer started: {self.username} → {filename}")

        # Acknowledge ready
        self._send_encrypted(json.dumps({"type": "file_ready"}))

        save_dir  = os.path.join(os.path.dirname(__file__), '..', 'received_files')
        os.makedirs(save_dir, exist_ok=True)
        save_path = os.path.join(save_dir, f"{self.username}_{filename}")

        chunks = {}   # index → decrypted bytes

        while True:
            raw = self._recv_encrypted()
            if raw is None:
                break
            data = json.loads(raw)
            t    = data.get("type")

            if t == "file_chunk":
                idx       = data["index"]
                b64_data  = data["data"]
                enc_bytes = base64.b64decode(b64_data)
                # Decrypt the chunk using the session AES key
                plain     = decrypt_bytes(self.aes_key, enc_bytes)
                chunks[idx] = plain
                self.bytes_recv += len(enc_bytes)

            elif t == "file_end":
                total = data.get("total_chunks", 0)
                # Write chunks in order
                with open(save_path, "wb") as f:
                    for i in range(total):
                        f.write(chunks.get(i, b""))
                received = sum(len(v) for v in chunks.values())
                log.info(f"File '{filename}' saved ({received} bytes)")
                self._send_encrypted(json.dumps({
                    "type": "file_done",
                    "msg":  f"✅ File '{filename}' received ({received} bytes)."
                }))
                self._broadcast(json.dumps({
                    "type": "system",
                    "msg":  f"📁 {self.username} shared file: {filename}"
                }), exclude_self=True)
                break

    def _broadcast(self, plaintext, exclude_self=False):
        with _clients_lock:
            targets = list(_clients.values())
        for handler in targets:
            if exclude_self and handler is self:
                continue
            try:
                handler._send_encrypted(plaintext)
            except Exception:
                pass

    def _send_raw(self, text):
        data = (text + "\n").encode("utf-8")
        self.ssl_sock.sendall(data)
        self.bytes_sent += len(data)

    def _send_encrypted(self, plaintext):
        token = encrypt_message(self.aes_key, plaintext)
        data  = (token + "\n").encode("utf-8")
        self.ssl_sock.sendall(data)
        self.bytes_sent += len(data)

    def _recv_raw_line(self):
        buf = b""
        while True:
            chunk = self.ssl_sock.recv(BUFFER_SIZE)
            if not chunk:
                return None
            buf += chunk
            if b"\n" in buf:
                line, _ = buf.split(b"\n", 1)
                return line.decode("utf-8")

    def _recv_encrypted(self):
        token = self._recv_raw_line()
        if token is None:
            return None
        decrypted = decrypt_message(self.aes_key, token)
        self.bytes_recv += len(token)
        return decrypted

    def _cleanup(self):
        if self.username:
            with _clients_lock:
                _clients.pop(self.username, None)
            if self.token:
                AuthManager.logout(self.token)
            if self.conn_id:
                db.close_connection_log(self.conn_id, self.bytes_sent, self.bytes_recv)
            self._broadcast(json.dumps({"type": "system",
                                         "msg":  f"🔓 {self.username} left."}))
            if on_client_disconnect:
                on_client_disconnect(self.username)
            log.info(f"User '{self.username}' disconnected.")
        try:
            self.ssl_sock.close()
        except Exception:
            pass


class VPNServer:
    def __init__(self, host=HOST, port=PORT):
        self.host     = host
        self.port     = port
        self._running = False
        self._sock    = None

    def start(self):
        AuthManager.setup()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind((self.host, self.port))
        raw_sock.listen(50)
        self._sock    = ctx.wrap_socket(raw_sock, server_side=True)
        self._running = True
        log.info(f"VPN Server listening on {self.host}:{self.port}")
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while self._running:
            try:
                ssl_sock, addr = self._sock.accept()
                ClientHandler(ssl_sock, addr).start()
            except ssl.SSLError as e:
                log.warning(f"SSL error: {e}")
            except OSError:
                break

    def stop(self):
        self._running = False
        with _clients_lock:
            for h in list(_clients.values()):
                try:
                    h.ssl_sock.close()
                except Exception:
                    pass
            _clients.clear()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        log.info("VPN Server stopped.")

    @staticmethod
    def get_connected_clients():
        with _clients_lock:
            return [
                {"username": h.username, "ip": h.ip,
                 "connected_since": datetime.fromtimestamp(h.connected_at).strftime("%H:%M:%S"),
                 "bytes_sent": h.bytes_sent, "bytes_recv": h.bytes_recv}
                for h in _clients.values()
            ]

    @staticmethod
    def kick_user(username):
        with _clients_lock:
            handler = _clients.get(username)
        if handler:
            try:
                handler.ssl_sock.close()
            except Exception:
                pass
