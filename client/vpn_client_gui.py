"""
vpn_client_gui.py - VPN Client GUI
Modern dark-theme Tkinter interface for connecting, chatting, and file transfer.
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading, os, sys, time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from client.client import VPNClient

# ── Colours ───────────────────────────────────────────────────────────────────
BG      = "#0d1117"
BG2     = "#161b22"
BG3     = "#21262d"
ACCENT  = "#00d4ff"
GREEN   = "#7ee787"
WARN    = "#f97316"
DANGER  = "#ff4444"
TEXT    = "#c9d1d9"
MUTED   = "#8b949e"
BORDER  = "#30363d"
FONT_MONO = ("Consolas", 10)
FONT_UI   = ("Segoe UI", 10)
FONT_H1   = ("Segoe UI", 15, "bold")
FONT_H2   = ("Segoe UI", 11, "bold")


def _style(root):
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".",              background=BG,  foreground=TEXT, font=FONT_UI)
    s.configure("TFrame",        background=BG)
    s.configure("TLabel",        background=BG,  foreground=TEXT)
    s.configure("TEntry",        fieldbackground=BG3, foreground=TEXT,
                insertcolor=ACCENT, borderwidth=0)
    s.configure("TButton",       background=BG3, foreground=TEXT,
                borderwidth=0, padding=6, relief="flat")
    s.map("TButton",             background=[("active", BG2)])
    s.configure("Accent.TButton",background=ACCENT, foreground=BG,
                font=("Segoe UI", 10, "bold"))
    s.map("Accent.TButton",      background=[("active", "#00b8d4")])
    s.configure("Green.TButton", background=GREEN, foreground=BG,
                font=("Segoe UI", 10, "bold"))
    s.configure("Danger.TButton",background=DANGER, foreground="#fff",
                font=("Segoe UI", 10, "bold"))
    s.configure("TLabelframe",   background=BG2, relief="flat")
    s.configure("TLabelframe.Label", background=BG2, foreground=ACCENT,
                font=FONT_H2)


class LoginScreen(tk.Toplevel):
    """Modal login / register dialog."""

    def __init__(self, parent, on_login):
        super().__init__(parent)
        self.on_login = on_login
        self.title("SecureVPN — Connect")
        self.geometry("400x460")
        self.resizable(False, False)
        self.configure(bg=BG)
        self.grab_set()
        _style(self)
        self._build()

    def _build(self):
        tk.Label(self, text="⬡  SecureVPN", font=("Segoe UI", 20, "bold"),
                 bg=BG, fg=ACCENT).pack(pady=(30, 4))
        tk.Label(self, text="Secure Encrypted Tunnel", font=FONT_UI,
                 bg=BG, fg=MUTED).pack(pady=(0, 20))

        form = tk.Frame(self, bg=BG2, padx=24, pady=24)
        form.pack(fill="x", padx=30)

        def field(label, var, show=None):
            tk.Label(form, text=label, bg=BG2, fg=MUTED,
                     font=FONT_UI).pack(anchor="w", pady=(8, 2))
            e = tk.Entry(form, textvariable=var, bg=BG3, fg=TEXT,
                         insertbackground=ACCENT, relief="flat",
                         font=FONT_UI, bd=6, show=show or "")
            e.pack(fill="x", ipady=4)
            return e

        self._host  = tk.StringVar(value="127.0.0.1")
        self._port  = tk.StringVar(value="9443")
        self._user  = tk.StringVar()
        self._pass  = tk.StringVar()

        field("Server IP", self._host)
        field("Port",      self._port)
        user_e = field("Username", self._user)
        field("Password",  self._pass, show="•")

        user_e.focus()
        self.bind("<Return>", lambda e: self._do_login())

        self._status = tk.Label(self, text="", bg=BG, fg=DANGER, font=FONT_UI)
        self._status.pack(pady=(12, 0))

        btn_row = tk.Frame(self, bg=BG)
        btn_row.pack(pady=16)
        ttk.Button(btn_row, text="🔐  Login",
                   style="Accent.TButton",
                   command=self._do_login).pack(side="left", padx=6)
        ttk.Button(btn_row, text="📝  Register",
                   style="Green.TButton",
                   command=self._do_register).pack(side="left", padx=6)

    def _do_login(self):
        self._connect("login")

    def _do_register(self):
        self._connect("register")

    def _connect(self, action):
        host = self._host.get().strip()
        port = int(self._port.get().strip())
        user = self._user.get().strip()
        pw   = self._pass.get().strip()
        if not user or not pw:
            self._status.config(text="Username and password required.")
            return
        self._status.config(text="Connecting...", fg=ACCENT)
        self.update()

        def task():
            client = VPNClient(host, port)
            try:
                resp = client.connect(user, pw, action)
                if resp.get("status") == "ok":
                    self.after(0, lambda: self._success(client, resp["msg"]))
                else:
                    self.after(0, lambda: self._status.config(
                        text=resp.get("msg", "Login failed."), fg=DANGER))
            except Exception as e:
                self.after(0, lambda: self._status.config(
                    text=f"Connection error: {e}", fg=DANGER))

        threading.Thread(target=task, daemon=True).start()

    def _success(self, client, msg):
        self.destroy()
        self.on_login(client, msg)


class ClientApp(tk.Tk):
    """Main VPN client window shown after login."""

    def __init__(self):
        super().__init__()
        self.title("SecureVPN — Client")
        self.geometry("900x650")
        self.minsize(700, 500)
        self.configure(bg=BG)
        _style(self)
        self.withdraw()   # Hide until logged in

        self._client: VPNClient | None = None
        self._build_ui()
        self._show_login()

    # ── Login flow ────────────────────────────────────────────────────────────

    def _show_login(self):
        LoginScreen(self, self._on_logged_in)

    def _on_logged_in(self, client: VPNClient, welcome_msg: str):
        self._client = client
        self._client.on_message    = self._on_chat
        self._client.on_system     = self._on_system
        self._client.on_file_done  = self._on_file_done
        self._client.on_disconnect = self._on_disconnected

        self.title(f"SecureVPN — {client.username}")
        self._set_status(True, client.username)
        self._append(welcome_msg, "system")
        self.deiconify()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=BG2, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="⬡  SecureVPN", font=FONT_H1,
                 bg=BG2, fg=ACCENT).pack(side="left", padx=20)
        ttk.Button(hdr, text="✕ Disconnect", style="Danger.TButton",
                   command=self._disconnect).pack(side="right", padx=16, pady=10)
        self._status_dot = tk.Label(hdr, text="●", font=("Segoe UI", 18),
                                    bg=BG2, fg=DANGER)
        self._status_dot.pack(side="right", padx=(0, 4))
        self._status_lbl = tk.Label(hdr, text="Disconnected", font=FONT_UI,
                                    bg=BG2, fg=MUTED)
        self._status_lbl.pack(side="right")
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # Body
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=12, pady=8)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)

        # Chat area
        chat_frame = ttk.LabelFrame(body, text=" 💬 Encrypted Chat ")
        chat_frame.grid(row=0, column=0, sticky="nsew")
        chat_frame.columnconfigure(0, weight=1)
        chat_frame.rowconfigure(0, weight=1)

        self._chat = scrolledtext.ScrolledText(
            chat_frame, bg=BG2, fg=TEXT, font=FONT_MONO,
            state="disabled", relief="flat", bd=0, wrap="word")
        self._chat.pack(fill="both", expand=True, padx=4, pady=4)
        self._chat.tag_config("system", foreground=GREEN)
        self._chat.tag_config("self",   foreground=ACCENT)
        self._chat.tag_config("other",  foreground=TEXT)
        self._chat.tag_config("time",   foreground=MUTED)
        self._chat.tag_config("warn",   foreground=WARN)

        # Input row
        inp = tk.Frame(self, bg=BG, pady=8)
        inp.pack(fill="x", padx=12)

        self._msg_var = tk.StringVar()
        msg_entry = tk.Entry(inp, textvariable=self._msg_var,
                             bg=BG3, fg=TEXT, insertbackground=ACCENT,
                             relief="flat", font=FONT_UI, bd=6)
        msg_entry.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 8))
        msg_entry.bind("<Return>", lambda e: self._send_msg())

        ttk.Button(inp, text="Send ➤", style="Accent.TButton",
                   command=self._send_msg).pack(side="left", padx=(0, 8))
        ttk.Button(inp, text="📁 Send File", style="Green.TButton",
                   command=self._send_file).pack(side="left")

        # Progress bar
        self._prog_var = tk.DoubleVar()
        self._prog_bar = ttk.Progressbar(self, variable=self._prog_var,
                                          maximum=100)
        self._prog_bar.pack(fill="x", padx=12, pady=(0, 6))

        # Stats bar
        stats = tk.Frame(self, bg=BG2, height=28)
        stats.pack(fill="x")
        self._stats_lbl = tk.Label(stats, text="", bg=BG2, fg=MUTED,
                                   font=("Consolas", 9))
        self._stats_lbl.pack(side="left", padx=12)

        self._start_stats_loop()

    # ── Status helpers ────────────────────────────────────────────────────────

    def _set_status(self, online: bool, username: str = ""):
        if online:
            self._status_dot.config(fg=GREEN)
            self._status_lbl.config(fg=GREEN,
                text=f"Connected as {username} — Tunnel Active 🔒")
        else:
            self._status_dot.config(fg=DANGER)
            self._status_lbl.config(fg=MUTED, text="Disconnected")

    # ── Chat helpers ──────────────────────────────────────────────────────────

    def _append(self, text: str, tag: str = "other",
                sender: str = "", ts: str = ""):
        self._chat.config(state="normal")
        if ts:
            self._chat.insert("end", f"[{ts}] ", "time")
        if sender:
            style = "self" if sender == (self._client.username if self._client else "") else "other"
            self._chat.insert("end", f"{sender}: ", style)
        self._chat.insert("end", text + "\n", tag)
        self._chat.see("end")
        self._chat.config(state="disabled")

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def _on_chat(self, sender, text, ts):
        self.after(0, lambda: self._append(text, "other", sender, ts))

    def _on_system(self, msg):
        self.after(0, lambda: self._append(msg, "system"))

    def _on_file_done(self, msg):
        self.after(0, lambda: self._append(msg, "warn"))

    def _on_disconnected(self):
        self.after(0, lambda: self._set_status(False))
        self.after(0, lambda: self._append("Disconnected from server.", "warn"))

    # ── Actions ───────────────────────────────────────────────────────────────

    def _send_msg(self):
        if not self._client or not self._client.connected:
            messagebox.showwarning("Not Connected", "Connect to the server first.")
            return
        text = self._msg_var.get().strip()
        if not text:
            return
        self._client.send_message(text)
        ts = time.strftime("%H:%M:%S")
        self._append(text, "self", self._client.username, ts)
        self._msg_var.set("")

    def _send_file(self):
        if not self._client or not self._client.connected:
            messagebox.showwarning("Not Connected", "Connect to the server first.")
            return
        path = filedialog.askopenfilename(title="Select file to send")
        if not path:
            return
        self._append(f"📤 Sending file: {os.path.basename(path)}", "warn")

        def task():
            def prog(pct):
                self.after(0, lambda: self._prog_var.set(pct))
            ok = self._client.send_file(path, progress_cb=prog)
            self.after(0, lambda: self._prog_var.set(0))
            if not ok:
                self.after(0, lambda: self._append("File transfer failed.", "warn"))

        threading.Thread(target=task, daemon=True).start()

    def _disconnect(self):
        if self._client:
            self._client.disconnect()
        self._set_status(False)
        self._append("You disconnected.", "system")

    # ── Stats loop ────────────────────────────────────────────────────────────

    def _start_stats_loop(self):
        self._update_stats()

    def _update_stats(self):
        if self._client and self._client.connected:
            s = self._client.bytes_sent
            r = self._client.bytes_recv
            self._stats_lbl.config(
                text=f"↑ {_fmt(s)}  ↓ {_fmt(r)}  |  AES-256-GCM Encrypted  |  SSL/TLS Tunnel Active")
        else:
            self._stats_lbl.config(text="Not connected")
        self.after(2000, self._update_stats)


def _fmt(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}TB"


def main():
    app = ClientApp()
    app.mainloop()


if __name__ == "__main__":
    main()
