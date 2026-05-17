"""
vpn_server_gui.py - VPN Server Dashboard
Modern dark-theme Tkinter GUI for monitoring and controlling the VPN server.

Panels:
  ├─ Header bar  : logo, server status LED, start/stop button
  ├─ Left panel  : connected users list + kick button
  ├─ Centre panel: live chat log
  ├─ Right panel : bandwidth stats
  └─ Bottom panel: raw VPN log tail (auto-refreshes)
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import os
import sys

# Allow running from project root: python -m server.vpn_server_gui
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from .server import VPNServer
from . import server as server_module
from .logger import read_log_tail
from . import database as db

# ── Colour palette (dark cyberpunk theme) ─────────────────────────────────────
BG        = "#0d1117"
BG2       = "#161b22"
BG3       = "#21262d"
ACCENT    = "#00d4ff"
ACCENT2   = "#7ee787"
WARN      = "#f97316"
DANGER    = "#ff4444"
TEXT      = "#c9d1d9"
MUTED     = "#8b949e"
BORDER    = "#30363d"

FONT_MONO = ("Consolas", 10)
FONT_UI   = ("Segoe UI", 10)
FONT_H1   = ("Segoe UI", 16, "bold")
FONT_H2   = ("Segoe UI", 12, "bold")


def _style(root: tk.Tk):
    """Configure ttk styles for the dark theme."""
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".",           background=BG,  foreground=TEXT,  font=FONT_UI)
    style.configure("TFrame",      background=BG)
    style.configure("TLabel",      background=BG,  foreground=TEXT)
    style.configure("TButton",     background=BG3, foreground=TEXT,  borderwidth=0,
                    padding=6, relief="flat")
    style.map("TButton",           background=[("active", BG2)])
    style.configure("Accent.TButton", background=ACCENT, foreground=BG,
                    font=("Segoe UI", 10, "bold"))
    style.map("Accent.TButton",    background=[("active", "#00b8d4")])
    style.configure("Danger.TButton", background=DANGER, foreground="#fff",
                    font=("Segoe UI", 10, "bold"))
    style.configure("TLabelframe", background=BG2, foreground=ACCENT,
                    relief="flat", borderwidth=1)
    style.configure("TLabelframe.Label", background=BG2, foreground=ACCENT,
                    font=FONT_H2)
    style.configure("Treeview",    background=BG2, foreground=TEXT,
                    fieldbackground=BG2, rowheight=24, font=FONT_UI)
    style.configure("Treeview.Heading", background=BG3, foreground=ACCENT,
                    font=("Segoe UI", 10, "bold"))
    style.map("Treeview",          background=[("selected", BG3)])


# ─────────────────────────────────────────────────────────────────────────────
class ServerDashboard(tk.Tk):
# ─────────────────────────────────────────────────────────────────────────────

    def __init__(self):
        super().__init__()
        self.title("SecureVPN — Server Dashboard")
        self.geometry("1200x750")
        self.minsize(900, 600)
        self.configure(bg=BG)
        _style(self)

        self._server: VPNServer | None = None
        self._running = False
        self._stats   = {"clients": 0, "msgs": 0, "bytes_in": 0, "bytes_out": 0}

        self._build_ui()
        self._register_callbacks()
        self._start_refresh_loop()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_header()

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        body.columnconfigure(0, weight=1, minsize=220)
        body.columnconfigure(1, weight=3)
        body.columnconfigure(2, weight=1, minsize=200)
        body.rowconfigure(0, weight=3)
        body.rowconfigure(1, weight=2)

        self._build_users_panel(body)
        self._build_chat_panel(body)
        self._build_stats_panel(body)
        self._build_logs_panel(body)

    def _build_header(self):
        hdr = tk.Frame(self, bg=BG2, height=60)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        # Logo
        tk.Label(hdr, text="⬡  SecureVPN", font=("Segoe UI", 18, "bold"),
                 bg=BG2, fg=ACCENT).pack(side="left", padx=20)

        # Status indicator
        self._status_dot  = tk.Label(hdr, text="●", font=("Segoe UI", 20),
                                     bg=BG2, fg=DANGER)
        self._status_dot.pack(side="left", padx=(0, 6))
        self._status_lbl  = tk.Label(hdr, text="Server Offline", font=FONT_H2,
                                     bg=BG2, fg=MUTED)
        self._status_lbl.pack(side="left")

        # Controls (right side)
        ttk.Button(hdr, text="✕  Stop Server", style="Danger.TButton",
                   command=self._stop_server).pack(side="right", padx=(6, 20), pady=10)
        ttk.Button(hdr, text="▶  Start Server", style="Accent.TButton",
                   command=self._start_server).pack(side="right", padx=6, pady=10)

        # Separator
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

    def _build_users_panel(self, parent):
        frame = ttk.LabelFrame(parent, text=" 👥 Connected Clients ")
        frame.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=6)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        cols = ("User", "IP", "Since")
        self._users_tree = ttk.Treeview(frame, columns=cols, show="headings",
                                         selectmode="browse")
        for c in cols:
            self._users_tree.heading(c, text=c)
            self._users_tree.column(c, width=70, anchor="w")
        self._users_tree.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)

        sb = ttk.Scrollbar(frame, orient="vertical",
                           command=self._users_tree.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self._users_tree.configure(yscrollcommand=sb.set)

        ttk.Button(frame, text="⚡ Kick User",
                   command=self._kick_selected).grid(row=1, column=0,
                   columnspan=2, sticky="ew", padx=4, pady=(0, 4))

    def _build_chat_panel(self, parent):
        frame = ttk.LabelFrame(parent, text=" 💬 Live Activity Log ")
        frame.grid(row=0, column=1, sticky="nsew", padx=6, pady=6)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        self._chat_box = scrolledtext.ScrolledText(
            frame, bg=BG2, fg=TEXT, font=FONT_MONO, state="disabled",
            relief="flat", bd=0, wrap="word", insertbackground=ACCENT
        )
        self._chat_box.pack(fill="both", expand=True, padx=4, pady=4)
        # Tag colours
        self._chat_box.tag_config("system", foreground=ACCENT2)
        self._chat_box.tag_config("chat",   foreground=TEXT)
        self._chat_box.tag_config("sender", foreground=ACCENT)
        self._chat_box.tag_config("time",   foreground=MUTED)

        # Broadcast input
        row = ttk.Frame(frame)
        row.pack(fill="x", padx=4, pady=(0, 4))
        self._bcast_var = tk.StringVar()
        tk.Entry(row, textvariable=self._bcast_var, bg=BG3, fg=TEXT,
                 insertbackground=ACCENT, relief="flat", font=FONT_UI,
                 bd=4).pack(side="left", fill="x", expand=True, padx=(0, 6))
        ttk.Button(row, text="Broadcast", style="Accent.TButton",
                   command=self._broadcast_msg).pack(side="right")

    def _build_stats_panel(self, parent):
        frame = ttk.LabelFrame(parent, text=" 📊 Statistics ")
        frame.grid(row=0, column=2, sticky="nsew", padx=(6, 0), pady=6)

        stats = [
            ("Clients Online",  "stat_clients",  ACCENT),
            ("Messages Routed", "stat_msgs",     ACCENT2),
            ("Data In",         "stat_in",       WARN),
            ("Data Out",        "stat_out",       "#a78bfa"),
            ("Server Uptime",   "stat_uptime",   MUTED),
        ]
        self._stat_labels = {}
        for row_i, (label, key, color) in enumerate(stats):
            tk.Label(frame, text=label, font=FONT_UI, bg=BG2,
                     fg=MUTED).grid(row=row_i * 2, column=0,
                     sticky="w", padx=12, pady=(10, 0))
            val = tk.Label(frame, text="—", font=("Segoe UI", 18, "bold"),
                           bg=BG2, fg=color)
            val.grid(row=row_i * 2 + 1, column=0, sticky="w", padx=12)
            self._stat_labels[key] = val

        self._start_time = None

    def _build_logs_panel(self, parent):
        frame = ttk.LabelFrame(parent, text=" 📋 VPN Logs ")
        frame.grid(row=1, column=0, columnspan=3, sticky="nsew",
                   padx=0, pady=(0, 0))
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        self._log_box = scrolledtext.ScrolledText(
            frame, bg="#0a0f14", fg="#57606a", font=("Consolas", 9),
            state="disabled", relief="flat", bd=0, height=10
        )
        self._log_box.pack(fill="both", expand=True, padx=4, pady=4)
        self._log_box.tag_config("INFO",    foreground=ACCENT2)
        self._log_box.tag_config("WARNING", foreground=WARN)
        self._log_box.tag_config("ERROR",   foreground=DANGER)

    # ── Server control ────────────────────────────────────────────────────────

    def _start_server(self):
        if self._running:
            return
        try:
            self._server  = VPNServer()
            self._server.start()
            self._running = True
            self._start_time = time.time()
            self._set_status(online=True)
            self._append_activity("🟢 Server started.", "system")
        except Exception as e:
            messagebox.showerror("Start Error", str(e))

    def _stop_server(self):
        if not self._running:
            return
        if messagebox.askyesno("Stop Server", "Stop the VPN server? All clients will be disconnected."):
            self._server.stop()
            self._running  = False
            self._start_time = None
            self._set_status(online=False)
            self._append_activity("🔴 Server stopped.", "system")

    def _set_status(self, online: bool):
        if online:
            self._status_dot.config(fg=ACCENT2)
            self._status_lbl.config(fg=ACCENT2, text="Server Online")
        else:
            self._status_dot.config(fg=DANGER)
            self._status_lbl.config(fg=MUTED, text="Server Offline")

    # ── Callbacks registered on server_module ────────────────────────────────

    def _register_callbacks(self):
        server_module.on_client_connect    = self._on_connect
        server_module.on_client_disconnect = self._on_disconnect
        server_module.on_message           = self._on_message

    def _on_connect(self, username, ip):
        self.after(0, lambda: self._append_activity(
            f"🔐 {username} connected from {ip}", "system"))
        self._stats["clients"] += 1

    def _on_disconnect(self, username):
        self.after(0, lambda: self._append_activity(
            f"🔓 {username} disconnected", "system"))
        self._stats["clients"] = max(0, self._stats["clients"] - 1)

    def _on_message(self, sender, text):
        self._stats["msgs"] += 1
        self.after(0, lambda: self._append_activity(
            f"{sender}: {text}", "chat", sender=sender))

    # ── Activity log helpers ──────────────────────────────────────────────────

    def _append_activity(self, text: str, tag: str = "chat", sender: str = ""):
        self._chat_box.config(state="normal")
        ts = time.strftime("%H:%M:%S")
        self._chat_box.insert("end", f"[{ts}] ", "time")
        if sender:
            self._chat_box.insert("end", f"{sender} » ", "sender")
            self._chat_box.insert("end", text.replace(f"{sender}: ", "") + "\n", tag)
        else:
            self._chat_box.insert("end", text + "\n", tag)
        self._chat_box.see("end")
        self._chat_box.config(state="disabled")

    # ── Kick selected user ────────────────────────────────────────────────────

    def _kick_selected(self):
        sel = self._users_tree.selection()
        if not sel:
            messagebox.showinfo("Kick", "Select a user first.")
            return
        username = self._users_tree.item(sel[0], "values")[0]
        if messagebox.askyesno("Kick User", f"Kick '{username}'?"):
            VPNServer.kick_user(username)
            self._append_activity(f"⚡ Admin kicked {username}", "system")

    # ── Broadcast from server ─────────────────────────────────────────────────

    def _broadcast_msg(self):
        import json
        from .server import _clients, _clients_lock
        msg = self._bcast_var.get().strip()
        if not msg:
            return
        envelope = json.dumps({"type": "system", "msg": f"📢 SERVER: {msg}"})
        with _clients_lock:
            for h in list(_clients.values()):
                try:
                    h._send_encrypted(envelope)
                except Exception:
                    pass
        self._append_activity(f"📢 Broadcast: {msg}", "system")
        self._bcast_var.set("")

    # ── Auto-refresh loop ─────────────────────────────────────────────────────

    def _start_refresh_loop(self):
        self._refresh()

    def _refresh(self):
        self._refresh_users()
        self._refresh_stats()
        self._refresh_logs()
        self.after(2000, self._refresh)  # Every 2 seconds

    def _refresh_users(self):
        clients = VPNServer.get_connected_clients() if self._running else []
        self._users_tree.delete(*self._users_tree.get_children())
        for c in clients:
            self._users_tree.insert("", "end", values=(
                c["username"], c["ip"], c["connected_since"]
            ))

    def _refresh_stats(self):
        clients = VPNServer.get_connected_clients() if self._running else []
        total_in  = sum(c["bytes_recv"] for c in clients)
        total_out = sum(c["bytes_sent"] for c in clients)

        self._stat_labels["stat_clients"].config(text=str(len(clients)))
        self._stat_labels["stat_msgs"].config(text=str(self._stats["msgs"]))
        self._stat_labels["stat_in"].config(text=_fmt_bytes(total_in))
        self._stat_labels["stat_out"].config(text=_fmt_bytes(total_out))

        if self._start_time:
            uptime = int(time.time() - self._start_time)
            h, r  = divmod(uptime, 3600)
            m, s  = divmod(r, 60)
            self._stat_labels["stat_uptime"].config(
                text=f"{h:02d}:{m:02d}:{s:02d}")
        else:
            self._stat_labels["stat_uptime"].config(text="—")

    def _refresh_logs(self):
        tail = read_log_tail(100)
        self._log_box.config(state="normal")
        self._log_box.delete("1.0", "end")
        for line in tail.splitlines():
            tag = "INFO"
            if "WARNING" in line:  tag = "WARNING"
            elif "ERROR"   in line: tag = "ERROR"
            self._log_box.insert("end", line + "\n", tag)
        self._log_box.see("end")
        self._log_box.config(state="disabled")


# ── Utilities ─────────────────────────────────────────────────────────────────

def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    app = ServerDashboard()
    app.mainloop()


if __name__ == "__main__":
    main()
