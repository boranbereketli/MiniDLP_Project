# unified_agent.py

import sys
import socket
import json
import threading
import time
import requests
import os
import pyperclip
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

# Take necessary functions from the library (Maintained as is)
from YOUR_DLP_LIB import (
    scan_content, read_file_content, quarantine_file,
    get_usb_mount_points, QUARANTINE_DIR, ALLOWED_EXT,
    MAX_FILE_SIZE
)

# ============================================================
# CONFIGURATION (READS FROM CONFIG.JSON)
# ============================================================
CONFIG_FILE = "config.json"

# Default values (Used if file does not exist)
SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000
GATEWAY_PORT = 9101

# If file exists, take IP from there
if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            SERVER_IP = config.get("server_ip", SERVER_IP)
            SERVER_PORT = config.get("server_port", SERVER_PORT)
            GATEWAY_PORT = config.get("gateway_port", GATEWAY_PORT)
    except Exception as e:
        print(f"Config reading error: {e}")

# Create URL and IP variables
SERVER_URL = f"http://{SERVER_IP}:{SERVER_PORT}"
GATEWAY_IP = SERVER_IP 

# Static Folder Settings
SIM_USB_DIR = "SIM_USB_DRIVE"
STYLE_FILE = "styles.qss"

os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(SIM_USB_DIR, exist_ok=True)


# ============================================================
# HELPER FUNCTIONS
# ============================================================
def load_stylesheet():
    """Reads styles.qss file."""
    if os.path.exists(STYLE_FILE):
        try:
            with open(STYLE_FILE, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return ""
    return ""

def post_incident_to_server(user_id, event_type, data_type, action, details):
    payload = {
        "event_type": event_type, 
        "data_type": data_type, 
        "action": action,
        "details": details, 
        "user_id": user_id, 
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
    }
    try: 
        requests.post(f"{SERVER_URL}/log_incident", json=payload, timeout=2)
    except: 
        pass


# ============================================================
# WORKER THREADS (LOGIC)
# ============================================================
class ClipboardWorker(QThread):
    signal_incident = pyqtSignal(str)

    def __init__(self, vm_id, policy):
        super().__init__()
        self.vm_id = vm_id
        self.policy = policy
        self.running = True

    def update_policy(self, new_policy):
        self.policy = new_policy

    def run(self):
        # INITIAL FIX: Get existing clipboard data on startup so
        # there's no confusion between "empty" and "existing data".
        try:
            last_content = pyperclip.paste()
        except:
            last_content = ""

        while self.running:
            try:
                clip_policy = self.policy.get("clipboard", {})
                
                # Wait if no clipboard protection
                if not clip_policy:
                    time.sleep(1) 
                    continue

                # Read clipboard
                try:
                    current_content = pyperclip.paste() or ""
                except:
                    time.sleep(0.2)
                    continue

                if current_content != last_content and current_content:
                    keywords = clip_policy.get("Keywords", [])
                    str_content = str(current_content)
                    
                    incidents = scan_content(str_content, keywords)
                    blocked = []
                    match_txt = ""

                    for inc in incidents:
                        dt = inc["data_type"]
                        if dt == "KEYWORD_MATCH" and keywords:
                            blocked.append("KEYWORD")
                        if clip_policy.get(dt, False):
                            blocked.append(dt)
                            match_txt = inc.get("masked_match", "")

                    if blocked:
                        typ = ", ".join(set(blocked))
                        clean_msg = f"🚫 [DLP BLOCK] {typ} detected."
                        
                        # Clear restricted data, set warning message
                        pyperclip.copy(clean_msg)
                        last_content = clean_msg 
                        
                        post_incident_to_server(self.vm_id, "Clipboard", typ, "BLOCK", match_txt)
                        self.signal_incident.emit(f"📋 CLIPBOARD BLOCK: {typ}")
                    else:
                        last_content = current_content
                
                time.sleep(0.2)
                
            except Exception as e:
                time.sleep(1)

    def stop(self):
        self.running = False
        self.wait()

class USBWorker(QThread):
    signal_incident = pyqtSignal(str)

    def __init__(self, vm_id, policy):
        super().__init__()
        self.vm_id = vm_id
        self.policy = policy
        self.running = True
        self.observers = {}
        self.known_mounts = set()

    def update_policy(self, new_policy):
        self.policy = new_policy

    def run(self):
        if os.path.exists(SIM_USB_DIR):
            self.start_obs(SIM_USB_DIR)
            self.known_mounts.add(SIM_USB_DIR)

        while self.running:
            try:
                curr = set(get_usb_mount_points(SIM_USB_DIR))
                
                # Newly Connected
                for m in (curr - self.known_mounts):
                    self.start_obs(m)
                    self.known_mounts.add(m)
                    self.signal_incident.emit(f"🔌 USB Connected: {m}")

                # Removed
                for m in (self.known_mounts - curr):
                    self.stop_obs(m)
                    self.known_mounts.discard(m)
                    self.signal_incident.emit(f"🔌 USB Disconnected: {m}")

                time.sleep(2)
            except:
                time.sleep(2)

    def start_obs(self, path):
        if path in self.observers: return
        h = USBHandler(self.vm_id, self.policy, self.signal_incident)
        o = Observer()
        o.schedule(h, path, recursive=True)
        o.start()
        self.observers[path] = (o, h)
        self.scan_existing(path, h)

    def stop_obs(self, path):
        if path in self.observers:
            self.observers[path][0].stop()
            self.observers[path][0].join()
            del self.observers[path]

    def scan_existing(self, path, h):
        for r, _, f in os.walk(path):
            for fi in f:
                h.process(os.path.join(r, fi))

    def stop(self):
        self.running = False
        for p in list(self.observers.keys()):
            self.stop_obs(p)
        self.wait()


class USBHandler(FileSystemEventHandler):
    def __init__(self, vm_id, policy, signal):
        self.vm_id = vm_id
        self.policy = policy
        self.signal = signal

    def process(self, path):
        p = self.policy.get("usb", {})
        if not p: return
        try:
            if not os.path.isfile(path): return
            name = os.path.basename(path)
            if name.startswith(".") or name.startswith("~$"): return
            if os.path.splitext(name)[1].lower() not in ALLOWED_EXT: return

            content = read_file_content(path)
            if not content: return

            kws = p.get("Keywords", [])
            incs = scan_content(content, kws)
            blocked = []

            for i in incs:
                dt = i["data_type"]
                if dt == "KEYWORD_MATCH" and kws:
                    blocked.append("KEYWORD")
                if p.get(dt, False):
                    blocked.append(dt)

            if blocked:
                typ = ", ".join(set(blocked))
                quarantine_file(path)
                post_incident_to_server(self.vm_id, "USB Transfer", typ, "BLOCK", f"{name} -> Quarantine")
                self.signal.emit(f"💾 USB BLOCK: {name} ({typ}) -> Quarantined.")
        except:
            pass

    def on_created(self, e):
        if not e.is_directory:
            time.sleep(0.5)
            self.process(e.src_path)

    def on_modified(self, e):
        if not e.is_directory:
            time.sleep(0.5)
            self.process(e.src_path)


# ============================================================
# CORE ENGINE (NETWORK UPDATE)
# ============================================================
class UnifiedAgentCore(QObject):
    # (Message, Is_Mine, Is_Error)
    sig_chat_msg = pyqtSignal(str, bool, bool) 
    sig_dlp_log = pyqtSignal(str)
    sig_net_status = pyqtSignal(bool)

    def __init__(self, vm_id):
        super().__init__()
        self.vm_id = vm_id
        self.sock = None
        self.running = True
        self.policy = {}

        self.refresh_policy()
        
        self.clip = ClipboardWorker(vm_id, self.policy)
        self.clip.signal_incident.connect(self.sig_dlp_log.emit)
        self.clip.start()

        self.usb = USBWorker(vm_id, self.policy)
        self.usb.signal_incident.connect(self.sig_dlp_log.emit)
        self.usb.start()

        self.net = threading.Thread(target=self.net_loop, daemon=True)
        self.net.start()

    def refresh_policy(self):
        try:
            r = requests.get(f"{SERVER_URL}/policies/{self.vm_id}", timeout=2)
            if r.status_code == 200:
                self.policy = r.json()
                self.clip.update_policy(self.policy)
                self.usb.update_policy(self.policy)
        except:
            pass

    def connect(self):
        if self.sock:
            self.sock.close()
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((GATEWAY_IP, GATEWAY_PORT))
            self.sock.sendall(f"HELLO:{self.vm_id}\n".encode("utf-8"))
            f = self.sock.makefile("r", encoding="utf-8")
            
            # Expecting WELCOME from server
            resp = f.readline()
            if "WELCOME" in resp:
                self.sig_net_status.emit(True)
                return f
            else:
                return None
        except:
            self.sock = None
            self.sig_net_status.emit(False)
            return None

    def net_loop(self):
        f = None
        while self.running:
            if not self.sock:
                f = self.connect()
                if not f:
                    time.sleep(3)
                    continue
            try:
                line = f.readline()
                if not line: raise Exception
                raw = line.strip()

                # 1. Normal message from another user
                # Format: MSG:sender:content
                if raw.startswith("MSG:"):
                    parts = raw.split(":", 2)
                    sender = parts[1]
                    content = parts[2]
                    self.sig_chat_msg.emit(f"<b>{sender}:</b> {content}", False, False)

                # 2. Server approved my message (ACK)
                # Format: ACK:receiver:content
                elif raw.startswith("ACK:"):
                    parts = raw.split(":", 2)
                    target = parts[1]
                    content = parts[2]
                    # true, true -> My message, No error
                    self.sig_chat_msg.emit(f"<b>ME -> {target}:</b> {content}", True, False)

                # 3. Server blocked my message or returned error (ERR)
                # Format: ERR:receiver:error_code
                elif raw.startswith("ERR:"):
                    parts = raw.split(":", 2)
                    target = parts[1]
                    err_code = parts[2]
                    
                    if "BLOCKED" in err_code:
                        reason = err_code.split(":")[1] if ":" in err_code else "Restricted Content"
                        error_msg = f"🚫 <b>UNDELIVERED ({target}):</b> Your message was blocked due to '{reason}'."
                        self.sig_chat_msg.emit(error_msg, True, True) # True, True -> My message, Error EXISTS
                        self.sig_dlp_log.emit(f"Network Block: Sending to {target} was blocked due to '{reason}'.")
                    
                    elif "OFFLINE" in err_code:
                        self.sig_chat_msg.emit(f"⚠️ <b>ERROR:</b> {target} is offline.", True, True)
                    
                    else:
                        self.sig_chat_msg.emit(f"⚠️ <b>ERROR:</b> Send failed.", True, True)

                # Support for old format
                elif raw.startswith("[DLP]"):
                    self.sig_dlp_log.emit(raw)
                    
            except:
                self.sock = None
                self.sig_net_status.emit(False)
                time.sleep(3)

    def send(self, target, msg):
        if not self.sock:
            self.sig_dlp_log.emit("⚠️ Message could not be sent: Gateway offline.")
            return
        try:
            # Only sending, not printing. Printing happens when ACK arrives.
            self.sock.sendall((json.dumps({"dst": target, "channel": "chat", "payload": msg}) + "\n").encode("utf-8"))
        except:
            self.sock = None
            self.sig_dlp_log.emit("⚠️ Sending error.")

    def stop(self):
        self.running = False
        self.clip.stop()
        self.usb.stop()
        if self.sock:
            self.sock.close()


# ============================================================
# GUI CLASSES
# ============================================================
class PolicyViewerDialog(QDialog):
    def __init__(self, policy_data):
        super().__init__()
        self.setWindowTitle("Security Policy Details")
        self.setMinimumSize(700, 500)

        layout = QVBoxLayout()
        header = QFrame()
        hl = QHBoxLayout(header)
        hl.addWidget(QLabel("🛡️ <b>Active DLP Rules</b>"))
        hl.addStretch()
        layout.addWidget(header)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_table(policy_data.get("clipboard", {})), "📋 Clipboard")
        self.tabs.addTab(self.create_table(policy_data.get("usb", {})), "💾 USB")
        self.tabs.addTab(self.create_network_tree(policy_data.get("network", {})), "🌐 Network")
        layout.addWidget(self.tabs)

        btn = QPushButton("Close")
        btn.clicked.connect(self.close)
        btn.setStyleSheet("background-color: #666;")
        layout.addWidget(btn)
        self.setLayout(layout)

    def create_table(self, rules):
        t = QTableWidget()
        t.setColumnCount(2)
        t.setHorizontalHeaderLabels(["Data Type", "Status"])
        t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        t.verticalHeader().setVisible(False)
        
        # --- FIX HERE: Table set to non-editable ---
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        # --------------------------------------------------------

        r = 0
        for k, v in rules.items():
            t.insertRow(r)
            # Data Type Column (Read Only)
            item_key = QTableWidgetItem(k)
            t.setItem(r, 0, item_key)

            # Status Column
            if k == "Keywords":
                it = QTableWidgetItem(", ".join(v) if v else "-")
                it.setForeground(QColor("blue"))
            else:
                it = QTableWidgetItem("⛔ BLOCKED" if v else "✅ ALLOWED")
                it.setBackground(QColor("#ffcdd2" if v else "#c8e6c9"))
                it.setForeground(QColor("#b71c1c" if v else "#1b5e20"))
                it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            
            t.setItem(r, 1, it)
            r += 1
        return t

    def create_network_tree(self, net):
        t = QTreeWidget()
        t.setHeaderLabels(["Target / Rule", "Status"])
        t.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

        for user, rules in net.items():
            root = QTreeWidgetItem(t)
            root.setText(0, f"👤 {user}")
            root.setBackground(0, QColor("#e3f2fd"))
            root.setExpanded(True)
            for k, v in rules.items():
                ch = QTreeWidgetItem(root)
                ch.setText(0, k)
                if k == "Keywords":
                    ch.setText(1, ", ".join(v) if v else "-")
                    ch.setForeground(1, QColor("blue"))
                else:
                    ch.setText(1, "⛔ BLOCKED" if v else "✅ ALLOWED")
                    ch.setForeground(1, QColor("red" if v else "green"))
        return t

def get_registered_users():
    """ Fetches registered user list from the server. """
    try:
        r = requests.get(f"{SERVER_URL}/users", timeout=2)
        if r.status_code == 200:
            return r.json().get("users", [])
    except:
        pass
    return []


class UnifiedWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DLP Unified Agent - Enterprise Edition")
        self.setMinimumSize(1000, 750)

        # --- USERNAME CONTROL LOOP ---
        valid_users = get_registered_users()
        self.vm_id = None

        while not self.vm_id:
            # Ask user for VM ID
            vm_id, ok = QInputDialog.getText(self, "Login", "Enter VM ID (e.g., vm_user_1):")
            
            # 1. Exit / Cancel Control
            if not ok: 
                sys.exit()

            # 2. Valid User Control
            vm_id = vm_id.strip()
            # If server is off or list is empty, allow entry (For testing)
            if not valid_users:
                if vm_id: self.vm_id = vm_id
            else:
                if vm_id in valid_users:
                    self.vm_id = vm_id 
                elif not vm_id:
                    QMessageBox.critical(self, "Error", "Username cannot be empty.")
                else:
                    QMessageBox.critical(self, "Error", f"'{vm_id}' is not a registered username.")

        self.setWindowTitle(f"YourDLP {self.vm_id}")
        self.core = UnifiedAgentCore(self.vm_id)
        self.core.sig_chat_msg.connect(self.on_chat_msg)
        self.core.sig_dlp_log.connect(self.on_dlp_log)
        self.core.sig_net_status.connect(self.on_net_status)

        main = QVBoxLayout()
        main.setContentsMargins(15, 15, 15, 15)
        main.setSpacing(15)

        main.addWidget(self.build_fancy_header())

        self.tabs = QTabWidget()
        self.tabs.addTab(self.build_chat_tab(), "💬 Secure Chat")
        self.tabs.addTab(self.build_log_tab(), "🛡️ DLP Event Log")
        main.addWidget(self.tabs)
        self.setLayout(main)

        self.timer = QTimer()
        self.timer.timeout.connect(self.core.refresh_policy)
        self.timer.start(10000)

        self.on_dlp_log("✅ System Started. Protection Active.")
        self.on_dlp_log(f"👤 User: {self.vm_id}")
        self.init_tray()


    def build_fancy_header(self):
        f = QFrame()
        l = QHBoxLayout(f)
        l.setContentsMargins(20, 15, 20, 15)

        info = QVBoxLayout()
        lbl = QLabel(f"👤 <b>{self.vm_id}</b>")
        lbl.setStyleSheet("font-size: 18px; color: #333;")
        self.lbl_status = QLabel("Gateway: Connecting...")
        self.lbl_status.setStyleSheet("color: orange; font-weight: bold;")
        info.addWidget(lbl)
        info.addWidget(self.lbl_status)
        l.addLayout(info)

        l.addStretch()

        btn = QPushButton("🛡️ View Policies")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet("background-color: #2e7d32; padding: 10px 20px; font-size: 14px;")
        btn.clicked.connect(lambda: PolicyViewerDialog(self.core.policy).exec())
        l.addWidget(btn)

        return f

    def build_chat_tab(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(10)

        tf = QFrame()
        hl = QHBoxLayout(tf)
        hl.addWidget(QLabel("<b>Recipient:</b>"))
        self.cmb_target = QComboBox()
        self.cmb_target.setMinimumWidth(200)
        self.load_users()
        hl.addWidget(self.cmb_target)
        hl.addStretch()
        l.addWidget(tf)

        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        self.chat_area.setStyleSheet(
            "background-color: white; border: 1px solid #ddd; border-radius: 8px; padding: 10px; font-size: 14px;"
        )
        l.addWidget(self.chat_area)

        bl = QHBoxLayout()
        self.txt_msg = QLineEdit()
        self.txt_msg.setPlaceholderText("Type your secure message here...")
        self.txt_msg.setStyleSheet(
            "padding: 12px; font-size: 14px; border: 1px solid #ccc; border-radius: 20px;"
        )
        self.txt_msg.returnPressed.connect(self.send_message)

        btn = QPushButton("Send ➤")
        btn.setStyleSheet(
            "QPushButton { background-color: #0078d7; border-radius: 20px; padding: 10px 20px; font-size: 14px; } QPushButton:hover { background-color: #005a9e; }"
        )
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(self.send_message)

        bl.addWidget(self.txt_msg)
        bl.addWidget(btn)
        l.addLayout(bl)
        return w

    def build_log_tab(self):
        w = QWidget()
        l = QVBoxLayout(w)

        h = QHBoxLayout()
        h.addWidget(QLabel("<b>Real-Time Violation and System Logs</b>"))
        h.addStretch()
        btn = QPushButton("Sweep 🧹 Clear")
        btn.setStyleSheet("background-color: #757575; font-size: 12px; padding: 5px 10px;")
        btn.clicked.connect(lambda: self.log_box.clear())
        h.addWidget(btn)
        l.addLayout(h)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setStyleSheet(
            "background-color: #1e1e1e; color: #00ff00; font-family: 'Consolas', 'Courier New', monospace; font-size: 13px; border-radius: 6px; padding: 10px;"
        )
        l.addWidget(self.log_box)
        return w

    def send_message(self):
        msg = self.txt_msg.text().strip()
        if not msg: return
        self.core.send(self.cmb_target.currentText(), msg)
        self.txt_msg.clear()

    def load_users(self):
        try:
            r = requests.get(f"{SERVER_URL}/users", timeout=1)
            u = r.json().get("users", [])
            c = self.cmb_target.currentText()
            self.cmb_target.clear()
            self.cmb_target.addItems([x for x in u if x != self.vm_id])
            if c: self.cmb_target.setCurrentText(c)
        except:
            pass

    def on_chat_msg(self, msg, is_mine, is_error):
        # NEW FEATURE: Red box for error status
        if is_error:
             self.chat_area.append(
                f"<div style='text-align: center; margin: 5px;'><span style='background-color: #ffebee; border: 1px solid #ffcdd2; color: #c62828; padding: 8px 12px; font-size: 14px; font-weight: bold;'>{msg}</span></div>"
            )
        else:
            style = "background-color: #DCF8C6; border-radius: 15px 15px 0 15px;" if is_mine else "background-color: #E5E5EA; border-radius: 15px 15px 15px 0;"
            align = "right" if is_mine else "left"
            self.chat_area.append(
                f"<div style='text-align: {align}; margin: 5px;'><span style='{style} color: black; padding: 8px 12px; font-size: 14px;'>{msg}</span></div>"
            )
        
        sb = self.chat_area.verticalScrollBar()
        sb.setValue(sb.maximum())

    def on_dlp_log(self, msg):
        ts = time.strftime("[%H:%M:%S]")
        if "BLOCK" in msg or "ERROR" in msg:
            color = "#ff5252"
            icon = "❌"
        elif "Connected" in msg or "Disconnected" in msg:
            color = "#ffff00"
            icon = "⚠️"
        else:
            color = "#69f0ae"
            icon = "ℹ️"
        self.log_box.append(f"<span style='color:{color}'>{ts} {icon} {msg}</span>")

    def on_net_status(self, c):
        self.lbl_status.setText("Gateway: ✔ ONLINE" if c else "Gateway: ✖ NO CONNECTION")
        self.lbl_status.setStyleSheet(f"color: {'#2e7d32' if c else '#d32f2f'}; font-weight: bold;")

    def closeEvent(self, event):
        """Minimize to tray instead of closing when window is closed."""
        if self.tray_icon.isVisible():
            self.hide()
            
            # Inform user (Balloon notification)
            self.tray_icon.showMessage(
                "YourDLP Agent",
                "Protection continues in the background.\nRight-click tray icon to exit.",
                QSystemTrayIcon.MessageIcon.Information,
                2000
            )
            event.ignore() 
        else:
            self.core.stop()
            event.accept()

    def init_tray(self):
        """Prepares system tray icon and menu."""
        self.tray_icon = QSystemTrayIcon(self)
        
        # Use standard computer icon if icon file is missing
        icon = self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
        self.tray_icon.setIcon(icon)
        
        # Tray Menu
        tray_menu = QMenu()
        
        action_show = tray_menu.addAction("Show")
        action_show.triggered.connect(self.show)
        
        action_quit = tray_menu.addAction("Exit Completely")
        action_quit.triggered.connect(self.quit_app)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        
        # Open window on double click
        self.tray_icon.activated.connect(self.on_tray_icon_activated)

    def on_tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show()

    def quit_app(self):
        """Truly closes the application."""
        self.tray_icon.hide()
        self.core.stop() # Stop threads
        QApplication.quit()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)   
    app.setStyleSheet(load_stylesheet())
    
    win = UnifiedWindow()
    win.show()
    sys.exit(app.exec())