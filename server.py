# server.py

from flask import Flask, request, jsonify
import threading
import socket
import time
import os
import json
import csv 

# Your external library
from YOUR_DLP_LIB import (
    scan_content, Message, LOG_CSV, 
    DLP_SCAN_ORDER 
)

app = Flask(__name__)
POLICY_FILE = "policies.json"

# Console Colors
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

# ============================================================
# CONFIG
# ============================================================
GATEWAY_LISTEN_HOST = "0.0.0.0" 
GATEWAY_LISTEN_PORT = 9101
LIVE_CONNECTIONS = {}
USER_POLICIES = {}

# ============================================================
# PERSISTENCE
# ============================================================
def save_policies():
    try:
        with open(POLICY_FILE, 'w', encoding='utf-8') as f:
            json.dump(USER_POLICIES, f, indent=4, ensure_ascii=False)
        print(f"{Colors.OKGREEN}[SERVER] Policies saved.{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[ERROR] Policies could not be saved: {e}{Colors.ENDC}")

def load_policies():
    global USER_POLICIES
    if os.path.exists(POLICY_FILE):
        try:
            with open(POLICY_FILE, 'r', encoding='utf-8') as f:
                USER_POLICIES = json.load(f)
            print(f"{Colors.OKCYAN}[SERVER] Policies loaded: {len(USER_POLICIES)} users.{Colors.ENDC}")
            return
        except Exception as e:
            print(f"{Colors.FAIL}[ERROR] Loading error: {e}.{Colors.ENDC}")
    
    USER_POLICIES = {}
    save_policies()

load_policies()

# ============================================================
# LOGGING
# ============================================================
def log_incident(event_type, data_type, action, details):
    try:
        file_exists = os.path.exists(LOG_CSV)
        with open(LOG_CSV, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Write headers if file does not exist
            if not file_exists:
                writer.writerow(["Date", "Event_Type", "Data_Type", "Action", "Details"])
            
            # Write data securely
            writer.writerow([
                time.strftime('%Y-%m-%d %H:%M:%S'),
                event_type,
                data_type,
                action,
                details
            ])
    except Exception as e:
        print(f"[LOG ERROR] {e}")

    # --- CONSOLE OUTPUT ---
    timestamp = time.strftime('%H:%M:%S')
    if "BLOCK" in action:
        color = Colors.FAIL
        icon = "⛔"
    elif "ALLOW" in action:
        color = Colors.OKGREEN
        icon = "✅"
    else:
        color = Colors.WARNING
        icon = "⚠️"

    safe_details = (details[:75] + '..') if len(details) > 75 else details
    print(f"{color}[{timestamp}] {icon} {event_type} | {data_type} | {action} -> {safe_details}{Colors.ENDC}")


# ============================================================
# REST API ENDPOINTS
# ============================================================

@app.route('/all_logs', methods=['GET'])
def get_all_logs():
    """Reads CSV file and returns as JSON. Repairs malformed lines."""
    logs = []
    if os.path.exists(LOG_CSV):
        try:
            with open(LOG_CSV, 'r', encoding='utf-8') as f:
                # Using DictReader
                reader = csv.DictReader(f)
                
                # --- ERROR CORRECTION BLOCK ---
                for row in reader:
                    # If a line has more commas than expected, DictReader assigns them to 'None' key.
                    # This causes a crash in JSON.dumps. Cleaning it:
                    if None in row:
                        extra_data = row.pop(None) # Delete None key and get data
                        # Add extra data to 'Details' column so it is not lost
                        if 'Details' in row and extra_data:
                            row['Details'] += " " + " ".join(extra_data)
                    
                    logs.append(row)
                
                logs.reverse() # Newest on top
        except Exception as e:
            # Return empty list on error, do not crash server
            print(f"[LOG READ ERROR] {e}")
            return jsonify({"error": str(e), "logs": []})
            
    return jsonify({"logs": logs})

@app.route('/policies/<user_id>', methods=['GET'])
def get_policies(user_id):
    policies = USER_POLICIES.get(user_id, {
        "clipboard": {d: False for d in DLP_SCAN_ORDER},
        "usb":       {d: False for d in DLP_SCAN_ORDER},
        "network":   {},
    })
    return jsonify(policies)

@app.route('/log_incident', methods=['POST'])
def receive_incident():
    data = request.json
    try:
        details = f"User: {data.get('user_id', 'UNKNOWN')} | {data.get('details', 'No details')}"
        log_incident(
            event_type=data.get('event_type', 'UNKNOWN'),
            data_type=data.get('data_type', 'N/A'),
            action=data.get('action', 'N/A'),
            details=details
        )
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/update_policy', methods=['POST'])
def update_policy():
    data = request.json
    user_id = data.get("user_id")
    new_policies = data.get("policies")

    if not user_id or not new_policies:
        return jsonify({"error": "Missing parameter"}), 400

    current_policy = USER_POLICIES.get(user_id, {})
    
    current_policy["clipboard"] = new_policies.get("clipboard", current_policy.get("clipboard", {}))
    current_policy["usb"] = new_policies.get("usb", current_policy.get("usb", {}))
    current_policy["network"] = new_policies.get("network", current_policy.get("network", {}))

    USER_POLICIES[user_id] = current_policy
    save_policies()
    return jsonify({"status": "ok"}), 200

@app.route("/users", methods=["GET"])
def get_users():
    return jsonify({"users": list(USER_POLICIES.keys())})

# ============================================================
# DLP NETWORK GATEWAY (SOCKET)
# ============================================================
def process_message(msg: Message, sender_sock):
    src = msg.src
    dst = msg.dst
    
    if dst not in LIVE_CONNECTIONS:
        log_incident("Network", "Error", "ERROR", f"{src}->{dst} (Recipient Offline)")
        return False, "OFFLINE"

    src_policy = USER_POLICIES.get(src, {})
    network_policy_for_dst = src_policy.get("network", {}).get(dst)
    
    recipient_sock = LIVE_CONNECTIONS[dst]['socket']

    if network_policy_for_dst is None:
        log_incident("Network", "General", "ALLOW", f"{src}->{dst}")
        try:
            recipient_sock.sendall(f"MSG:{src}:{msg.payload}\n".encode("utf-8"))
            return True, "OK"
        except:
            return False, "SEND_ERR"

    dynamic_keywords = network_policy_for_dst.get("Keywords", []) 
    incidents = scan_content(msg.payload.lower(), [k.lower() for k in dynamic_keywords])
    
    blocked_reasons = []
    if incidents:
        for incident in incidents:
            d_type = incident["data_type"]
            if d_type == "KEYWORD_MATCH" and dynamic_keywords:
                blocked_reasons.append("KEYWORD")
            
            if network_policy_for_dst.get(d_type, False): 
                blocked_reasons.append(d_type)
        
    if blocked_reasons:
        reason_str = "/".join(set(blocked_reasons))
        log_incident("Network", reason_str, "BLOCK", f"{src}->{dst}")
        return False, f"BLOCKED:{reason_str}"
    
    log_incident("Network", "Clean", "ALLOW", f"{src}->{dst}")
    try:
        recipient_sock.sendall(f"MSG:{src}:{msg.payload}\n".encode("utf-8"))
        return True, "OK"
    except:
        return False, "SEND_ERR"

def client_handler(conn, addr):
    user_id = None
    try:
        conn_file = conn.makefile("r", encoding="utf-8")
        
        first_line = conn_file.readline().strip()
        if first_line.startswith("HELLO:"):
            user_id = first_line.split(":", 1)[1].strip()
            LIVE_CONNECTIONS[user_id] = {'ip': addr[0], 'socket': conn}
            print(f"{Colors.OKBLUE}[GATEWAY] Connected: {user_id} ({addr[0]}){Colors.ENDC}")
            conn.sendall(f"WELCOME:{user_id}\n".encode("utf-8"))
        else:
            conn.close()
            return

        for line in conn_file:
            try:
                data = json.loads(line.rstrip("\n"))
                msg = Message(
                    src=user_id, 
                    dst=data.get("dst", "UNKNOWN"), 
                    channel=data.get("channel", "chat"), 
                    payload=data.get("payload", "")
                )
                
                success, status_code = process_message(msg, conn)
                
                if success:
                    conn.sendall(f"ACK:{msg.dst}:{msg.payload}\n".encode("utf-8"))
                else:
                    conn.sendall(f"ERR:{msg.dst}:{status_code}\n".encode("utf-8"))

            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"[Global Error] {e}")

    except Exception:
        pass
    finally:
        if user_id and user_id in LIVE_CONNECTIONS:
            del LIVE_CONNECTIONS[user_id]
            print(f"{Colors.WARNING}[GATEWAY] Disconnected: {user_id}{Colors.ENDC}")
        try: conn.close()
        except: pass

def run_gateway():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((GATEWAY_LISTEN_HOST, GATEWAY_LISTEN_PORT))
        server_sock.listen(5)
        print(f"{Colors.HEADER}[GATEWAY] Listening: {GATEWAY_LISTEN_HOST}:{GATEWAY_LISTEN_PORT}{Colors.ENDC}")
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(target=client_handler, args=(conn, addr), daemon=True).start()
    except OSError as e:
        print(f"[GATEWAY FATAL] {e}")
    finally:
        server_sock.close()

if __name__ == '__main__':
    threading.Thread(target=run_gateway, daemon=True).start()
    print("\n[SERVER] API starting (Port 5000)...")
    app.run(host='0.0.0.0', port=5000)