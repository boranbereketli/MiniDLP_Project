# server.py

from flask import Flask, request, jsonify
import threading
import socket
import time
import os
import json
from YOUR_DLP_LIB import (
    scan_content, Message, LOG_CSV, 
    DLP_SCAN_ORDER 
)

app = Flask(__name__)
POLICY_FILE = "policies.json"

# ============================================================
# CONFIG
# ============================================================
GATEWAY_LISTEN_HOST = "127.0.0.1" 
GATEWAY_LISTEN_PORT = 9101
LIVE_CONNECTIONS = {}
USER_POLICIES = {}

DEFAULT_POLICIES = {
    "vm_user_1": {
        "clipboard": {"TCKN": True, "IBAN_TR": True, "KREDI_KARTI": True, "E_POSTA": False, "TEL_NO": False, "Keywords": ["araba", "pilot"]}, 
        "usb":       {"TCKN": False, "IBAN_TR": True, "KREDI_KARTI": True, "E_POSTA": False, "TEL_NO": False},  
        "network":   {"vm_user_2": {"TCKN": True,  "IBAN_TR": True, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False, "Keywords": ["domates", "patates"]}}, 
    },
    "vm_user_2": {
        "clipboard": {"TCKN": False, "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False}, 
        "usb":       {"TCKN": True,  "IBAN_TR": True, "KREDI_KARTI": True, "E_POSTA": True, "TEL_NO": True},   
        "network":   {"vm_user_1": {"TCKN": True,  "IBAN_TR": False, "KREDI_KARTI": False, "E_POSTA": False, "TEL_NO": False}}, 
    },
    "vm_user_3": {
        "clipboard": {}, 
        "usb":       {}, 
        "network":   {},
    },
}

# ============================================================
# PERSISTENCE (Kalıcılık)
# ============================================================
def save_policies():
    """ USER_POLICIES sözlüğünü JSON dosyasına yazar. """
    try:
        with open(POLICY_FILE, 'w', encoding='utf-8') as f:
            json.dump(USER_POLICIES, f, indent=4, ensure_ascii=False)
        print("[SERVER] Politikalar kaydedildi.")
    except Exception as e:
        print(f"[ERROR] Politikalar kaydedilemedi: {e}")

def load_policies():
    """ Sunucu açılışında dosyadan politikaları yükler. """
    global USER_POLICIES
    if os.path.exists(POLICY_FILE):
        try:
            with open(POLICY_FILE, 'r', encoding='utf-8') as f:
                USER_POLICIES = json.load(f)
            print(f"[SERVER] Politikalar yüklendi: {POLICY_FILE}")
            return
        except Exception as e:
            print(f"[ERROR] Yükleme hatası: {e}. Varsayılanlar dönülüyor.")
    
    # Dosya yoksa veya hatalıysa varsayılanları yükle
    USER_POLICIES = DEFAULT_POLICIES.copy()
    save_policies()

load_policies()

# ============================================================
# LOGGING
# ============================================================
def log_incident(event_type, data_type, action, details):
    log_line = f"{time.strftime('%Y-%m-%d %H:%M:%S')},{event_type},{data_type},{action},{details}\n"
    try:
        if not os.path.exists(LOG_CSV):
            with open(LOG_CSV, "w", encoding="utf-8") as f:
                f.write("Tarih,Olay_Tipi,Veri_Tipi,Aksiyon,Detay\n")
        with open(LOG_CSV, "a", encoding="utf-8") as f:
            f.write(log_line)
    except Exception as e:
        print(f"[SERVER LOG ERROR] {e}")
    print(f"\n[SERVER LOG] {data_type} | {action} | {details}")


# ============================================================
# REST API ENDPOINTS
# ============================================================
@app.route('/policies/<user_id>', methods=['GET'])
def get_policies(user_id):
    default_restrictions = {d: True for d in DLP_SCAN_ORDER}
    # Eğer kullanıcı yoksa katı kurallar döndür
    policies = USER_POLICIES.get(user_id, {
        "clipboard": default_restrictions.copy(),
        "usb":       default_restrictions.copy(),
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
    policies = data.get("policies")

    if not user_id or not policies:
        return jsonify({"error": "Eksik parametre"}), 400

    USER_POLICIES[user_id] = policies
    save_policies()
    return jsonify({"status": "ok"}), 200

@app.route('/delete_policy/<user_id>', methods=['POST'])
def delete_policy(user_id):
    if user_id in USER_POLICIES:
        del USER_POLICIES[user_id]
        save_policies()
        return jsonify({"status": "ok"}), 200
    return jsonify({"error": "Kullanıcı bulunamadı"}), 404

@app.route('/logs/<vm_id>', methods=['GET'])
def get_logs_for_user(vm_id):
    try:
        if not os.path.exists(LOG_CSV):
            return jsonify({"logs": []})
        
        filtered = []
        with open(LOG_CSV, "r", encoding="utf-8") as f:
            for line in f:
                if f"User: {vm_id}" in line or f"{vm_id}->" in line:
                    filtered.append(line.strip())
        return jsonify({"logs": filtered}), 200
    except Exception as e:
        return jsonify({"logs": [], "error": str(e)})

@app.route("/users", methods=["GET"])
def get_users():
    return jsonify({"users": list(USER_POLICIES.keys())})


# ============================================================
# DLP NETWORK GATEWAY (SOCKET)
# ============================================================
def process_message(msg: Message):
    src = msg.src
    dst = msg.dst
    
    # 1. Alıcı Kontrolü
    if dst not in LIVE_CONNECTIONS:
        log_incident("Ağ Mesajı", "Hata", "ENGEL - Alıcı Offline", f"{src}->{dst}")
        return False, f"[DLP] HATA: Alıcı VM ({dst}) Gateway'e bağlı değil."

    # 2. Politika Kontrolü
    src_policy = USER_POLICIES.get(src, {})
    network_policy_for_dst = src_policy.get("network", {}).get(dst)
    
    recipient_sock = LIVE_CONNECTIONS[dst]['socket']

    # Hedef için özel bir kural yoksa izin ver
    if network_policy_for_dst is None:
        log_incident(f"{msg.channel}", "YOK", "İZİN VERİLDİ - Kural Yok", f"{src}->{dst}")
        try:
            recipient_sock.sendall(f"[{src}]: {msg.payload}\n".encode("utf-8"))
            return True, "[DLP] Mesaj iletildi."
        except:
            return False, "[DLP] Gönderim hatası."

    # 3. İçerik Taraması
    dynamic_keywords = network_policy_for_dst.get("Keywords", []) 
    incidents = scan_content(msg.payload, dynamic_keywords) 
    
    blocked_reasons = []
    if incidents:
        for incident in incidents:
            d_type = incident["data_type"]
            if d_type == "KEYWORD_MATCH" and dynamic_keywords:
                blocked_reasons.append("ANAHTAR_KELİME")
            
            # Eğer politika bu veri tipini True (Yasaklı) olarak işaretlemişse
            if network_policy_for_dst.get(d_type, False): 
                blocked_reasons.append(d_type)
        
    # 4. Aksiyon (Engel veya İzin)
    if blocked_reasons:
        reason_str = "/".join(set(blocked_reasons))
        log_incident(f"{msg.channel}", reason_str, "ENGEL - Yasak Veri", f"{src}->{dst}")
        return False, f"[DLP] Mesajınız yasaklanmış veri ({reason_str}) içerdiği için engellendi."
    
    # Temiz
    log_incident(f"{msg.channel}", "YOK", "İZİN VERİLDİ - Temiz", f"{src}->{dst}")
    try:
        recipient_sock.sendall(f"[{src}]: {msg.payload}\n".encode("utf-8"))
        return True, "[DLP] Mesaj iletildi."
    except:
        return False, "[DLP] Mesaj gönderilemedi."

def client_handler(conn, addr):
    user_id = None
    try:
        conn_file = conn.makefile("r", encoding="utf-8")
        
        # Handshake
        first_line = conn_file.readline().strip()
        if first_line.startswith("HELLO:"):
            user_id = first_line.split(":", 1)[1].strip()
            LIVE_CONNECTIONS[user_id] = {'ip': addr[0], 'socket': conn}
            print(f"[GATEWAY] Bağlandı: {user_id} ({addr[0]})")
            conn.sendall(f"Hoş Geldin, {user_id}. Gateway aktif.\n".encode("utf-8"))
        else:
            conn.sendall("ERROR: Protocol mismatch.\n".encode("utf-8"))
            return

        # Mesaj Döngüsü
        for line in conn_file:
            try:
                data = json.loads(line.rstrip("\n"))
                msg = Message(
                    src=user_id, 
                    dst=data.get("dst", "UNKNOWN"), 
                    channel=data.get("channel", "chat"), 
                    payload=data.get("payload", "")
                )
                success, response_msg = process_message(msg)
                if not success:
                    conn.sendall(f"{response_msg}\n".encode("utf-8"))
            except json.JSONDecodeError:
                continue

    except Exception:
        pass
    finally:
        if user_id and user_id in LIVE_CONNECTIONS:
            del LIVE_CONNECTIONS[user_id]
        try: conn.close()
        except: pass

def run_gateway():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.bind((GATEWAY_LISTEN_HOST, GATEWAY_LISTEN_PORT))
        server_sock.listen(5)
        print(f"[GATEWAY] Dinleniyor: {GATEWAY_LISTEN_HOST}:{GATEWAY_LISTEN_PORT}")
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(target=client_handler, args=(conn, addr), daemon=True).start()
    except OSError as e:
        print(f"[GATEWAY FATAL] {e}")
    finally:
        server_sock.close()

if __name__ == '__main__':
    # Gateway'i thread olarak başlat
    threading.Thread(target=run_gateway, daemon=True).start()
    
    # Flask sunucusunu başlat
    print("\n[SERVER] API başlatılıyor (Port 5000)...")
    app.run(host='127.0.0.1', port=5000)