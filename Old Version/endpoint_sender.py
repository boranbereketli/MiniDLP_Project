import socket

GATEWAY_HOST = ""              # DLP Gateway'in IP'si
GATEWAY_PORT = 9001            # DLP Gateway portu (dlp_gateway.py'deki LISTEN_PORT ile aynı olmalı)


def main():
    print("========================================")
    print("   Endpoint Sender Agent (PC1)         ")
    print("========================================")
    print(f"DLP Gateway: {GATEWAY_HOST}:{GATEWAY_PORT}")
    print("Çıkmak için 'q' yaz.\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((GATEWAY_HOST, GATEWAY_PORT))
    print("[SENDER] Gateway'e bağlanıldı.\n")

    gateway_file = sock.makefile("r", encoding="utf-8")

    try:
        while True:
            text = input("Gönderilecek mesaj: ").strip()
            if text.lower() in {"q", "quit", "exit"}:
                print("[SENDER] Çıkılıyor...")
                break

            if not text:
                continue

            # Her satır bir mesaj
            sock.sendall((text + "\n").encode("utf-8"))

            # Gateway'den bilgi mesajı gelebilir
            sock.settimeout(0.2)
            try:
                line = gateway_file.readline()
                if line:
                    print("[GATEWAY MESAJI]", line.strip())
            except Exception:
                # Her zaman cevap gelmeyebilir, sorun değil
                pass
            finally:
                sock.settimeout(None)

    except KeyboardInterrupt:
        print("\n[SENDER] Kapatılıyor...")
    finally:
        gateway_file.close()
        sock.close()


if __name__ == "__main__":
    main()
