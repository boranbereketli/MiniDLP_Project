import socket

LISTEN_HOST = ""         # Herkesten dinle
LISTEN_PORT = 9002       # DLP Gateway buraya bağlanacak (dlp_gateway'deki RECEIVER_PORT ile aynı)


def main():
    print("========================================")
    print("   Endpoint Receiver Agent (PC2)       ")
    print("========================================")
    print(f"{LISTEN_HOST}:{LISTEN_PORT} dinleniyor...\n")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((LISTEN_HOST, LISTEN_PORT))
    server_sock.listen(1)

    conn, addr = server_sock.accept()
    print("[RECEIVER] Gateway bağlandı:", addr)

    conn_file = conn.makefile("r", encoding="utf-8")

    try:
        for line in conn_file:
            text = line.rstrip("\n")
            if not text:
                continue

            print(f"[RECEIVER] Yeni mesaj: {text}")

    except KeyboardInterrupt:
        print("\n[RECEIVER] Kapatılıyor...")
    finally:
        conn_file.close()
        conn.close()
        server_sock.close()


if __name__ == "__main__":
    main()
