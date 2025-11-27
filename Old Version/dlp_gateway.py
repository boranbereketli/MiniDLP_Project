import socket
from dataclasses import dataclass
from typing import Optional

from dlp_monitor import scan_content, log_incident

# ---- KONFİG ----
LISTEN_HOST = ""   # Sender'ın bağlanacağı IP (gateway'in kendi IP'si)
LISTEN_PORT = 9001        # Sender -> DLP portu

RECEIVER_HOST = ""  # BURAYA ALICI PC'nin IP'sini yaz
RECEIVER_PORT = 9002            # DLP -> Receiver portu


@dataclass
class Message:
    src: str
    dst: str
    channel: str
    payload: str


class DLPAgent:
    def __init__(self, name="DLP_GATEWAY"):
        self.name = name

    def handle(self, msg: Message) -> Optional[Message]:
        print(f"\n[{self.name}] Mesaj alındı: {msg.src} -> {msg.dst}")
        print(f"Kanal  : {msg.channel}")
        print(f"İçerik : {msg.payload}")

        incidents = scan_content(msg.payload)

        if incidents:
            detected_types = sorted({i["data_type"] for i in incidents})
            data_type_str = "/".join(detected_types)
            masked_samples = ", ".join(sorted({i["masked_match"] for i in incidents}))

            log_incident(
                event_type=f"{msg.channel} Mesajı",
                data_type=data_type_str,
                action="ENGEL - Mesaj gönderilmedi",
                details=f"{msg.src}->{msg.dst} | {masked_samples}"
            )

            print(f"[{self.name}] UYARI: Mesaj BLOKLANDI!")
            print(f"  Veri tipleri : {data_type_str}")
            print(f"  Örnek       : {masked_samples}")
            return None
        else:
            log_incident(
                event_type=f"{msg.channel} Mesajı",
                data_type="YOK",
                action="İZİN VERİLDİ - Mesaj iletildi",
                details=f"{msg.src}->{msg.dst} | {msg.payload[:50]}"
            )

            print(f"[{self.name}] Mesaj temiz, {msg.dst}'ye iletiliyor.")
            return msg


def run_gateway():
    dlp = DLPAgent()

    # Alıcıya bağlantı aç
    print(f"[{dlp.name}] Receiver'a bağlanılıyor: {RECEIVER_HOST}:{RECEIVER_PORT}")
    receiver_sock = socket.create_connection((RECEIVER_HOST, RECEIVER_PORT))
    print(f"[{dlp.name}] Receiver bağlantısı OK.")

    # Sender'dan gelecek bağlantıyı dinle
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((LISTEN_HOST, LISTEN_PORT))
    server_sock.listen(1)
    print(f"[{dlp.name}] Sender için dinleniyor: {LISTEN_HOST}:{LISTEN_PORT}")

    sender_sock, sender_addr = server_sock.accept()
    print(f"[{dlp.name}] Sender bağlandı:", sender_addr)

    sender_file = sender_sock.makefile("r", encoding="utf-8")

    try:
        for line in sender_file:
            text = line.rstrip("\n")
            if not text:
                continue

            msg = Message(
                src="SENDER_PC",
                dst="RECEIVER_PC",
                channel="chat",
                payload=text
            )

            checked = dlp.handle(msg)

            if checked is None:
                # İstersen sender'a uyarı mesajı da gönderebilirsin
                sender_sock.sendall("[DLP] Mesajın hassas veri içerdiği için gönderilmedi.\n".encode("utf-8"))
            else:
                # Temizse alıcıya ilet
                receiver_sock.sendall((checked.payload + "\n").encode("utf-8"))

    except KeyboardInterrupt:
        print("\n[Gateway] Kapatılıyor...")
    finally:
        sender_file.close()
        sender_sock.close()
        receiver_sock.close()
        server_sock.close()


if __name__ == "__main__":
    run_gateway()
