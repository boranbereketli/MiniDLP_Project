YourDLP - Veri Kaybı Önleme (DLP) Sistemi
YourDLP, yerel ağ üzerinde çalışan, hassas verilerin (TCKN, Kredi Kartı, Telefon No vb.) sızdırılmasını engelleyen Python tabanlı bir Veri Kaybı Önleme (Data Loss Prevention) sistemidir.

Bu proje; merkezi bir sunucu, yönetici paneli ve uç nokta ajanı (agent) mimarisiyle çalışır.

🚀 Özellikler
📋 Pano (Clipboard) Koruması: Kullanıcı hassas veri kopyaladığında (Örn: TCKN) otomatik algılar, içeriği temizler ve sunucuya log düşer.

💾 USB Denetimi: İzinsiz USB bellek takıldığında veya USB'ye hassas dosya kopyalanmaya çalışıldığında engeller ve dosyayı karantinaya alır.

💬 Güvenli Ağ Sohbeti: Kullanıcılar arasında mesajlaşma sağlar ancak hassas içerik barındıran mesajları ağ geçidinde (Gateway) engeller.

⚙️ Merkezi Yönetim: Yönetici paneli üzerinden her kullanıcı için (USB, Pano, Ağ) ayrı ayrı kurallar tanımlanabilir.

🕵️‍♂️ Ajan (Agent) Modu: Uygulama kapatılsa bile sistem tepsisine (System Tray) küçülerek arka planda korumaya devam eder.

📊 Detaylı Loglama: Tüm ihlaller ve sistem olayları sunucuda CSV formatında tutulur ve arayüzden izlenebilir.

🛠️ Kurulum ve Gereksinimler
Projenin çalışması için Python 3.x yüklü olmalıdır.

1. Dosyaları Hazırlayın
Tüm proje dosyalarının (py, json, qss) aynı klasörde olduğundan emin olun.

Not: YOUR_DLP_LIB.py kütüphane dosyanızın da bu klasörde bulunması gerekir.

2. Kütüphaneleri Yükleyin
Gerekli Python paketlerini yüklemek için terminali açın ve şu komutu çalıştırın:

Bash

pip install -r requirements.txt
(Eğer requirements.txt dosyanız yoksa manuel olarak: pip install Flask requests pyperclip watchdog PyQt6 komutunu kullanabilirsiniz.)

⚙️ Yapılandırma (Config)
Ajan uygulamasının sunucuyu bulabilmesi için config.json dosyasını düzenlemeniz gerekir.

Tek Bilgisayar (Localhost) Testi İçin:

JSON

{
    "server_ip": "127.0.0.1",
    "server_port": 5000,
    "gateway_port": 9101
}
Farklı Bilgisayarlar (Ağ) Testi İçin: Sunucunun çalıştığı bilgisayarın IP adresini (Örn: 192.168.1.35) server_ip kısmına yazın.

▶️ Çalıştırma Adımları
Sistemi ayağa kaldırmak için aşağıdaki sırayı takip edin:

1. Sunucuyu Başlatın (Server)
Veritabanını yöneten ve ağ trafiğini dinleyen sunucudur.

Bash

python server.py
Çıktı olarak [SERVER] API başlatılıyor... görmelisiniz.

2. Yönetici Panelini Başlatın (Manager)
Kullanıcı eklemek ve kuralları belirlemek için kullanılır.

Bash

python main_window.py
Açılan ekranda "Yeni Kullanıcı Ekle" butonuna basın.

Bir VM ID (Örn: user1) ve İsim girerek kullanıcıyı oluşturun.

3. Ajanı Başlatın (Agent)
Korunacak bilgisayarda (veya test için aynı bilgisayarda) ajanı çalıştırın.

Bash

python unified_agent.py
Sizden VM ID isteyecektir. Yönetici panelinde oluşturduğunuz ID'yi (Örn: user1) girin.

Sistem tepsisinde (saatin yanında) YourDLP simgesi belirecektir.
