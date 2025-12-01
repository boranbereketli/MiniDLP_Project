# policy_window.py (Düzeltilmiş ve Geliştirilmiş)

from PyQt6.QtWidgets import *
from PyQt6.QtCore import Qt
import requests
import json

SERVER = "http://127.0.0.1:5000"

DATA_TYPES = ["TCKN", "IBAN_TR", "KREDI_KARTI", "E_POSTA", "TEL_NO"]


# ======================================================
#  POLICY TAB SINIFI (Clipboard, USB, Network target paneli)
# ======================================================
class PolicyTab(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()
        self.checks = {}

        # Checkboxlar
        for d in DATA_TYPES:
            cb = QCheckBox(d)
            layout.addWidget(cb)
            self.checks[d] = cb

        # Keywords alanı
        layout.addWidget(QLabel("Anahtar Kelimeler (virgülle ayır):"))
        self.keywords = QLineEdit()
        layout.addWidget(self.keywords)

        self.setLayout(layout)

    # Policy → GUI
    def load(self, data: dict):
        """ Politika verilerini GUI'ye yükler. """
        for d in DATA_TYPES:
            # None veya eksik anahtar gelirse False (Serbest) kabul et
            self.checks[d].setChecked(bool(data.get(d, False)))

        # Keywords listesini birleştir
        kws = data.get("Keywords", [])
        self.keywords.setText(", ".join(kws))
        
        # Etkileşim aç
        self.set_controls_enabled(True)


    # GUI → Policy
    def export(self):
        """ GUI'deki ayarları politika verisine dönüştürür. """
        out = {d: self.checks[d].isChecked() for d in DATA_TYPES}
        kws = [k.strip() for k in self.keywords.text().split(",") if k.strip()]
        out["Keywords"] = kws
        return out
        
    # Kontrolleri etkinleştir/devre dışı bırak
    def set_controls_enabled(self, enabled):
        """ Tüm kontrollerin etkinliğini ayarlar. """
        for cb in self.checks.values():
            cb.setEnabled(enabled)
        self.keywords.setEnabled(enabled)
        


# ======================================================
#  ASIL PENCERE — POLICYWINDOW
# ======================================================
class PolicyWindow(QWidget):
    def __init__(self, vm_id, initial_target=None):
        super().__init__()
        self.vm_id = vm_id
        self.setWindowTitle(f"Politika Düzenle — {vm_id}")
        self.setMinimumSize(800, 500)
        self.network_data = {} # Network politikalarını tutacak
        self.raw_policy = {}
        self.current_target_vm = None # Ağ sekmesinde seçili hedef
        self.initial_target = initial_target # Network sekmesine otomatik geçiş için

        main = QVBoxLayout()

        # Tabs
        self.tabs = QTabWidget()

        self.clip_tab = PolicyTab()
        self.usb_tab = PolicyTab()
        self.net_tab = self.build_network_tab()

        self.tabs.addTab(self.clip_tab, "Clipboard")
        self.tabs.addTab(self.usb_tab, "USB")
        self.tabs.addTab(self.net_tab, "Network")

        main.addWidget(self.tabs)

        # Kaydet butonu
        btn = QPushButton("POLİTİKAYI KAYDET")
        btn.clicked.connect(self.save)
        main.addWidget(btn)

        self.setLayout(main)

        # Politika çek
        self.fetch_existing()
        
        # Eğer Network hedefi belirtilmişse, Network sekmesine geç ve hedefi seç
        if self.initial_target:
            self.tabs.setCurrentWidget(self.net_tab)
            # Listede hedefi bul ve seç
            for i in range(self.target_list.count()):
                if self.target_list.item(i).text() == self.initial_target:
                    self.target_list.setCurrentRow(i)
                    break


    # ===============================================
    # NETWORK PANEL
    # ===============================================
    def build_network_tab(self):
        wrapper = QWidget()
        layout = QHBoxLayout()

        # Sol taraf (Liste ve Ekle/Sil butonu)
        left_layout = QVBoxLayout()
        
        self.target_list = QListWidget()
        self.target_list.itemSelectionChanged.connect(self.load_target_policy)
        left_layout.addWidget(self.target_list)
        
        # Yeni Network Hedefi Ekle butonu
        btn_add_target = QPushButton("Yeni Hedef Ekle")
        btn_add_target.clicked.connect(self.add_new_target)
        left_layout.addWidget(btn_add_target)
        
        # Seçili Network Hedefini Sil butonu
        btn_del_target = QPushButton("Seçili Hedefi Sil")
        btn_del_target.clicked.connect(self.delete_selected_target)
        left_layout.addWidget(btn_del_target)
        
        layout.addLayout(left_layout, 30)

        # Sağ panel: seçili hedefin policy tabı
        self.target_panel = PolicyTab()
        # Başlangıçta devre dışı bırak
        self.target_panel.set_controls_enabled(False) 
        layout.addWidget(self.target_panel, 70)

        wrapper.setLayout(layout)
        return wrapper
        
    # ===============================================
    # MEVCUT POLİTİKAYI SUNUCUDAN GETİR
    # ===============================================
    def fetch_existing(self):
        try:
            r = requests.get(f"{SERVER}/policies/{self.vm_id}", timeout=3)
            if r.status_code != 200:
                QMessageBox.critical(self, "Hata", "Politika sunucudan çekilemedi.")
                return
            self.raw_policy = r.json()
        except Exception:
            QMessageBox.critical(self, "Hata", "Sunucuya bağlanılamadı.")
            return

        # Clipboard
        self.clip_tab.load(self.raw_policy.get("clipboard", {}))

        # USB
        self.usb_tab.load(self.raw_policy.get("usb", {}))

        # Network hedefleri listeye koy
        self.network_data = self.raw_policy.get("network", {})
        self.target_list.clear()
        for target in self.network_data.keys():
            self.target_list.addItem(target)
            
        # Eğer initial_target varsa ve listede yoksa ekleyelim
        if self.initial_target and self.initial_target not in self.network_data:
            self.add_new_target(predefined_id=self.initial_target)


    # ===============================================
    # NETWORK — Yeni Hedef Ekle
    # ===============================================
    def add_new_target(self, predefined_id=None):
        if predefined_id:
            target_vm_id = predefined_id
            ok = True
        else:
            target_vm_id, ok = QInputDialog.getText(self, "Yeni Network Hedefi", 
                                                    "Hedef VM ID'sini girin:")
        
        if ok and target_vm_id:
            target_vm_id = target_vm_id.strip()
            if not target_vm_id: return
            
            if target_vm_id in self.network_data:
                QMessageBox.warning(self, "Uyarı", "Bu hedef zaten listede.")
                return
            
            if target_vm_id == self.vm_id:
                QMessageBox.warning(self, "Uyarı", "Kendi VM ID'nizi hedef olarak ekleyemezsiniz.")
                return

            # Network verisine varsayılan, kısıtlayıcı bir kural ekle (Hepsi True=Yasak)
            default_restriction = {d: True for d in DATA_TYPES}
            default_restriction["Keywords"] = []
            
            self.network_data[target_vm_id] = default_restriction 
            
            # Listeye ekle ve seç
            self.target_list.addItem(target_vm_id)
            self.target_list.setCurrentRow(self.target_list.count() - 1)
            
            # Eğer otomatik olarak ekleniyorsa, kullanıcıya bilgi ver
            if predefined_id:
                QMessageBox.information(self, "Bilgi", f"Yeni hedef '{target_vm_id}' eklendi. Varsayılan olarak tüm veri tipleri kısıtlanmıştır (Yasak).")

    # ===============================================
    # NETWORK — Seçili Hedefi Sil
    # ===============================================
    def delete_selected_target(self):
        item = self.target_list.currentItem()
        if not item:
            QMessageBox.warning(self, "Uyarı", "Silinecek bir hedef seçin.")
            return

        target_vm = item.text()
        reply = QMessageBox.question(self, 'Onay', 
                                     f"'{target_vm}' hedefine uygulanan network kısıtlamasını silmek istediğinizden emin misiniz? (Silinirse bu hedefe giden trafik **incelemesiz/serbest** kalır.)", 
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            # Listeden ve veri yapısından sil
            row = self.target_list.currentRow()
            self.target_list.takeItem(row)
            del self.network_data[target_vm]
            
            # Paneli temizle ve devre dışı bırak
            self.target_panel.set_controls_enabled(False)
            QMessageBox.information(self, "Silindi", f"'{target_vm}' için network kısıtlaması silindi. Bu hedefe giden trafik artık Kaynak VM'nin kuralına tabi değildir.")


    # ===============================================
    # NETWORK — Seçilen hedefin panelini doldur
    # ===============================================
    def load_target_policy(self):
        # Önceki seçili hedefin verilerini kaydet
        if self.current_target_vm and self.current_target_vm in self.network_data:
            self.network_data[self.current_target_vm] = self.target_panel.export()

        item = self.target_list.currentItem()
        if not item:
            self.current_target_vm = None
            # Seçim kalkarsa paneli temizle/devre dışı bırak
            self.target_panel.load({d: False for d in DATA_TYPES})
            self.target_panel.set_controls_enabled(False)
            return

        target_vm = item.text()
        self.current_target_vm = target_vm
        
        policy = self.network_data.get(target_vm, {})
        self.target_panel.load(policy)
        self.target_panel.set_controls_enabled(True)


    # ===============================================
    # GÖNDERİLECEK JSON’U HAZIRLA
    # ===============================================
    def build_final_policy(self):
        # Network panelindeki en son seçili hedefin verilerini kaydet
        if self.current_target_vm and self.current_target_vm in self.network_data:
            self.network_data[self.current_target_vm] = self.target_panel.export()
        
        final = {
            "clipboard": self.clip_tab.export(),
            "usb": self.usb_tab.export(),
            "network": self.network_data 
        }

        return final


    # ===============================================
    # POLİTIKA KAYDET → SERVER'A POST
    # ===============================================
    def save(self):
        final_policy = self.build_final_policy()
        
        payload = {
            "user_id": self.vm_id,
            "policies": final_policy
        }
        
        try:
            r = requests.post(f"{SERVER}/update_policy", json=payload, timeout=5)
            if r.status_code == 200:
                QMessageBox.information(self, "OK", "Politika güncellendi!")
                # Başarılı kayıttan sonra pencereyi kapat
                self.close() 
            else:
                QMessageBox.critical(self, "HATA", f"Sunucuya gönderilemedi. (Durum: {r.status_code})")
        except Exception as e:
            QMessageBox.critical(self, "HATA", f"Sunucuya bağlanılamadı: {e}")