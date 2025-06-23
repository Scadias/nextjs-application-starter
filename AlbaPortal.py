from unittest import result
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.checkbox import CheckBox
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.screenmanager import Screen
from kivy.uix.anchorlayout import AnchorLayout
from kivy.core.window import Window
import webbrowser
import bcrypt
import os
from bcrypt import hashpw, gensalt, checkpw
import sqlite3
from datetime import datetime
import gspread
from oauth2client.service_account import ServiceAccountCredentials


# Arka plan rengini ayarlıyoruz
Window.clearcolor = (0.1, 0.1, 0.1, 1)  # Siyah tonlarında arka plan
# Pencere boyutunu ayarlıyoruz
Window.size = (400, 600)

# Özel TextInput sınıfı
class NoSpaceTextInput(TextInput):
    def insert_text(self, substring, from_undo=False):
        if ' ' in substring:
            return  # Eğer boşluk karakteri varsa yazmayı engelle
        super(NoSpaceTextInput, self).insert_text(substring, from_undo=from_undo)

    def keyboard_on_key_down(self, window, keycode, text, modifiers):
        if keycode[1] == 'tab':  # Tab tuşu algılandığında
            next_widget = self.get_focus_next()
            if next_widget:  # Sonraki odaklanabilir widget'a geçiş yap
                self.focus = False
                next_widget.focus = True
            return True  # Varsayılan işlevi iptal et
        return super(NoSpaceTextInput, self).keyboard_on_key_down(window, keycode, text, modifiers)
        


# Giriş ekranı
class LoginScreen(Screen):
    def __init__(self, **kwargs):
        super(LoginScreen, self).__init__(**kwargs)
        

        # Ana düzen: AnchorLayout ile ortalama
        anchor_layout = AnchorLayout(anchor_x='center', anchor_y='center')

        # Dikey düzen: Kullanıcı adı, şifre ve buton
        layout = BoxLayout(orientation='vertical', padding=50, spacing=20, size_hint=(None, None))
        layout.size = (400, 300)  # Belirli bir boyut vererek ortalamayı sabitle

        # Kullanıcı veritabanı bağlantısı
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        # Kullanıcı oluşturma (ilk kurulumda bir kez çalıştırın)
        cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
        
        # Şifreyi hashleyerek kaydedin (hash'i str olarak saklıyoruz)
        hashed_password = hashpw("ssh1246".encode(), gensalt()).decode()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin", hashed_password))
        conn.commit()
        conn.close()

        # Alba Portal yazısını oluşturuyoruz
        title_label = Label(text="Alba-Ebikes.com", font_size=30, color=(1, 0.647, 0, 1), pos_hint={'center_x': 0.5, 'center_y': 0.8})
        title_label.bind(on_touch_up=self.on_label_click)  # Tıklama olayını bağla
        layout.add_widget(title_label)

        # Kullanıcı adı
        self.username_input = NoSpaceTextInput(hint_text="Kullanıcı Adı", multiline=False, size_hint=(1, None), height=40)
        layout.add_widget(self.username_input)

        # Şifre
        self.password_input = NoSpaceTextInput(hint_text="Şifre", password=True, multiline=False, size_hint=(1, None), height=40)
        layout.add_widget(self.password_input)
        
        # Giriş butonu
        login_button = Button(text="Giriş Yap", size_hint=(1, None), height=50, on_press=self.login)
        layout.add_widget(login_button)
        
        # Şifre değiştirme butonu
        change_password_button = Button(text="Şifreyi Değiştir", size_hint=(1, None), height=50, on_press=self.open_change_password_popup)
        layout.add_widget(change_password_button)

        # Layout'u ana düzenin içine ekle
        anchor_layout.add_widget(layout)

        # Ana düzeni ekrana ekle
        self.add_widget(anchor_layout)

        

    def on_label_click(self, instance, touch):
        if instance.collide_point(*touch.pos):  # Etiketin üzerine tıklandığını kontrol et
            webbrowser.open('https://alba-ebikes.com/')  # Yönlendirme işlemi

    def login(self, instance):
        username = self.username_input.text
        password = self.password_input.text

        # Kullanıcı veritabanı bağlantısı
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        # Kullanıcıyı veritabanından al
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        # Şifre doğrulama
        if result and checkpw(password.encode(), result[0].encode()):
            self.manager.current = 'main_menu'
        else:
            popup = Popup(title='Hata', content=Label(text='Geçersiz kullanıcı adı veya şifre!'),
                          size_hint=(0.6, None))
            popup.open()

    def open_change_password_popup(self, instance):
        
        # Şifre değiştirme popup'ını aç
        content = BoxLayout(orientation='vertical', padding=20, spacing=10)


        # Kullanıcı adı girişi
        self.username_input_popup = NoSpaceTextInput(hint_text="Kullanıcı Adı", multiline=False, size_hint=(1, None), height=40)
        content.add_widget(self.username_input_popup)

        # Eski şifre girişi
        self.old_password_input = NoSpaceTextInput(hint_text="Eski Şifre", password=True, multiline=False, size_hint=(1, None), height=40)
        content.add_widget(self.old_password_input)

        # Yeni şifre girişi
        self.new_password_input = NoSpaceTextInput(hint_text="Yeni Şifre", password=True, multiline=False, size_hint=(1, None), height=40)
        content.add_widget(self.new_password_input)

        # Yeni şifreyi tekrar girme
        self.confirm_new_password_input = NoSpaceTextInput(hint_text="Yeni Şifreyi Tekrar Girin", password=True, multiline=False, size_hint=(1, None), height=40)
        content.add_widget(self.confirm_new_password_input)

        # Değişiklikleri kaydetme butonu
        change_password_button = Button(text="Şifreyi Değiştir", size_hint=(1, None), height=50, on_press=self.change_password)
        content.add_widget(change_password_button)

        # Kullanıcı adı değiştirme butonu
        change_username_button = Button(text="Kullanıcı Adını Değiştir", size_hint=(1, None), height=50, on_press=self.open_change_username_popup)
        content.add_widget(change_username_button)

        # Popup penceresi
        self.change_password_popup = Popup(title='Şifre Değiştir', content=content, size_hint=(0.6, None), height=420)
        self.change_password_popup.open()

    def change_password(self, instance):
        username = self.username_input_popup.text
        old_password = self.old_password_input.text
        new_password = self.new_password_input.text
        confirm_new_password = self.confirm_new_password_input.text

        # Şifre doğrulama
        if new_password != confirm_new_password:
            popup = Popup(title='Hata', content=Label(text='Yeni şifreler uyuşmuyor!'),
                          size_hint=(0.6, None))
            popup.open()
            return

        # Kullanıcı veritabanı bağlantısı
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        # Kullanıcıyı veritabanından al
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        # Eski şifreyi doğrula
        if result and checkpw(old_password.encode(), result[0].encode()):
            # Yeni şifreyi hashleyerek kaydedin (hash'i str olarak saklıyoruz)
            hashed_new_password = hashpw(new_password.encode(), gensalt()).decode()

            # Yeni şifreyi veritabanında güncelle
            cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_new_password, username))
            conn.commit()  # Değişiklikleri kaydet
            conn.close()

            popup = Popup(title='Başarılı', content=Label(text='Şifre başarıyla değiştirildi!'),
                          size_hint=(0.6, None))
            popup.open()
            self.change_password_popup.dismiss()  # Popup'ı kapat
        else:
            popup = Popup(title='Hata', content=Label(text='Eski şifre yanlış!'),
                          size_hint=(0.6, None))
            popup.open()

    def open_change_username_popup(self, instance):
        # Kullanıcı adı değiştirme popup'ını aç
        content = BoxLayout(orientation='vertical', padding=10, spacing=10)

        # Eski kullanıcı adı girişi
        self.old_username_input = NoSpaceTextInput(hint_text="Eski Kullanıcı Adı", multiline=False, size_hint=(1, None), height=40)
        content.add_widget(self.old_username_input)

        # Yeni kullanıcı adı girişi
        self.new_username_input = NoSpaceTextInput(hint_text="Yeni Kullanıcı Adı", multiline=False, size_hint=(1, None), height=40)
        content.add_widget(self.new_username_input)

        # Değişiklikleri kaydetme butonu
        change_username_button = Button(text="Kullanıcı Adını Değiştir", size_hint=(1, None), height=50, on_press=self.change_username)
        content.add_widget(change_username_button)

        # Popup penceresi
        self.change_username_popup = Popup(title='Kullanıcı Adı Değiştir', content=content, size_hint=(0.6, None), height=250)
        self.change_username_popup.open()

    def change_username(self, instance):
        old_username = self.old_username_input.text
        new_username = self.new_username_input.text

        # Kullanıcı veritabanı bağlantısı
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        # Kullanıcıyı veritabanından al
        cursor.execute("SELECT username FROM users WHERE username = ?", (old_username,))
        result = cursor.fetchone()

        # Eski kullanıcı adını doğrula
        if result:
            # Yeni kullanıcı adını veritabanında güncelle
            cursor.execute("UPDATE users SET username = ? WHERE username = ?", (new_username, old_username))
            conn.commit()  # Değişiklikleri kaydet
            conn.close()

            popup = Popup(title='Başarılı', content=Label(text='Kullanıcı adı başarıyla değiştirildi!'),
                          size_hint=(0.6, None))
            popup.open()
            self.change_username_popup.dismiss()  # Popup'ı kapat
        else:
            popup = Popup(title='Hata', content=Label(text='Eski kullanıcı adı yanlış!'),
                          size_hint=(0.6, None))
            popup.open()


# Batarya Hesaplama Ekranı
class BatteryPriceScreen(Screen):
    def __init__(self, **kwargs):
        super(BatteryPriceScreen, self).__init__(**kwargs)
        
        # Ana düzen: AnchorLayout ile ortalama
        anchor_layout = AnchorLayout(anchor_x='center', anchor_y='center')

        # Dikey düzen: Girişler ve butonlar
        layout = BoxLayout(orientation='vertical', padding=30, spacing=20, size_hint=(None, None))
        layout.size = (400, 500)  # Belirli bir boyut vererek ortalamayı sabitle

        # Batarya Ücreti Hesapla
        title_label = Label(text="  Batarya Fiyat Hesapla  ", font_size=35, color=(1, 0.647, 0, 1), pos_hint={'center_x': 0.5, 'center_y': 0.8})
        layout.add_widget(title_label)

        # Voltaj Girişi
        self.voltage_input = TextInput(hint_text="Batarya Voltajı (V)", multiline=False, input_filter='float', size_hint=(None, None), size=(330, 40))
        self.voltage_input.pos_hint = {'center_x': 0.5}
        layout.add_widget(self.voltage_input)

        # Ah Girişi
        self.ah_input = TextInput(hint_text="Batarya Ah Değeri", multiline=False, input_filter='float', size_hint=(None, None), size=(330, 40))
        self.ah_input.pos_hint = {'center_x': 0.5}
        layout.add_widget(self.ah_input)

        # Döviz Kuru Girişi
        self.exchange_rate_input = TextInput(hint_text="Döviz Kuru", multiline=False, input_filter='float', size_hint=(None, None), size=(330, 40))
        self.exchange_rate_input.pos_hint = {'center_x': 0.5}
        layout.add_widget(self.exchange_rate_input)

        # Bagaj Bataryası seçeneği
        bagaj_layout = BoxLayout(size_hint=(1, None), height=40, padding=(0, 10))
        self.bagaj_checkbox = CheckBox(size_hint=(None, None), size=(40, 40))
        self.bagaj_label = Label(text="[color=ffffff]Bagaj Bataryası[/color]", markup=True, size_hint=(None, None), size=(150, 40))

        bagaj_layout.add_widget(self.bagaj_checkbox)
        bagaj_layout.add_widget(self.bagaj_label)
        layout.add_widget(bagaj_layout)

        # Revizyon Bataryası Seçeneği
        revizyon_layout = BoxLayout(size_hint=(1, None), height=40, padding=(0, 10))
        self.revizyon_checkbox = CheckBox(size_hint=(None, None), size=(40, 40))
        self.revizyon_label = Label(text="[color=ffffff]       Revizyon Bataryası[/color]", markup=True, size_hint=(None, None), size=(150, 40))

        revizyon_layout.add_widget(self.revizyon_checkbox)
        revizyon_layout.add_widget(self.revizyon_label)
        layout.add_widget(revizyon_layout)

        # Bayi Özel İndirim Seçeneği
        bayi_layout = BoxLayout(size_hint=(1, None), height=40, padding=(0, 10))
        self.bayi_checkbox = CheckBox(size_hint=(None, None), size=(40, 40))
        self.bayi_label = Label(text="[color=ffffff]   Bayi Özel İndirim[/color]", markup=True, size_hint=(None, None), size=(150, 40))

        bayi_layout.add_widget(self.bayi_checkbox)
        bayi_layout.add_widget(self.bayi_label)
        layout.add_widget(bayi_layout)

        # Hesapla Butonu
        calculate_button = Button(text="Fiyat Hesapla", size_hint=(None, None), size=(300, 40), on_press=self.calculate_price)
        calculate_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(calculate_button)

        # Fiyatı gösteren etiket
        self.price_label = Label(text="Fiyat: Hesaplamak için bilgileri girin.", size_hint=(1, None), height=40)
        layout.add_widget(self.price_label)

        # Geri Gelme Butonu
        back_button = Button(text="Geri", size_hint=(None, None), size=(300, 40), on_press=self.go_back)
        back_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(back_button)

        # Layout'u ana düzenin içine ekle
        anchor_layout.add_widget(layout)

        # Ana düzeni ekrana ekle
        self.add_widget(anchor_layout)


    def calculate_price(self, instance):
        try:
            # Kullanıcıdan alınan girişler
            voltage = float(self.voltage_input.text)
            ah = float(self.ah_input.text)
            exchange_rate = float(self.exchange_rate_input.text)
            
            # Hücre bilgileri
            cell_cost = 7.14231  # Hücre başına maliyet (USD)
            cells_per_battery = 0  # Batarya başına hücre sayısı

            # 48V 16Ah batarya
            if voltage == 48:
                if ah == 16:
                    cells_per_battery = 65
                elif ah == 10.4:
                    cells_per_battery = 52
                elif ah == 7.8:
                    cells_per_battery = 46
                elif ah == 13:
                    cells_per_battery = 58
                elif ah == 12.8:
                    cells_per_battery = 58

            # 36V 13Ah batarya
            if voltage == 36:
                if ah == 19.2:
                    cells_per_battery = 60
                elif ah == 13:
                    cells_per_battery = 48
                elif ah == 12.8:
                    cells_per_battery = 48
                elif ah == 10.4:
                    cells_per_battery = 50
                elif ah == 7.8:
                    cells_per_battery = 36
                elif ah == 9.6:
                    cells_per_battery = 44
                    
            if cells_per_battery == 0:
                popup = Popup(title='Hata', content=Label(text='Geçerli bir batarya kombinasyonu girin!'),
                              size_hint=(1, None))
                popup.open()
                return

            # Batarya fiyatını hesapla (USD cinsinden)
            total_cell_cost = cell_cost * cells_per_battery
            total_price_tl = total_cell_cost * exchange_rate  # Döviz kuru ile fiyatı TL'ye çevir

            # Revizyon bataryası seçilmişse ek ücret Çıkaralım
            if self.revizyon_checkbox.active:  # Eğer Revizyon bataryası seçildiyse 
                total_price_tl -= 1000

            # Bagaj bataryası seçilmişse ek ücret ekleyelim
            if self.bagaj_checkbox.active:  # Eğer Bagaj bataryası seçildiyse
                total_price_tl += 2000

            # Revizyon bataryası seçilmişse ek ücret Çıkaralım
            if self.bayi_checkbox.active:  # Eğer Bayi Özel İndirim seçildiyse
                total_price_tl *= 0.85  # %20 indirim uygula
            
            # Hesaplanan fiyatı ekrana yazdırma
            self.price_label.text = f"Batarya Fiyatı: {total_price_tl:.2f} TL"
        
        except ValueError:
            # Geçersiz giriş durumunda kullanıcıya hata mesajı
            popup = Popup(title='Hata', content=Label(text='Lütfen geçerli bir sayı girin.'), 
                          size_hint=(1, None))
            popup.open()

    def go_back(self, instance):
        # Geri butonuna tıklandığında ana menüye dönme
        self.manager.current = 'main_menu'

# Parça listesi
class PartsListScreen(Screen):
    def __init__(self, **kwargs):
        super(PartsListScreen, self).__init__(**kwargs)
        
        # Initialize parca_listesi
        self.parca_listesi = {}

        # Ana düzen: AnchorLayout ile ortalama
        anchor_layout = AnchorLayout(anchor_x='center', anchor_y='center')

        # Dikey düzen: Girişler ve butonlar
        layout = BoxLayout(orientation='vertical', padding=30, spacing=20, size_hint=(None, None))
        layout.size = (500, 800)  # Belirli bir boyut vererek ortalamayı sabitle

        # Batarya Ücreti Hesapla
        title_label = Label(text="Yedek Parça Fiyat Hesapla", font_size=30, color=(1, 0.647, 0, 1), pos_hint={'center_x': 0.5, 'center_y': 0.1})
        layout.add_widget(title_label)
        
        # Döviz Kuru Girişi
        self.exchange_rate_input = TextInput(hint_text="Dolar Kuru Gir", multiline=False, input_filter='float', size_hint=(1, None), height=33)
        layout.add_widget(self.exchange_rate_input)
        
        # Parça Arama Girişi
        self.search_input = TextInput(hint_text="Parça Adı Ara", multiline=False, size_hint=(1, None), height=33)
        self.search_input.bind(text=self.on_search_text)
        layout.add_widget(self.search_input)
        
        # Arama sonuçları
        self.results_label = Label(text="Parça Listesi", size_hint=(1, None), height=12)
        layout.add_widget(self.results_label)
     
        
        # Parçaların listeleneceği ScrollView
        self.parts_scroll = ScrollView(size_hint=(1, None), height=400)
        self.parts_box = BoxLayout(orientation='vertical', size_hint_y=None)
        self.parts_box.bind(minimum_height=self.parts_box.setter('height'))
        
        self.parts_scroll.add_widget(self.parts_box)
        layout.add_widget(self.parts_scroll)
        
        # Parça fiyatını hesapla butonu
        calculate_button = Button(text="Fiyat Hesapla", size_hint=(None, None), size=(300, 35), on_press=self.calculate_price)
        calculate_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(calculate_button)

        # Parça fiyat etiketi
        self.price_label = Label(text="Fiyat: Hesaplamak için parça seçin.", size_hint=(1, None), height=25)
        layout.add_widget(self.price_label)

        # Geri Gelme Butonu
        back_button = Button(text="Geri", size_hint=(None, None), size=(300, 30), on_press=self.go_back)
        back_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(back_button)
        
        # Layout'u ana düzenin içine ekle
        anchor_layout.add_widget(layout)

        # Ana düzeni ekrana ekle
        self.add_widget(anchor_layout)
    
    def on_enter(self):
        self.update_parts_list()

    def on_search_text(self, instance, value):
        self.update_parts_list()

    def update_parts_list(self):
        # Listeyi güncellemeye yarayan fonksiyon
        self.parts_box.clear_widgets()
        search_text = self.search_input.text.lower()
        
        # ReportScreen'den güncellenmiş parça listesini al
        report_screen = self.manager.get_screen('report')
        self.parca_listesi = report_screen.parca_listesi
        
        for part, price in self.parca_listesi.items():
            if search_text in part.lower():
                button = Button(text=f"{part} - ${price}", size_hint_y=None, height=40)
                button.bind(on_press=self.on_part_selected)
                self.parts_box.add_widget(button)

    def on_part_selected(self, instance):
        # Parça seçildiğinde fiyatı gösterme
        self.selected_part = instance.text.split(" - ")[0]
        self.selected_price = float(instance.text.split(" - ")[1][1:])
        self.price_label.text = f"{self.selected_part} | Fiyat: {self.selected_price}$"
        
    def calculate_price(self, instance):
        # Dolar kuru ile TL cinsinden hesaplama
        try:
            exchange_rate = float(self.exchange_rate_input.text)
            price_tl = self.selected_price * exchange_rate
            self.price_label.text = f"{self.selected_part} | Fiyat: {price_tl:.2f}₺"
        except AttributeError:
            self.price_label.text = "Lütfen bir parça seçin."
        except ValueError:
            self.price_label.text = "Geçersiz dolar kuru."

        # Bayi Özel Dolar kuru ile TL cinsinden hesaplama
        try:
            exchange_rate = float(self.exchange_rate_input.text)
            price_tl = self.selected_price * exchange_rate
            discounted_price = price_tl * 0.8  # %20 indirim uygulandı
            self.price_label.text = f"({self.selected_part})\nMüşteri Fiyatı: {price_tl:.2f}₺\nBayi Fiyatı: {discounted_price:.2f}₺"
        except AttributeError:
            self.price_label.text = "Lütfen bir parça seçin."
        except ValueError:
            self.price_label.text = "Geçersiz dolar kuru."
    
    def go_back(self, instance):
        # Geri butonuna tıklandığında ana menüye dönme
        self.manager.current = 'main_menu'


# Hakkında Ekranı
class AboutScreen(Screen):
    def __init__(self, **kwargs):
        super(AboutScreen, self).__init__(**kwargs)
        
        layout = BoxLayout(orientation='vertical', padding=50, spacing=20)
        
        # Başlık
        title_label = Label(
            text="Hakkında",
            font_size=35,
            color=(1, 0.647, 0, 1),
            size_hint=(1, 0.2),
            halign="center",
            valign="middle"
        )
        title_label.bind(size=title_label.setter('text_size'))
        layout.add_widget(title_label)
        
        # Hakkında metni (tek label, alt alta)
        about_text = Label(
            text="Bu uygulama Murat Günaydın tarafından\nAlba E-bikes için geliştirilmiştir.",
            font_size=18,
            color=(1, 1, 1, 1),
            size_hint=(1, 0.8),
            halign="center",
            valign="middle"
        )
        about_text.bind(size=about_text.setter('text_size'))
        layout.add_widget(about_text)
        
        # Geri butonu
        back_button = Button(text="Geri", size_hint=(None, None), size=(200, 45), on_press=self.go_back)
        back_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(back_button)
        
        self.add_widget(layout)
    
    def go_back(self, instance):
        self.manager.current = 'main_menu'

# Fiyat Güncelleme Ekranı
class ReportScreen(Screen):
    def __init__(self, **kwargs):
        super(ReportScreen, self).__init__(**kwargs)
        
        self.parca_listesi = load_parts_from_db()
        if not self.parca_listesi:
            self.parca_listesi = {
                "PAS Sensörü": 25.3,
                "El Gazı": 22,
                "G010 250W": 198,
                "G020 250 PRO": 275,
                "G040 500W": 330,
                "1000W MİD STATÖR": 363,
                "750W MİD STATÖR": 330,
                "MID MOTOR PAS SENSÖRÜ": 16.5,
                "MİD DATA KABLOSU": 16.5,
                "1000W MOTOR": 1089,
                "1000W MOTOR CONTROLLER": 330,
                "750W MOTOR": 825,
                "750W CONTROLLER": 275,
                "MİD DRİVE HIZ SENSÖRÜ": 27.5,
                "250W G010 FM": 198,
                "500W G040 FM ÖN MOTOR": 330,
                "250W G010 RM": 198,
                "500W G040 ARKA MOTOR": 330,
                "500W G040 KASET MOTOR": 330,
                "250W KASET MOTOR(G120) (G020)": 264,
                "750W DIŞ DİŞLİ 46T": 44,
                "1000W DIŞ DİŞLİ 46T": 44,
                "JANT VE MOTOR ÖRÜM": 62.7,
                "FREN KOLU TAKIMI": 38.5,
                "MOTOR KABLO DEĞİŞİMİ": 55,
                "HALL SENSÖR DEĞİŞİMİ": 27.5,
                "KATLANIR PEDAL (WELLGO)": 25.3,
                "FOLD2 PİL KUTUSU": 60.5,
                "DS4 DS5 DS6 KUTU": 66,
                "MİD MOTOR BAKIMI": 44,
                "HUB MOTOR PUL SOMUN SETİ": 11,
                "AFX-AF2-BAGAJ-SULUK KİLİT": 66,
                "AFX-AF2-BAGAJ-SULUK CONTROLLER": 66,
                "2.3 MM JANT TELİ + TEL BAŞI (40 ADET)": 22,
                "MİD MOTOR DEBRİYAJ DİŞLİ": 82.5,
                "AYNAKOL 52T": 55,
                "DATA KABLOSU 5İN1 (KİT)": 19.8,
                "BATARYA KIZAĞI": 29.7,
                "ARKA AKTARICI": 55,
                "VİTES KOLU": 16.5,
                "FREN KESİCİ V MK": 41.8,
                "FREN KESİCİ HİDROLİK": 38.5,
                "3İN 1 DATA KABLOSU": 16.5,
                "MOTOR KABLOSU": 22,
                "DUAL BATTERY CONVERTOR": 82.5,
                "AYNAKOL 44T": 66,
                "250W 3LÜ POLYEMİD": 49.5,
                "500W 3LÜ POLYEMİD": 55,
                "AFX BALATA TEKTRO/ZOOM": 16.5,
                "JANT ÇEMBERİ": 33,
                "EL GAZI ÇEVİRİCİ KABLO": 5.5,
                "BATARYA KAPAĞI(DS)": 8.8,
                "MID MOTOR PAS SENSÖRÜ": 27.5,
                "DİSK ROTOR": 22,
                "SPRO 2 DIŞ LASTİK": 33,
                "SPRO2 İÇ LASTİK": 16.5,
                "ORTA GÖBEK": 0,
                "SPRO2 AYAKLIK": 22,
                "FOLD X ve 2 AYAKLIK": 30.8,
                "CİTY 2 ÇAMURLUK SET": 0,
                "Spro Çamurluk": 44,
                "Fold Çamurluk": 42.9,
                "Fold F Çamurluk": 0,
                "Moto Bike Çamurluk": 0
            }
            save_parts_to_db(self.parca_listesi)

        layout = BoxLayout(orientation='vertical', padding=50, spacing=20)
        
        
        # Başlık
        title_label = Label(text="Fiyat Güncelleme", font_size=30, color=(1, 0.647, 0, 1), size_hint=(1, None), height=50, halign="center", valign="middle")
        layout.add_widget(title_label, index=0) 
        
        # Batarya Fiyatları Düzenle
        battery_report_button = Button(text="Batarya Fiyatları Düzenle", size_hint=(None, None), size=(300, 45), on_press=self.show_battery_report)
        battery_report_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(battery_report_button)
        
        # Yedek Parça Fiyatları Düzenle
        parts_report_button = Button(text="Yedek Parça Ekle ve Düzenle", size_hint=(None, None), size=(300, 45), on_press=self.show_parts_report)
        parts_report_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(parts_report_button)
        
        # Geri butonu
        back_button = Button(text="Geri", size_hint=(None, None), size=(200, 45), on_press=self.go_back)
        back_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(back_button)
        
        self.add_widget(layout)
    
    def show_battery_report(self, instance):
        # Batarya fiyatları Düzenle göster
        popup = Popup(title='Batarya Fiyatları Düzenle', content=Label(text='Batarya fiyatları düzenlemesi burada gösterilecek.'), size_hint=(0.8, 0.8))
        popup.open()
    
    def show_parts_report(self, instance):
        # Yedek parça fiyatları Düzenle göster
        content = BoxLayout(orientation='vertical', padding=10, spacing=10)

        # Parça Arama Girişi
        self.search_input = TextInput(hint_text="Parça Adı Ara", multiline=False, size_hint=(1, None), height=40)
        content.add_widget(self.search_input)

        # Parçaların listeleneceği ScrollView
        self.parts_scroll = ScrollView(size_hint=(1, None), height=510)
        self.parts_box = BoxLayout(orientation='vertical', size_hint_y=None)
        self.parts_box.bind(minimum_height=self.parts_box.setter('height'))
        self.parts_scroll.add_widget(self.parts_box)
        content.add_widget(self.parts_scroll)

        # Parça fiyatını güncelleme butonu
        update_button = Button(text="Fiyat Güncelle", size_hint=(None, None), size=(200, 40), on_press=lambda x: self.update_part_price(self.parts_box))
        update_button.pos_hint = {'center_x': 0.5}
        content.add_widget(update_button)

        # Yeni parça ekleme ve silme butonları
        button_layout = BoxLayout(size_hint=(None, None), height=40, spacing=10)
        add_part_button = Button(text="Yeni Parça Ekle", size_hint=(None, None), size=(200, 40), on_press=self.open_add_part_popup)
        delete_part_button = Button(text="Seçilen Parçayı Sil", size_hint=(None, None), size=(200, 40), on_press=self.delete_selected_part)
        button_layout.add_widget(add_part_button)
        button_layout.add_widget(delete_part_button)
        content.add_widget(button_layout)

        # Popup penceresi
        self.parts_report_popup = Popup(title='Yedek Parça Ekle ve Düzenle', content=content, size_hint=(1.0, 1.0))  # Increase width
        self.parts_report_popup.open()

        # Parça listesini güncelle
        self.update_parts_list(self.parts_box, self.search_input)

        # Arama metni değiştiğinde listeyi güncelle
        self.search_input.bind(text=lambda instance, value: self.update_parts_list(self.parts_box, self.search_input))

    def open_add_part_popup(self, instance):
        # Yeni parça ekleme popup'ını aç
        content = BoxLayout(orientation='vertical', padding=10, spacing=10)

        # Parça adı girişi
        self.new_part_name_input = TextInput(hint_text="Parça Adı", multiline=False, size_hint=(1, None), height=40)
        content.add_widget(self.new_part_name_input)

        # Parça fiyatı girişi
        self.new_part_price_input = TextInput(hint_text="Parça Fiyatı", multiline=False, input_filter='float', size_hint=(1, None), height=40)
        content.add_widget(self.new_part_price_input)

        # Ekleme butonu
        add_button = Button(text="Ekle", size_hint=(None, None), size=(200, 40), on_press=self.add_new_part)
        add_button.pos_hint = {'center_x': 0.5}
        content.add_widget(add_button)

        # Popup penceresi
        self.add_part_popup = Popup(title='Yeni Parça Ekle', content=content, size_hint=(0.6, None), height=250)
        self.add_part_popup.open()

    def add_new_part(self, instance):
        part_name = self.new_part_name_input.text
        part_price = self.new_part_price_input.text

        # Boş alan kontrolü
        if not part_name or not part_price:
            popup = Popup(title='Hata', content=Label(text='Lütfen tüm alanları doldurun!'), size_hint=(0.6, None))
            popup.open()
            return

        try:
            part_price = float(part_price)
        except ValueError:
            popup = Popup(title='Hata', content=Label(text='Geçersiz fiyat değeri!'), size_hint=(0.6, None))
            popup.open()
            return

        # Yeni parçayı listeye ekle
        self.parca_listesi[part_name] = part_price
        save_parts_to_db(self.parca_listesi)

        # Popup'ı kapat
        self.add_part_popup.dismiss()

        # Parça listesini güncelle
        self.update_parts_list(self.parts_box, self.search_input)

    def delete_selected_part(self, instance):
        if hasattr(self, 'selected_part') and self.selected_part in self.parca_listesi:
            del self.parca_listesi[self.selected_part]
            save_parts_to_db(self.parca_listesi)  # Save changes to the database
            self.update_parts_list(self.parts_box, self.search_input)
            popup = Popup(title='Başarılı', content=Label(text='Parça başarıyla silindi!'), size_hint=(0.6, None))
            popup.open()
        else:
            popup = Popup(title='Hata', content=Label(text='Lütfen silmek için bir parça seçin!'), size_hint=(0.6, None))
            popup.open()

    def update_parts_list(self, parts_box, search_input):
        parts_box.clear_widgets()
        search_text = search_input.text.lower()

        for part, price in self.parca_listesi.items():
            if search_text in part.lower():
                part_layout = BoxLayout(size_hint_y=None, height=40)
                part_label = Label(text=f"{part} - ${price}", size_hint_x=1.8)
                part_input = TextInput(text=str(price), multiline=False, size_hint_x=0.3)
                part_layout.add_widget(part_label)
                part_layout.add_widget(part_input)
                part_layout.bind(on_touch_down=self.on_part_selected)
                parts_box.add_widget(part_layout)

    def on_part_selected(self, instance, touch):
        if instance.collide_point(*touch.pos):
            self.selected_part = instance.children[1].text.split(" - ")[0]

    def update_part_price(self, parts_box):
        for part_layout in parts_box.children:
            part_label = part_layout.children[1].text.split(" - ")[0]
            new_price = part_layout.children[0].text
            try:
                new_price = float(new_price)
                self.parca_listesi[part_label] = new_price
            except ValueError:
                popup = Popup(title='Hata', content=Label(text='Geçersiz fiyat değeri!'), size_hint=(0.6, None))
                popup.open()
                return

        save_parts_to_db(self.parca_listesi)
        popup = Popup(title='Başarılı', content=Label(text='Fiyatlar başarıyla güncellendi!'), size_hint=(0.6, None))
        popup.open()
        self.parts_report_popup.dismiss()

    def go_back(self, instance):
        self.manager.current = 'main_menu'

# Veritabanı şemasını güncelleme fonksiyonu
def update_database_schema():
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    
    # customers tablosuna action_taken ve arrival_date sütunlarını ekleyin
    cursor.execute("PRAGMA table_info(customers)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'action_taken' not in columns:
        cursor.execute("ALTER TABLE customers ADD COLUMN action_taken TEXT")
    if 'arrival_date' not in columns:
        cursor.execute("ALTER TABLE customers ADD COLUMN arrival_date TEXT")
    
    # parts tablosunu oluşturun
    cursor.execute("CREATE TABLE IF NOT EXISTS parts (name TEXT PRIMARY KEY, price REAL)")
    
    # Check if parts table is empty and insert default parts if it is
    cursor.execute("SELECT COUNT(*) FROM parts")
    if cursor.fetchone()[0] == 0:
        default_parts = {
            "PAS Sensörü": 25.3,
            "El Gazı": 22,
            "G010 250W": 198,
            "G020 250 PRO": 275,
            "G040 500W": 330,
            "1000W MİD STATÖR": 363,
            "750W MİD STATÖR": 330,
            "MID MOTOR PAS SENSÖRÜ": 16.5,
            "MİD DATA KABLOSU": 16.5,
            "1000W MOTOR": 1089,
            "1000W MOTOR CONTROLLER": 330,
            "750W MOTOR": 825,
            "750W CONTROLLER": 275,
            "MİD DRİVE HIZ SENSÖRÜ": 27.5,
            "250W G010 FM": 198,
            "500W G040 FM ÖN MOTOR": 330,
            "250W G010 RM": 198,
            "500W G040 ARKA MOTOR": 330,
            "500W G040 KASET MOTOR": 330,
            "250W KASET MOTOR(G120) (G020)": 264,
            "750W DIŞ DİŞLİ 46T": 44,
            "1000W DIŞ DİŞLİ 46T": 44,
            "JANT VE MOTOR ÖRÜM": 62.7,
            "FREN KOLU TAKIMI": 38.5,
            "MOTOR KABLO DEĞİŞİMİ": 55,
            "HALL SENSÖR DEĞİŞİMİ": 27.5,
            "KATLANIR PEDAL (WELLGO)": 25.3,
            "FOLD2 PİL KUTUSU": 60.5,
            "DS4 DS5 DS6 KUTU": 66,
            "MİD MOTOR BAKIMI": 44,
            "HUB MOTOR PUL SOMUN SETİ": 11,
            "AFX-AF2-BAGAJ-SULUK KİLİT": 66,
            "AFX-AF2-BAGAJ-SULUK CONTROLLER": 66,
            "2.3 MM JANT TELİ + TEL BAŞI (40 ADET)": 22,
            "MİD MOTOR DEBRİYAJ DİŞLİ": 82.5,
            "AYNAKOL 52T": 55,
            "DATA KABLOSU 5İN1 (KİT)": 19.8,
            "BATARYA KIZAĞI": 29.7,
            "ARKA AKTARICI": 55,
            "VİTES KOLU": 16.5,
            "FREN KESİCİ V MK": 41.8,
            "FREN KESİCİ HİDROLİK": 38.5,
            "3İN 1 DATA KABLOSU": 16.5,
            "MOTOR KABLOSU": 22,
            "DUAL BATTERY CONVERTOR": 82.5,
            "AYNAKOL 44T": 66,
            "250W 3LÜ POLYEMİD": 49.5,
            "500W 3LÜ POLYEMİD": 55,
            "AFX BALATA TEKTRO/ZOOM": 16.5,
            "JANT ÇEMBERİ": 33,
            "EL GAZI ÇEVİRİCİ KABLO": 5.5,
            "BATARYA KAPAĞI(DS)": 8.8,
            "MID MOTOR PAS SENSÖRÜ": 27.5,
            "DİSK ROTOR": 22,
            "SPRO 2 DIŞ LASTİK": 33,
            "SPRO2 İÇ LASTİK": 16.5,
            "ORTA GÖBEK": 0,
            "SPRO2 AYAKLIK": 22,
            "FOLD X ve 2 AYAKLIK": 30.8,
            "CİTY 2 ÇAMURLUK SET": 0,
            "Spro Çamurluk": 44,
            "Fold Çamurluk": 42.9,
            "Fold F Çamurluk": 0,
            "Moto Bike Çamurluk": 0
        }
        for part, price in default_parts.items():
            cursor.execute("INSERT INTO parts (name, price) VALUES (?, ?)", (part, price))
    
    conn.commit()
    conn.close()

# Parça fiyatlarını veritabanına kaydetme fonksiyonu
def save_parts_to_db(parts):
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM parts")  # Clear existing parts
    for part, price in parts.items():
        cursor.execute("INSERT OR REPLACE INTO parts (name, price) VALUES (?, ?)", (part, price))
    conn.commit()
    conn.close()

# Parça fiyatlarını veritabanından yükleme fonksiyonu
def load_parts_from_db():
    conn = sqlite3.connect('customers.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name, price FROM parts")
    parts = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()
    return parts

# Google Sheets'e müşteri verisi yazmak için fonksiyon
def save_to_google_sheets(name, surname, phone, product_info, issue, action_taken, arrival_date=None):
    try:
        # 1. Google Sheets API kimlik dosyası ve yetkilendirme
        scope = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
        creds = ServiceAccountCredentials.from_json_keyfile_name('credentials.json', scope)
        client = gspread.authorize(creds)

        # 2. Hedef Sheet dosyasını ve çalışma sayfasını seç
        sheet = client.open_by_key("1XzVDIrFOkrjYeKEhAzPuyRPoYBCB5G51PQMvRArknek").worksheet("Müşteri Kaydı")

        # 3. Verileri hazırla (isim birleştirme, tarih formatı)
        full_name = f"{name} {surname}".strip()
        now = datetime.now().strftime("%d.%m.%Y %H:%M") if arrival_date is None else arrival_date
        row_data = [now, full_name, phone, product_info, issue, action_taken]

        # 4. Tüm satırları al ve eşleşen satırı bul
        all_rows = sheet.get_all_values()
        found_row = None
        for idx, row in enumerate(all_rows, start=1):
            if len(row) >= 4:
                sheet_name = row[1].strip() if len(row) > 1 else ""
                sheet_product = row[3].strip() if len(row) > 3 else ""
                if sheet_name.lower() == full_name.lower() and sheet_product.lower() == product_info.strip().lower():
                    found_row = idx
                    break

        if found_row:
            # Eşleşen satırı güncelle
            sheet.update(f"A{found_row}:F{found_row}", [row_data])
            print(f"✅ Google Sheets'te {found_row}. satır güncellendi.")
        else:
            # Eşleşme yoksa ilk boş satıra ekle
            col_a = sheet.col_values(1)
            first_empty_row = None
            for idx, cell in enumerate(col_a, start=1):
                if not cell.strip():
                    first_empty_row = idx
                    break
            if not first_empty_row:
                first_empty_row = len(col_a) + 1
            for col, value in enumerate(row_data, start=1):
                sheet.update_cell(first_empty_row, col, value)
            print(f"✅ Google Sheets'e {first_empty_row}. satıra başarıyla eklendi.")

    except Exception as e:
        print("❌ Google Sheets'e kayıt eklenemedi:", e)
        



# Müşteri Kaydı Ekranı
class CustomerRecordScreen(Screen):
    def __init__(self, **kwargs):
        super(CustomerRecordScreen, self).__init__(**kwargs)
        
        layout = BoxLayout(orientation='vertical', padding=50, spacing=20)
        
        # Başlık
        title_label = Label(text="Müşteri Kaydı", font_size=30, color=(1, 0.647, 0, 1), size_hint=(1, 0.2), halign="center", valign="middle")
        layout.add_widget(title_label)
        
        # İsim (boşluk engelli)
        self.name_input = NoSpaceTextInput(hint_text="İsim", multiline=False, size_hint=(1, None), height=40)
        self.name_input.bind(on_text_validate=self.focus_next)
        layout.add_widget(self.name_input)
        
        # Soyisim (boşluk engelli)
        self.surname_input = NoSpaceTextInput(hint_text="Soyisim", multiline=False, size_hint=(1, None), height=40)
        self.surname_input.bind(on_text_validate=self.focus_next)
        layout.add_widget(self.surname_input)
        
        # Telefon (boşluk engelli)
        self.phone_input = NoSpaceTextInput(hint_text="Telefon", multiline=False, size_hint=(1, None), height=40)
        self.phone_input.bind(on_text_validate=self.focus_next)
        layout.add_widget(self.phone_input)
        
        # Ürün Bilgisi (boşluk engelli)
        self.product_info_input = TextInput(hint_text="Ürün Bilgisi", multiline=False, size_hint=(1, None), height=40)
        self.product_info_input.bind(on_text_validate=self.focus_next)
        layout.add_widget(self.product_info_input)
        
        # Bildirilen Arıza (boşluk serbest)
        self.issue_input = TextInput(hint_text="Bildirilen Arıza", multiline=True, size_hint=(1, None), height=80)
        self.issue_input.bind(on_text_validate=self.focus_next)
        layout.add_widget(self.issue_input)
        
        # Yapılan İşlem (boşluk serbest)
        self.action_taken_input = TextInput(hint_text="Yapılan İşlem", multiline=True, size_hint=(1, None), height=80)
        self.action_taken_input.bind(on_text_validate=self.focus_next)
        layout.add_widget(self.action_taken_input)
        
        # Kaydet Butonu
        save_button = Button(text="Kaydet", size_hint=(None, None), size=(200, 45), on_press=self.save_record)
        save_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(save_button)
        
        # Kayıtlı Müşterileri Gösterme Butonu
        show_records_button = Button(text="Kayıtlı Müşterileri Göster", size_hint=(None, None), size=(200, 45), on_press=self.show_records)
        show_records_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(show_records_button)
        
        # Geri Butonu
        back_button = Button(text="Geri", size_hint=(None, None), size=(200, 45), on_press=self.go_back)
        back_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(back_button)
        
        self.add_widget(layout)
    
    def focus_next(self, instance):
        instance.focus = False
        next_widget = instance.get_focus_next()
        if next_widget:
            next_widget.focus = True
    
    def save_record(self, instance):
        name = self.name_input.text
        surname = self.surname_input.text
        phone = self.phone_input.text
        product_info = self.product_info_input.text
        issue = self.issue_input.text
        action_taken = self.action_taken_input.text
        arrival_date = datetime.now().strftime("%Y-%m-%d")
        
        # Boş alan kontrolü
        if not name or not surname or not phone or not product_info or not issue:
            popup = Popup(title='Hata', content=Label(text='Lütfen tüm alanları doldurun!'), size_hint=(0.6, None))
            popup.open()
            return
        
        # Veritabanına kaydetme işlemi
        conn = sqlite3.connect('customers.db')
        cursor = conn.cursor()
        
        # Aynı isim, soyisim ve telefon numarasıyla kayıt olup olmadığını kontrol et
        cursor.execute("SELECT rowid FROM customers WHERE name = ? AND surname = ? AND phone = ?", (name, surname, phone))
        existing_customer = cursor.fetchone()
        
        if existing_customer:
            # Mevcut kaydı güncelle
            cursor.execute("UPDATE customers SET product_info = ?, issue = ?, action_taken = ?, arrival_date = ? WHERE rowid = ?", (product_info, issue, action_taken, arrival_date, existing_customer[0]))
            popup = Popup(title='Başarılı', content=Label(text='Müşteri kaydı başarıyla güncellendi!'), size_hint=(0.6, None))
        else:
            # Yeni kayıt oluştur
            cursor.execute("INSERT INTO customers (name, surname, phone, product_info, issue, action_taken, arrival_date) VALUES (?, ?, ?, ?, ?, ?, ?)", (name, surname, phone, product_info, issue, action_taken, arrival_date))
            popup = Popup(title='Başarılı', content=Label(text='Müşteri kaydı başarıyla oluşturuldu!'), size_hint=(0.6, None))
        
        conn.commit()
        conn.close()

        # 🔽 Google Sheets'e ekle
        save_to_google_sheets(name, surname, phone, product_info, issue, action_taken, arrival_date)

        popup.open()
        
        # Müşteri listesini güncelle
        self.manager.get_screen('customer_list').update_customer_list()
        
        # Giriş alanlarını temizle
        self.clear_inputs()
    
    def clear_inputs(self):
        self.name_input.text = ""
        self.surname_input.text = ""
        self.phone_input.text = ""
        self.product_info_input.text = ""
        self.issue_input.text = ""
        self.action_taken_input.text = ""
    
    def show_records(self, instance):
        self.manager.current = 'customer_list'
    
    def go_back(self, instance):
        self.manager.current = 'main_menu'

# Kayıtlı Müşterileri Gösterme Ekranı
class CustomerListScreen(Screen):
    def __init__(self, **kwargs):
        super(CustomerListScreen, self).__init__(**kwargs)
        
        layout = BoxLayout(orientation='vertical', padding=50, spacing=20)
        
        # Başlık
        title_label = Label(text="Kayıtlı Müşteriler", font_size=30, color=(1, 0.647, 0, 1), size_hint=(1, None), height=50, halign="center", valign="middle")
        layout.add_widget(title_label)
        
        # Arama Girişi
        self.search_input = TextInput(hint_text="İsim Ara", multiline=False, size_hint=(1, None), height=40)
        self.search_input.bind(text=self.on_search_text)
        layout.add_widget(self.search_input)
        
        # Müşteri Listesi
        self.scroll_view = ScrollView(size_hint=(1, 1))
        self.customer_list = BoxLayout(orientation='vertical', size_hint_y=None)
        self.customer_list.bind(minimum_height=self.customer_list.setter('height'))
        self.scroll_view.add_widget(self.customer_list)
        layout.add_widget(self.scroll_view)
        
        # Geri Butonu
        back_button = Button(text="Geri", size_hint=(None, None), size=(200, 45), on_press=self.go_back)
        back_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(back_button)
        
        self.add_widget(layout)
        self.update_customer_list()
    
    def on_search_text(self, instance, value):
        self.update_customer_list()
    
    def update_customer_list(self):
        self.customer_list.clear_widgets()
        search_text = self.search_input.text.lower()
        
        conn = sqlite3.connect('customers.db')
        cursor = conn.cursor()
        cursor.execute("SELECT rowid, name, surname, phone, product_info, issue, action_taken, arrival_date FROM customers")
        customers = cursor.fetchall()
        conn.close()
        
        for customer in customers:
            rowid, name, surname, phone, product_info, issue, action_taken, arrival_date = customer
            if search_text in name.lower():
                customer_info = f"İsim: {name} {surname}\nTelefon: {phone}\nÜrün Bilgisi: {product_info}\nBildirilen Arıza: {issue}\nYapılan İşlem: {action_taken}\nGeliş Tarihi: {arrival_date}"
                customer_label = Label(text=customer_info, size_hint_y=None, height=150)
                edit_button = Button(text="Düzenle", size_hint_y=None, height=40, on_press=lambda instance, rowid=rowid: self.edit_customer(rowid))
                remove_button = Button(text="Kaldır", size_hint_y=None, height=40, on_press=lambda instance, rowid=rowid: self.confirm_remove_customer(rowid))
                button_layout = BoxLayout(size_hint_y=None, height=40)
                button_layout.add_widget(edit_button)
                button_layout.add_widget(remove_button)
                self.customer_list.add_widget(customer_label)
                self.customer_list.add_widget(button_layout)
    
    def edit_customer(self, rowid):
        self.manager.current = 'customer_record'
        conn = sqlite3.connect('customers.db')
        cursor = conn.cursor()
        cursor.execute("SELECT name, surname, phone, product_info, issue, action_taken, arrival_date FROM customers WHERE rowid = ?", (rowid,))
        customer = cursor.fetchone()
        conn.close()
        
        if customer:
            name, surname, phone, product_info, issue, action_taken, arrival_date = customer
            self.manager.get_screen('customer_record').name_input.text = name or ""
            self.manager.get_screen('customer_record').surname_input.text = surname or ""
            self.manager.get_screen('customer_record').phone_input.text = phone or ""
            self.manager.get_screen('customer_record').product_info_input.text = product_info or ""
            self.manager.get_screen('customer_record').issue_input.text = issue or ""
            self.manager.get_screen('customer_record').action_taken_input.text = action_taken or ""
            self.manager.get_screen('customer_record').rowid = rowid
    
    def confirm_remove_customer(self, rowid):
        content = BoxLayout(orientation='vertical', padding=10, spacing=10)
        message = Label(text="Bu müşteriyi silmek istediğinizden emin misiniz?")
        button_layout = BoxLayout(size_hint_y=None, height=40, spacing=10)
        yes_button = Button(text="Evet", on_press=lambda instance: self.remove_customer(rowid))
        no_button = Button(text="Hayır", on_press=lambda instance: self.dismiss_popup())
        button_layout.add_widget(yes_button)
        button_layout.add_widget(no_button)
        content.add_widget(message)
        content.add_widget(button_layout)
        
        self.popup = Popup(title='Onay', content=content, size_hint=(0.6, 0.4))
        self.popup.open()
    
    def dismiss_popup(self):
        self.popup.dismiss()
    
    def remove_customer(self, rowid):
        conn = sqlite3.connect('customers.db')
        cursor = conn.cursor()
        cursor.execute("DELETE FROM customers WHERE rowid = ?", (rowid,))
        conn.commit()
        conn.close()
        
        # Müşteri listesini güncelle
        self.update_customer_list()
        
        # Popup'ı kapat
        self.dismiss_popup()
    
    def go_back(self, instance):
        self.manager.current = 'customer_record'

# Ana menü ekranı
class MainMenuScreen(Screen):
    def __init__(self, **kwargs):
        super(MainMenuScreen, self).__init__(**kwargs)
        
        layout = BoxLayout(orientation='vertical', padding=50, spacing=20)
        
        # Alba Ebikes Başlık
        title_label = Label(text="Alba-Ebikes.com", font_size=30, color=(1, 0.647, 0, 1), size_hint=(1, 0.2), halign="center", valign="middle")
        title_label.bind(on_touch_up=self.on_label_click)  # Tıklama olayını bağla
        layout.add_widget(title_label)
  
        # Batarya Ücret Hesaplama butonu
        battery_button = Button(text="Batarya Fiyat Hesaplama", size_hint=(None, None), size=(400, 65), on_press=self.battery_price)
        battery_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(battery_button)
        
        # Yedek Parça Fiyat Listesi butonu
        parts_button = Button(text="Yedek Parça Fiyat Listesi", size_hint=(None, None), size=(400, 65), on_press=self.parts_list)
        parts_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(parts_button)
        
        # Teknik Servis Müşteri Listesi butonu
        service_button = Button(text="Teknik Servis Müşteri Listesi", size_hint=(None, None), size=(400, 65), on_press=self.open_google_sheets)
        service_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(service_button)
        
        # Yedek Parça Stok Durumu butonu
        stock_button = Button(text="Yedek Parça Stok Durumu", size_hint=(None, None), size=(400, 65), on_press=self.open_stock_status)
        stock_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(stock_button)

        # Müşteri Kaydı butonu
        customer_record_button = Button(text="Müşteri Kaydı", size_hint=(None, None), size=(400, 65), on_press=self.customer_record)
        customer_record_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(customer_record_button)

        # Düzenleme butonu
        report_button = Button(text="Fiyat Güncelleme", size_hint=(None, None), size=(400, 65), on_press=self.report)
        report_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(report_button)

        # Hakkında butonu
        about_button = Button(text="Hakkında", size_hint=(None, None), size=(400, 65), on_press=self.about)
        about_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(about_button)

        # ÇIKIŞ
        exit_button = Button(text="ÇIKIŞ", size_hint=(None, None), size=(200, 45), on_press=self.exit_app)
        exit_button.pos_hint = {'center_x': 0.5}
        layout.add_widget(exit_button)

        self.add_widget(layout)

    def on_label_click(self, instance, touch):
        if instance.collide_point(*touch.pos):  # Etiketin üzerine tıklandığını kontrol et
            webbrowser.open('https://alba-ebikes.com/')  # Yönlendirme işlemi

    def battery_price(self, instance):
        self.manager.current = 'battery_price'

    def parts_list(self, instance):
        self.manager.current = 'parts_list'

    def open_google_sheets(self, instance):
        # Teknik Servis Müşteri Listesi için Google Sheets bağlantısını aç
        url = "https://docs.google.com/spreadsheets/d/1XzVDIrFOkrjYeKEhAzPuyRPoYBCB5G51PQMvRArknek/edit?gid=0#gid=0"
        webbrowser.open(url)

    def open_stock_status(self, instance):
        # Yedek Parça Stok Durumu için Google Sheets bağlantısını aç
        url = "https://docs.google.com/spreadsheets/d/1i5P7RXsp5FTW4kcxpJwGhEC4JByFSJFPY_gahOVo93Q/edit?gid=0#gid=0"  
        webbrowser.open(url)
        
    def customer_record(self, instance):
        self.manager.current = 'customer_record'

    def report(self, instance):
        self.manager.current = 'report'

    def about(self, instance):
        self.manager.current = 'about'

    def exit_app(self, instance):
        self.manager.current = 'login'

# Uygulama yönetici
class AlbaPortalApp(App):
    def build(self):
        update_database_schema()  # Veritabanı şemasını güncelle
        sm = ScreenManager()
        self.sm = ScreenManager()
        self.sm.add_widget(LoginScreen(name='login'))
        self.sm.add_widget(MainMenuScreen(name='main_menu'))
        self.sm.add_widget(BatteryPriceScreen(name='battery_price'))
        self.sm.add_widget(PartsListScreen(name='parts_list'))
        self.sm.add_widget(CustomerRecordScreen(name='customer_record'))
        self.sm.add_widget(CustomerListScreen(name='customer_list'))
        self.sm.add_widget(ReportScreen(name='report'))
        self.sm.add_widget(AboutScreen(name='about'))
        self.sm.add_widget(LoginScreen(name='exit_button'))
        return self.sm

    def __init__(self, **kwargs):
        super(AlbaPortalApp, self).__init__(**kwargs)
        self.title = "Alba Portal"  # Pencere başlığını ayarla
        self.icon = 'icon.ico'  # İkonu ayarla (örneğin icon.ico dosyasını kullan)

if __name__ == "__main__":
    AlbaPortalApp().run()