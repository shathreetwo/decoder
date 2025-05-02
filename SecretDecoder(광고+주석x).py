from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.core.text import LabelBase
import random
from kivy.graphics import Color, Rectangle 
from kivy.clock import Clock
from kivy.uix.textinput import TextInput
from kivy.uix.spinner import Spinner
import base64
from kivy.core.clipboard import Clipboard 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib
import requests
from bs4 import BeautifulSoup
import json
import os
from kivy.utils import platform 
from kivy.metrics import dp, sp
from kivy.uix.spinner import SpinnerOption
from kivy.uix.image import Image

from jnius import autoclass, cast
from android import activity
from android.runnable import run_on_ui_thread


LabelBase.register(name='Font', fn_regular='NotoSansKR.ttf')

AES_KEY = b'mysecretaeskey12'  
AES_BLOCK_SIZE = 16

DES_KEY = b'8bytekey'   
DES_BLOCK_SIZE = 8

AES_DEFAULT_KEY = b'myaesdefaultkey1'   
DES_DEFAULT_KEY = b'deskey88'           


AdMobModule = autoclass("org.kivy.admob.AdMobModule")
PythonActivity = autoclass("org.kivy.android.PythonActivity")

@run_on_ui_thread
def load_admob(activity):
    AdMobModule.loadInterstitial(activity)

@run_on_ui_thread
def show_admob(activity):
    AdMobModule.showInterstitial(activity)

class MainScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.current_activity = cast('android.app.Activity', PythonActivity.mActivity)
        load_admob(self.current_activity)

        layout = BoxLayout(orientation='vertical', padding=dp(20), spacing=dp(15))

        # 상단 이미지 (예: logo.png)
        top_image = Image(
            source='logo2.png',  # 프로젝트 내 이미지 파일 경로
            size_hint=(1, 0.2),  # 화면 비율로 조절 (높이 40%)
            allow_stretch=True,
            keep_ratio=True
        )
        layout.add_widget(top_image)
        
        spy_image = Image(
            source='spy_lobby.png',
            size_hint=(1, 0.5),
            allow_stretch=True,
            keep_ratio=True
        )
        layout.add_widget(spy_image)


        btn3 = Button(text='암호문', font_name='Font', font_size=sp(28),
                      size_hint_y=None, height=dp(80))
        btn3.bind(on_press=self.show_ad_and_switch)
        layout.add_widget(btn3)

        self.add_widget(layout)

    def show_ad_and_switch(self, instance):
        show_admob(self.current_activity)
        App.get_running_app().switch_to_screen('encry')





class KoreanSpinnerOption(SpinnerOption):
    font_name = 'Font'  
    font_size = sp(20)


class CipherApp(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.algorithm_groups = {
            '대칭키 암호화': ['AES', 'DES'],
            '비대칭키 암호화': ['RSA'],
            '해시': ['SHA-256'],
            '고전 암호': ['Caesar', 'Reverse'],
            '인코딩': ['Base64', 'ASCII', 'Unicode']
        }
        self.rsa_key = RSA.generate(2048)

        layout = BoxLayout(orientation='vertical', padding=dp(20), spacing=dp(10))


        spinner_layout = BoxLayout(orientation='horizontal', spacing=dp(10), size_hint_y=None, height=dp(50))

        self.group_spinner = Spinner(
            text='암호화 종류 선택',
            values=tuple(self.algorithm_groups.keys()),
            font_name='Font',
            font_size=sp(20),
            option_cls=KoreanSpinnerOption,
            size_hint=(0.5, 1),
            height=dp(50)
        )
        self.group_spinner.bind(text=self.on_group_select)
        spinner_layout.add_widget(self.group_spinner)

        self.algo_spinner = Spinner(
            text='알고리즘 선택',
            values=self.algorithm_groups['대칭키 암호화'],
            font_name='Font',
            font_size=sp(20),
            size_hint=(0.5, 1),
            height=dp(50)
        )
        self.algo_spinner.bind(text=self.on_algo_select)
        spinner_layout.add_widget(self.algo_spinner)

        layout.add_widget(spinner_layout)


        self.key_input_layout = BoxLayout(orientation='vertical', size_hint_y=None, height=0)
        self.key_input = TextInput(
            hint_text="암호 키 입력 (AES/DES)",
            font_name='Font',
            font_size=sp(20),
            multiline=False,
            size_hint_y=None,
            height=dp(50)
        )
        self.key_input_layout.add_widget(self.key_input)
        self.key_input_layout.opacity = 0
        self.key_input_layout.disabled = True
        layout.add_widget(self.key_input_layout)


        self.rsa_key_line = BoxLayout(orientation='horizontal', spacing=dp(10), size_hint_y=None, height=0)

        self.rsa_pubkey_label = Label(text="공개키:", font_name='Font', font_size=sp(18), size_hint=(0.15, 1))
        self.rsa_pubkey_input = TextInput(
            hint_text="-----BEGIN PUBLIC KEY----- ...",
            font_name='Font',
            font_size=sp(16),
            multiline=False,
            size_hint=(0.35, 1)
        )
        self.rsa_privkey_label = Label(text="개인키:", font_name='Font', font_size=sp(18), size_hint=(0.15, 1))
        self.rsa_privkey_input = TextInput(
            hint_text="-----BEGIN PRIVATE KEY----- ...",
            font_name='Font',
            font_size=sp(16),
            multiline=False,
            size_hint=(0.35, 1)
        )

        self.rsa_key_line.add_widget(self.rsa_pubkey_label)
        self.rsa_key_line.add_widget(self.rsa_pubkey_input)
        self.rsa_key_line.add_widget(self.rsa_privkey_label)
        self.rsa_key_line.add_widget(self.rsa_privkey_input)

        self.rsa_key_line.opacity = 0
        self.rsa_key_line.disabled = True
        layout.add_widget(self.rsa_key_line)


        self.plain_input = TextInput(
            hint_text="여기에 평문 입력 (키 없으면 기본키)",
            font_name='Font',
            font_size=sp(20),
            multiline=True
        )
        layout.add_widget(self.plain_input)


        self.encrypt_button = Button(
            text="암호화",
            font_name='Font',
            font_size=sp(22),
            size_hint=(1, None),
            height=dp(50)
        )
        self.encrypt_button.bind(on_press=self.encrypt_text)
        layout.add_widget(self.encrypt_button)

        output_layout = BoxLayout(orientation='horizontal', spacing=dp(10), size_hint_y=None, height=dp(50))

        self.encrypted_output = Label(
            text="암호문이 여기에 표시됩니다",
            font_name='Font',
            font_size=sp(18)
        )
        output_layout.add_widget(self.encrypted_output)

        self.copy_button = Button(
            text="복사",
            font_name='Font',
            font_size=sp(18),
            size_hint=(None, 1),
            width=dp(80)
        )
        self.copy_button.bind(on_press=self.copy_to_clipboard)
        output_layout.add_widget(self.copy_button)

        layout.add_widget(output_layout)


        self.cipher_input = TextInput(
            hint_text="여기에 암호문 입력",
            font_name='Font',
            font_size=sp(20),
            multiline=True
        )
        layout.add_widget(self.cipher_input)


        self.decrypt_button = Button(
            text="복호화",
            font_name='Font',
            font_size=sp(22),
            size_hint=(1, None),
            height=dp(50)
        )
        self.decrypt_button.bind(on_press=self.decrypt_text)
        layout.add_widget(self.decrypt_button)


        decrypt_output_layout = BoxLayout(orientation='horizontal', spacing=dp(10), size_hint_y=None, height=dp(50))

        self.decrypted_output = Label(
            text="복호화된 평문이 여기에 표시됩니다",
            font_name='Font',
            font_size=sp(18)
        )
        decrypt_output_layout.add_widget(self.decrypted_output)

        self.copy_decrypted_button = Button(
            text="복사",
            font_name='Font',
            font_size=sp(18),
            size_hint=(None, 1),
            width=dp(80)
        )
        self.copy_decrypted_button.bind(on_press=self.copy_decrypted_text)
        decrypt_output_layout.add_widget(self.copy_decrypted_button)

        layout.add_widget(decrypt_output_layout)


        back_button = Button(
            text='← 뒤로가기',
            font_name='Font',
            font_size=sp(20),
            size_hint=(1, None),
            height=dp(50)
        )
        back_button.bind(on_press=lambda x: setattr(self.manager, 'current', 'main'))
        layout.add_widget(back_button)

        self.add_widget(layout)

    def caesar_encrypt(self, text, shift=3):
        return ''.join(chr((ord(char) + shift) % 1114112) for char in text)  

    def caesar_decrypt(self, text, shift=3):
        return ''.join(chr((ord(char) - shift) % 1114112) for char in text)

    def encrypt_text(self, instance):
        algo = self.algo_spinner.text
        plain = self.plain_input.text
        if algo == 'Caesar':
            result = self.caesar_encrypt(plain)
        elif algo == 'Base64':
            result = base64.b64encode(plain.encode('utf-8')).decode('utf-8')
        elif algo == 'AES':
            result = self.aes_encrypt(plain)
        elif algo == 'Reverse':
            result = plain[::-1]  
        elif algo == 'DES':
            result = self.des_encrypt(plain)
        elif algo == 'RSA':
            result = self.rsa_encrypt(plain)

        elif algo == 'SHA-256':
            result = self.hash_text_sha256(plain)

        elif algo == 'ASCII':
            result = ' '.join(str(ord(c)) for c in plain)  

        elif algo == 'Unicode':
            result = ' '.join(f'U+{ord(c):04X}' for c in plain)  
    
        else:
            result = "지원되지 않는 알고리즘입니다."
            
        self.encrypted_output.text = f"암호문: {result}"

    def decrypt_text(self, instance):
        algo = self.algo_spinner.text
        cipher = self.cipher_input.text
        try:
            if algo == 'Caesar':
                result = self.caesar_decrypt(cipher)
            elif algo == 'Base64':
                result = base64.b64decode(cipher.encode('utf-8')).decode('utf-8')
            elif algo == 'AES':
                result = self.aes_decrypt(cipher)
            elif algo == 'Reverse':
                result = cipher[::-1]  
            elif algo == 'DES':
                result = self.des_decrypt(cipher)
            elif algo == 'RSA':
                result = self.rsa_decrypt(cipher)
            elif algo == 'SHA-256':
                result = "해시는 복호화가 불가능합니다."
            elif algo == 'ASCII':
                try:
                    result = ''.join(chr(int(code)) for code in cipher.strip().split())
                except:
                    result = "숫자 형식 오류: 공백으로 구분된 숫자여야 합니다."

            elif algo == 'Unicode':
                try:
                    result = ''.join(chr(int(code.replace("U+", ""), 16)) for code in cipher.strip().split())
                except:
                    result = "형식 오류: U+로 시작하는 유니코드 값이어야 합니다."
                
            else:
                result = "지원되지 않는 알고리즘입니다."
            
            self.decrypted_output.text = f"평문: {result}"
        except Exception:
            self.decrypted_output.text = "복호화 오류: 형식을 확인하세요."

    def copy_to_clipboard(self, instance):
        text = self.encrypted_output.text.replace("암호문: ", "")
        Clipboard.copy(text)
      

    def copy_decrypted_text(self, instance):
        text = self.decrypted_output.text.replace("평문: ", "")
        Clipboard.copy(text)
     

    def aes_encrypt(self, plaintext):
        key_input_text = self.key_input.text.strip()
        key = key_input_text.encode('utf-8') if key_input_text else AES_DEFAULT_KEY

        if len(key) not in [16, 24, 32]:
            return "AES 키는 16, 24 또는 32바이트여야 합니다."

        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return f"{iv}:{ct}"

    def aes_decrypt(self, ciphertext):
        try:
            key_input_text = self.key_input.text.strip()
            key = key_input_text.encode('utf-8') if key_input_text else AES_DEFAULT_KEY

            if len(key) not in [16, 24, 32]:
                return "AES 키는 16, 24 또는 32바이트여야 합니다."

            iv_b64, ct_b64 = ciphertext.split(":")
            iv = base64.b64decode(iv_b64)
            ct = base64.b64decode(ct_b64)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
            return pt
        except Exception:
            return "복호화 실패"
            
    def des_encrypt(self, plaintext):
        key_input = self.key_input.text.encode('utf-8')
        key = key_input if key_input else DES_DEFAULT_KEY
        
        if len(key) != 8:
            return "DES 키는 정확히 8바이트여야 합니다."
        cipher = DES.new(key, DES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), 8))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return f"{iv}:{ct}"

    def des_decrypt(self, ciphertext):
        try:
            key_input = self.key_input.text.encode('utf-8')
            key = key_input if key_input else DES_DEFAULT_KEY
            
            if len(key) != 8:
                return "DES 키는 정확히 8바이트여야 합니다."
            iv_b64, ct_b64 = ciphertext.split(":")
            iv = base64.b64decode(iv_b64)
            ct = base64.b64decode(ct_b64)
            cipher = DES.new(key, DES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), 8).decode('utf-8')
            return pt
        except Exception:
            return "복호화 실패"
        
    def rsa_encrypt(self, plaintext):
        try:
            if not hasattr(self, 'rsa_key'):
                self.rsa_key = RSA.generate(2048)  

            if self.rsa_pubkey_input.text.strip():
                pub_key = RSA.import_key(self.rsa_pubkey_input.text.strip().encode('utf-8'))
            else:
                pub_key = self.rsa_key.publickey()  

            cipher = PKCS1_OAEP.new(pub_key)
            encrypted = cipher.encrypt(plaintext.encode('utf-8'))
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            return f"암호화 실패: {str(e)}"

    def rsa_decrypt(self, ciphertext):
        try:
            if not hasattr(self, 'rsa_key'):
                self.rsa_key = RSA.generate(2048)

            if self.rsa_privkey_input.text.strip():
                priv_key = RSA.import_key(self.rsa_privkey_input.text.strip().encode('utf-8'))
            else:
                priv_key = self.rsa_key

            cipher = PKCS1_OAEP.new(priv_key)
            decrypted = cipher.decrypt(base64.b64decode(ciphertext))
            return decrypted.decode('utf-8')
        except Exception as e:
            return f"복호화 실패: {str(e)}"

    def hash_text_sha256(self, text):
        return hashlib.sha256(text.encode('utf-8')).hexdigest()
    
    def on_group_select(self, spinner, text):
        self.algo_spinner.values = self.algorithm_groups[text]
        self.algo_spinner.text = self.algorithm_groups[text][0]

    def on_algo_select(self, spinner, text):
        key_needed_algos = ['AES', 'DES']
        rsa_needed_algos = ['RSA']

        if text in key_needed_algos:
            self.key_input_layout.opacity = 1
            self.key_input_layout.disabled = False
            self.key_input_layout.height = dp(50)

            self.rsa_key_line.opacity = 0
            self.rsa_key_line.disabled = True
            self.rsa_key_line.height = 0

        elif text in rsa_needed_algos:
            self.key_input_layout.opacity = 0
            self.key_input_layout.disabled = True
            self.key_input_layout.height = 0

            self.rsa_key_line.opacity = 1
            self.rsa_key_line.disabled = False
            self.rsa_key_line.height = dp(50)

        else:
           
            self.key_input_layout.opacity = 0
            self.key_input_layout.disabled = True
            self.key_input_layout.height = 0

            self.rsa_key_line.opacity = 0
            self.rsa_key_line.disabled = True
            self.rsa_key_line.height = 0





class LottoApp(App):
    def build(self):
        self.sm = ScreenManager()
        self.sm.add_widget(MainScreen(name='main'))
        self.title = "SecretDecoder"  
        return self.sm

    def switch_to_screen(self, screen_name):
        if not self.sm.has_screen(screen_name):
            if screen_name == 'encry':
                self.sm.add_widget(CipherApp(name='encry'))
        self.sm.current = screen_name


if __name__ == '__main__':
    LottoApp().run()
