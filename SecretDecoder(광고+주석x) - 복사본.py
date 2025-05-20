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

from kivy.core.text import LabelBase
from datetime import datetime
from kivy.core.window import Window
from kivy.uix.popup import Popup
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES3
from kivy.uix.scrollview import ScrollView
from cryptography.fernet import Fernet

from kivy.core.window import Window
import locale
from jnius import autoclass




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
    def __init__(self, lang='ko', **kwargs):
        super().__init__(**kwargs)

        self.lang = lang
        self.translations = {
            'en': {
                'btn1': 'Encryption Tool',
                'btn2': 'Secure Notepad',
            },
            'ko': {
                'btn1': '암호화 도구',
                'btn2': '보안 메모장',
            }
        }

        self.current_activity = cast('android.app.Activity', PythonActivity.mActivity)
        load_admob(self.current_activity)

        layout = BoxLayout(orientation='vertical', padding=dp(20), spacing=dp(15))

       
        top_image = Image(
            source='logo2.png', 
            size_hint=(1, 0.2),  
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



        btn1 = Button(
            text=self.translations[self.lang]['btn1'], 
            font_name='Font', font_size=sp(28),
            size_hint_y=None, height=dp(80)
        )
        btn2 = Button(
            text=self.translations[self.lang]['btn2'], 
            font_name='Font', font_size=sp(28),
            size_hint_y=None, height=dp(80)
        )


        
        btn1.bind(on_press=self.show_ad_and_switch1)
        btn2.bind(on_press=self.show_ad_and_switch2)


        layout.add_widget(btn1)
        layout.add_widget(btn2)

        self.add_widget(layout)

    def show_ad_and_switch1(self, instance):
        show_admob(self.current_activity)
        App.get_running_app().switch_to_screen('encry')

    def show_ad_and_switch2(self, instance):
        show_admob(self.current_activity)
        App.get_running_app().switch_to_screen('memo')





class KoreanSpinnerOption(SpinnerOption):
    font_name = 'Font'  
    font_size = sp(20)


class CipherApp(Screen):
    def __init__(self, lang='ko', **kwargs):
        super().__init__(**kwargs)

        self.lang = lang
        translations = {
            'en': {
                'text1': 'Select Encryption Type',
                'text2': 'Select Algorithm',
                'text3': 'Enter encryption key (default key if empty)',
                'text4': 'Public Key :',
                'text5': 'Private Key :',
                'text6': 'Enter plaintext here',
                'text7': 'Encrypt',
                'text8': 'Encrypted text will appear here',
                'text9': 'Copy',
                'text10': 'Enter ciphertext here',
                'text11': 'Decrypt',
                'text12': 'Decrypted plaintext will appear here',
                'text13': 'Copy',
                'text14': '← Back',
                'text15': 'Unsupported algorithm.',
                'text16': 'Hashes cannot be decrypted.',
                'text17': 'Plaintext',
                'text18': 'Decryption error: please check the format.',
                'text19': 'Decryption Failed',
                'text20': 'Encryption Failed',
                'text21': 'Ciphertext',
                'text22': 'Number format error: Must be numbers separated by spaces.',
                'text23': 'Format error: Must start with U+ followed by a Unicode value.',
                'text24': 'AES key must be 16, 24, or 32 bytes long.',
                'text25': 'DES key must be exactly 8 bytes long.',
                'text26': 'Invalid key format. Please enter a Base64-encoded string.',
                'text27': 'ChaCha20 key must be exactly 32 bytes long.',
                'text28': 'Blowfish key must be between 4 and 56 bytes.',
                'text29': '3DES key must be either 16 or 24 bytes long.',
                'text30': 'Symmetric Encryption',
            },
            'ko': {
                'text1': '암호화 종류 선택',
                'text2': '알고리즘 선택',
                'text3': '암호 키 입력 (키 없으면 자동 기본키)',
                'text4': '공개키 :',
                'text5': '개인키 :',
                'text6': '여기에 평문 입력',
                'text7': '암호화',
                'text8': '암호문이 여기에 표시됩니다',
                'text9': '복사',
                'text10': '여기에 암호문 입력',
                'text11': '복호화',
                'text12': '복호화된 평문이 여기에 표시됩니다',
                'text13': '복사',
                'text14': '← 뒤로가기',
                'text15': '지원되지 않는 알고리즘입니다.',
                'text16': '해시는 복호화가 불가능합니다.',
                'text17': '평문',
                'text18': '복호화 오류: 형식을 확인하세요.',
                'text19': '복호화 실패',
                'text20': '암호화 실패',
                'text21': '암호문',
                'text22': '숫자 형식 오류: 공백으로 구분된 숫자여야 합니다.',
                'text23': '형식 오류: U+로 시작하는 유니코드 값이어야 합니다.',
                'text24': 'AES 키는 16, 24 또는 32바이트여야 합니다.',
                'text25': 'DES 키는 정확히 8바이트여야 합니다.',
                'text26': '키 형식이 잘못되었습니다. Base64로 인코딩된 문자열을 입력하세요.',
                'text27': 'ChaCha20 키는 정확히 32바이트여야 합니다.',
                'text28': 'Blowfish 키는 4~56바이트여야 합니다.',
                'text29': '3DES 키는 16 또는 24바이트여야 합니다.',
                'text30': '대칭키 암호화',
                
            }
        }





        

        if self.lang == 'en':
            self.algorithm_groups = {
                'Symmetric Encryption': ['ChaCha20', 'AES', 'Blowfish', '3DES', 'DES'],
                'Asymmetric Encryption': ['RSA'],
                'Hash': ['BLAKE2', 'SHA-512', 'SHA-256', 'SHA-1', 'MD5'],
                'Classical Ciphers': ['Caesar', 'Reverse', 'Vigenere'],
                'Encoding': ['ASCII', 'Hex', 'Unicode', 'Base64', 'URL']
            }
        else:
            self.algorithm_groups = {
                '대칭키 암호화': ['ChaCha20', 'AES', 'Blowfish', '3DES', 'DES'],
                '비대칭키 암호화': ['RSA'],
                '해시': ['BLAKE2', 'SHA-512', 'SHA-256', 'SHA-1', 'MD5'],
                '고전 암호': ['Caesar', 'Reverse', 'Vigenere'],
                '인코딩': ['ASCII', 'Hex', 'Unicode', 'Base64', 'URL']
            }

        group_key = self.translations[self.lang]['text30']
            
        self.rsa_key = RSA.generate(2048)

        layout = BoxLayout(orientation='vertical', padding=dp(20), spacing=dp(10))

        
        spinner_layout = BoxLayout(orientation='horizontal', spacing=dp(10), size_hint_y=None, height=dp(50))

        self.group_spinner = Spinner(
            text=self.translations[self.lang]['text1'],
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
            text=self.translations[self.lang]['text2'],
            values=self.algorithm_groups[group_key],
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
            hint_text=self.translations[self.lang]['text3'],
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

        self.rsa_pubkey_label = Label(text=self.translations[self.lang]['text4'], font_name='Font', font_size=sp(18), size_hint=(0.15, 1))
        self.rsa_pubkey_input = TextInput(
            hint_text="-----BEGIN PUBLIC KEY----- ...",
            font_name='Font',
            font_size=sp(16),
            multiline=False,
            size_hint=(0.35, 1)
        )
        self.rsa_privkey_label = Label(text=self.translations[self.lang]['text5'], font_name='Font', font_size=sp(18), size_hint=(0.15, 1))
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
            hint_text=self.translations[self.lang]['text6'],
            font_name='Font',
            font_size=sp(20),
            multiline=True       

        )
        layout.add_widget(self.plain_input)

        
        self.encrypt_button = Button(
            text=self.translations[self.lang]['text7'],
            font_name='Font',
            font_size=sp(22),
            size_hint=(1, None),
            height=dp(50)
        )
        self.encrypt_button.bind(on_press=self.encrypt_text)
        layout.add_widget(self.encrypt_button)

        
        output_layout = BoxLayout(orientation='horizontal', spacing=dp(10), size_hint_y=None, height=dp(50))

        self.encrypted_output = Label(
            text=self.translations[self.lang]['text8'],
            font_name='Font',
            font_size=sp(18)
        )
        output_layout.add_widget(self.encrypted_output)

        self.copy_button = Button(
            text=self.translations[self.lang]['text9'],
            font_name='Font',
            font_size=sp(18),
            size_hint=(None, 1),
            width=dp(80)
        )
        self.copy_button.bind(on_press=self.copy_to_clipboard)
        output_layout.add_widget(self.copy_button)

        layout.add_widget(output_layout)

        
        self.cipher_input = TextInput(
            hint_text=self.translations[self.lang]['text10'],
            font_name='Font',
            font_size=sp(20),
            multiline=True        
        )
        layout.add_widget(self.cipher_input)

        
        self.decrypt_button = Button(
            text=self.translations[self.lang]['text11'],
            font_name='Font',
            font_size=sp(22),
            size_hint=(1, None),
            height=dp(50)
        )
        self.decrypt_button.bind(on_press=self.decrypt_text)
        layout.add_widget(self.decrypt_button)

        
        decrypt_output_layout = BoxLayout(orientation='horizontal', spacing=dp(10), size_hint_y=None, height=dp(50))

        self.decrypted_output = Label(
            text=self.translations[self.lang]['text12'],
            font_name='Font',
            font_size=sp(18)
        )
        decrypt_output_layout.add_widget(self.decrypted_output)

        self.copy_decrypted_button = Button(
            text=self.translations[self.lang]['text13'],
            font_name='Font',
            font_size=sp(18),
            size_hint=(None, 1),
            width=dp(80)
        )
        self.copy_decrypted_button.bind(on_press=self.copy_decrypted_text)
        decrypt_output_layout.add_widget(self.copy_decrypted_button)

        layout.add_widget(decrypt_output_layout)

        back_button = Button(
            text=self.translations[self.lang]['text14'],
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
        elif algo == 'Blowfish':
            result = self.blowfish_encrypt(plain)
        elif algo == 'Reverse':
            result = plain[::-1]
        elif algo == 'DES':
            result = self.des_encrypt(plain)
        elif algo == '3DES':
            result = self.triple_des_encrypt(plain)
        elif algo == 'RSA':
            result = self.rsa_encrypt(plain)
        elif algo == 'SHA-256':
            result = self.hash_text_sha256(plain)

        elif algo == 'ASCII':
            result = ' '.join(str(ord(c)) for c in plain) 

        elif algo == 'Unicode':
            result = ' '.join(f'U+{ord(c):04X}' for c in plain) 

        elif algo == 'MD5':
            result = self.hash_text_md5(plain)
        elif algo == "SHA-1":
            result = self.hash_text_sha1(plain)
        elif algo == "SHA-512":
            result = self.hash_text_sha512(plain)
        elif algo == "BLAKE2":
            result = self.hash_text_blake2(plain)
        elif algo == "Hex":
            result = self.encode_text_hex(plain)
        elif algo == "URL":
            result = self.encode_text_url(plain)
        
        elif algo == 'ChaCha20':
            result = self.chacha20_encrypt(plain)
        elif algo == 'Vigenere':
            keyword = self.key_input.text.strip() or "KEY"
            result = self.vigenere_encrypt(plain, keyword)
            
        else:
            result = self.translations[self.lang]['text15']
            
        self.encrypted_output.text = f"{self.translations[self.lang]['text21']}: {result}"

    def decrypt_text(self, instance):
        algo = self.algo_spinner.text
        cipher = self.cipher_input.text
        try:
            if algo == 'Caesar':
                result = self.caesar_decrypt(cipher)
            elif algo == 'Base64':
                result = base64.b64decode(cipher.encode('utf-8')).decode('utf-8')
            elif algo == "Hex":
                result = self.decode_text_hex(cipher)
            elif algo == "URL":
                result = self.decode_text_url(cipher)
            elif algo == 'AES':
                result = self.aes_decrypt(cipher)
            elif algo == '3DES':
                result = self.triple_des_decrypt(cipher)
            elif algo == 'Blowfish':
                result = self.blowfish_decrypt(cipher)
            elif algo == 'Reverse':
                result = cipher[::-1] 
            elif algo == 'DES':
                result = self.des_decrypt(cipher)
            elif algo == 'RSA':
                result = self.rsa_decrypt(cipher)
            elif algo in ('SHA-1', 'SHA-256', 'SHA-512', 'BLAKE2', 'MD5'):
                result = self.translations[self.lang]['text16']        
            elif algo == 'ASCII':
                try:
                    result = ''.join(chr(int(code)) for code in cipher.strip().split())
                except:
                    result = self.translations[self.lang]['text22']

            elif algo == 'Unicode':
                try:
                    result = ''.join(chr(int(code.replace("U+", ""), 16)) for code in cipher.strip().split())
                except:
                    result = self.translations[self.lang]['text23']

            elif algo == 'ChaCha20':
                result = self.chacha20_decrypt(cipher)
            elif algo == 'Vigenere':
                keyword = self.key_input.text.strip() or "KEY"
                result = self.vigenere_decrypt(cipher, keyword)
                            
            else:
                result = self.translations[self.lang]['text15']
            
            self.decrypted_output.text = f"{self.translations[self.lang]['text17']}: {result}"
        except Exception:
            self.decrypted_output.text = self.translations[self.lang]['text18']

    def copy_to_clipboard(self, instance):
        prefix = f"{self.translations[self.lang]['text21']}: "
        text = self.encrypted_output.text.replace(prefix, "")
        Clipboard.copy(text)

    def copy_decrypted_text(self, instance):
        prefix = f"{self.translations[self.lang]['text17']}: "
        text = self.decrypted_output.text.replace(prefix, "")
        Clipboard.copy(text)
        

    def aes_encrypt(self, plaintext):
        key_input_text = self.key_input.text.strip()
        key = key_input_text.encode('utf-8') if key_input_text else AES_DEFAULT_KEY

        if len(key) not in [16, 24, 32]:
            return self.translations[self.lang]['text24']

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
                return self.translations[self.lang]['text24']

            iv_b64, ct_b64 = ciphertext.split(":")
            iv = base64.b64decode(iv_b64)
            ct = base64.b64decode(ct_b64)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
            return pt
        except Exception:
            return self.translations[self.lang]['text19']
            
    def des_encrypt(self, plaintext):
        key_input = self.key_input.text.encode('utf-8')
        key = key_input if key_input else DES_DEFAULT_KEY
        
        if len(key) != 8:
            return self.translations[self.lang]['text25']
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
                return self.translations[self.lang]['text25']
            iv_b64, ct_b64 = ciphertext.split(":")
            iv = base64.b64decode(iv_b64)
            ct = base64.b64decode(ct_b64)
            cipher = DES.new(key, DES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), 8).decode('utf-8')
            return pt
        except Exception:
            return self.translations[self.lang]['text19']
        
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
            return f"{self.translations[self.lang]['text20']}: {str(e)}"

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
            return f"{self.translations[self.lang]['text19']}: {str(e)}"

    def hash_text_sha256(self, text):
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    def hash_text_md5(self, text):
        return hashlib.md5(text.encode('utf-8')).hexdigest()

    def hash_text_sha1(self, text):
        return hashlib.sha1(text.encode('utf-8')).hexdigest()

    def hash_text_sha512(self, text):
        return hashlib.sha512(text.encode('utf-8')).hexdigest()

    def hash_text_blake2(self, text):
        return hashlib.blake2b(text.encode('utf-8')).hexdigest()

    def encode_text_hex(self, text):
        return text.encode('utf-8').hex()

    def decode_text_hex(self, hex_text):
        return bytes.fromhex(hex_text).decode('utf-8')

    def encode_text_url(self, text):
        import urllib.parse
        return urllib.parse.quote(text)

    def decode_text_url(self, url_text):
        import urllib.parse
        return urllib.parse.unquote(url_text)

    def chacha20_encrypt(self, plaintext):
        key_input_str = self.key_input.text.strip()
    
        try:
            
            if key_input_str:
                key = base64.b64decode(key_input_str)
                include_key = False  
            else:
                key = get_random_bytes(32)
                include_key = True  
        except Exception:
            return self.translations[self.lang]['text26']

        if len(key) != 32:
            return self.translations[self.lang]['text27']

        nonce = get_random_bytes(12)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext.encode('utf-8'))

        if include_key:
            combined = nonce + key + ciphertext
        else:
            combined = nonce + ciphertext

        return base64.b64encode(combined).decode('utf-8')


    def chacha20_decrypt(self, encoded_ciphertext):
        try:
            raw = base64.b64decode(encoded_ciphertext)
            nonce = raw[:12]
            key_input_str = self.key_input.text.strip()

            if key_input_str:
                key = base64.b64decode(key_input_str)
                if len(key) != 32:
                    return self.translations[self.lang]['text27']
                ciphertext = raw[12:]
            else:
                key = raw[12:44]
                ciphertext = raw[44:]

            cipher = ChaCha20.new(key=key, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext).decode('utf-8')
            return plaintext
        except Exception:
            return self.translations[self.lang]['text19']
        
    def blowfish_encrypt(self, plaintext):
        key_input_text = self.key_input.text.strip()
        key = key_input_text.encode('utf-8') if key_input_text else b'mydefaultkey123'  

        if not (4 <= len(key) <= 56):
            return self.translations[self.lang]['text28']

        cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), BLOWFISH_BLOCK_SIZE))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return f"{iv}:{ct}"

    def blowfish_decrypt(self, ciphertext):
        try:
            key_input_text = self.key_input.text.strip()
            key = key_input_text.encode('utf-8') if key_input_text else b'mydefaultkey123'

            if not (4 <= len(key) <= 56):
                return self.translations[self.lang]['text28']

            iv_b64, ct_b64 = ciphertext.split(":")
            iv = base64.b64decode(iv_b64)
            ct = base64.b64decode(ct_b64)
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), BLOWFISH_BLOCK_SIZE).decode('utf-8')
            return pt
        except Exception:
            return self.translations[self.lang]['text19']

    def triple_des_encrypt(self, plaintext):
        key_input_text = self.key_input.text.strip()
        key = key_input_text.encode('utf-8') if key_input_text else b'default3deskey1234567890'  

        
        if len(key) not in [16, 24]:
            return self.translations[self.lang]['text29']

        cipher = DES3.new(key, DES3.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), TDES_BLOCK_SIZE))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        return f"{iv}:{ct}"

    def triple_des_decrypt(self, ciphertext):
        try:
            key_input_text = self.key_input.text.strip()
            key = key_input_text.encode('utf-8') if key_input_text else b'default3deskey1234567890'

            if len(key) not in [16, 24]:
                return self.translations[self.lang]['text29']

            iv_b64, ct_b64 = ciphertext.split(":")
            iv = base64.b64decode(iv_b64)
            ct = base64.b64decode(ct_b64)
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), TDES_BLOCK_SIZE).decode('utf-8')
            return pt
        except Exception:
            return self.translations[self.lang]['text19']

    def vigenere_encrypt(self, plaintext, keyword):
        result = ''
        keyword = keyword.lower()
        keyword_index = 0

        for char in plaintext:
            if char.isalpha():
                shift = ord(keyword[keyword_index % len(keyword)]) - ord('a')
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base + shift) % 26 + base)
                keyword_index += 1
            else:
                result += char
        return result

    def vigenere_decrypt(self, ciphertext, keyword):
        result = ''
        keyword = keyword.lower()
        keyword_index = 0

        for char in ciphertext:
            if char.isalpha():
                shift = ord(keyword[keyword_index % len(keyword)]) - ord('a')
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base - shift) % 26 + base)
                keyword_index += 1
            else:
                result += char
        return result

    
    def on_group_select(self, spinner, text):
        self.algo_spinner.values = self.algorithm_groups[text]
        self.algo_spinner.text = self.algorithm_groups[text][0]

    def on_algo_select(self, spinner, text):
        key_needed_algos = ['ChaCha20', 'AES', 'Blowfish', '3DES', 'DES','Vigenere']
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



class MemoScreen(Screen):
    def __init__(self, lang='ko', **kwargs):
        super().__init__(**kwargs)
        
        self.lang = lang
        self.translations = {
            'en': {
                'txt1': 'Title (if empty, current date will be used)',
                'txt2': 'New Memo',
                'txt3': 'Select Memo',
                'txt4': 'Please enter content',
                'txt5': 'Save',
                'txt6': 'View Original',
                'txt7': 'Load',
                'txt8': 'Delete',
                'txt9': '← Back',
                'txt10': 'Save failed: No memo file selected.',
                'txt11': 'Encrypted and saved:',
                'txt12': 'Load failed: Please select a memo.',
                'txt13': 'Loaded (Decryption successful):',
                'txt14': 'Load failed:',
                'txt15': 'Load failed: Please select a memo.',
                'txt16': 'Loaded (Encrypted original):',
                'txt17': 'Load failed:',
                'txt18': 'Delete failed: Please select a memo.',
                'txt19': 'Do you want to delete this memo?',
                'txt20': 'Cancel',
                'txt21': 'Deleted:',
                'txt22': 'Memo selected',
                'txt23': 'Delete complete.',
                'txt24': 'Delete cancelled',
                'txt25': 'New memo created:',
                'txt26': 'New Memo',
            },
            'ko': {
                'txt1': '제목 (생략 시 날짜)',
                'txt2': '새 메모',
                'txt3': '메모 선택',
                'txt4': '내용을 입력해 주세요',
                'txt5': '저장',
                'txt6': '원문보기',
                'txt7': '불러오기',
                'txt8': '삭제',
                'txt9': '← 뒤로가기',
                'txt10': '저장 실패: 메모 파일이 선택되지 않았습니다.',
                'txt11': '암호화 저장됨:',
                'txt12': '불러오기 실패: 메모를 선택해주세요.',
                'txt13': '불러오기 (복호화 완료):',
                'txt14': '불러오기 실패:',
                'txt15': '불러오기 실패: 메모를 선택해주세요.',
                'txt16': '불러오기 (암호화된 원본):',
                'txt17': '불러오기 실패:',
                'txt18': '삭제 실패: 메모를 선택해주세요.',
                'txt19': '메모를 삭제하시겠습니까?',
                'txt20': '취소',
                'txt21': '삭제됨:',
                'txt22': '메모 선택',
                'txt23': '삭제 완료.',
                'txt24': '삭제 취소됨',
                'txt25': '새 메모 생성:',
                'txt26': '새 메모',
            }
        }

        Window.softinput_mode = 'resize'

        try:
            from android.storage import app_storage_path
            memo_base_path = app_storage_path()
        except ImportError:
            memo_base_path = os.path.join(os.path.expanduser("~"), 'AppData', 'Roaming', 'lotto')

        self.memo_dir = os.path.join(memo_base_path, 'memos')
        os.makedirs(self.memo_dir, exist_ok=True)

        self.key_path = os.path.join(self.memo_dir, 'secret.key')
        self.cipher = self.load_or_create_key()

        layout = BoxLayout(orientation='vertical', padding=dp(20), spacing=dp(10))

        title_layout = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(10))

        self.title_input = TextInput(
            hint_text=self.translations[self.lang]['txt1'],
            multiline=False,
            font_name='Font',
            size_hint_x=0.7,
            font_size=sp(20)
        )
        new_btn = Button(text=self.translations[self.lang]['txt2'], size_hint_x=0.3,  font_name='Font')
        new_btn.bind(on_press=self.new_memo)

        title_layout.add_widget(self.title_input)
        title_layout.add_widget(new_btn)

        layout.add_widget(title_layout)

        self.memo_spinner = Spinner(
            text=self.translations[self.lang]['txt3'],
            values=[],
            size_hint_y=None,
            height=dp(40),
            font_name='Font',
            option_cls=KoreanSpinnerOption
        )
        self.memo_spinner.bind(text=self.select_memo)
        layout.add_widget(self.memo_spinner)


        self.memo_scroll = ScrollView(
            size_hint_y=0.7,
            do_scroll_x=False,
            do_scroll_y=True
        )


        self.memo_container = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            padding=(dp(10), dp(10)),
            spacing=dp(10)
        )
        self.memo_container.bind(minimum_height=self.memo_container.setter('height'))
            

        self.memo_input = TextInput(
            hint_text=self.translations[self.lang]['txt4'],
            multiline=True,
            font_size=sp(22),
            font_name='Font',
            size_hint_y=None,
            height=dp(400),  
            padding =  [dp(10), dp(10), dp(10), dp(10)],
            background_normal='',
            background_active=''
        )
        

        self.bottom_spacer = Label(size_hint_y=None, height=dp(50))

        self.memo_input.fixed_height = dp(400)
        self.memo_input.size_hint_y = None
        self.memo_input.height = self.memo_input.fixed_height
        

        self.memo_container.add_widget(self.memo_input)
        self.memo_container.add_widget(self.bottom_spacer)

        self.memo_scroll.add_widget(self.memo_container)
        
        layout.add_widget(self.memo_scroll)

        def scroll_if_cursor_hidden(*args):
            Clock.schedule_once(check_cursor_position, 0.1)

        self.just_focused = True

        def check_cursor_position(dt):
            if self.just_focused:
                self.just_focused = False
                return

            try:
                sv = self.memo_scroll
                ti = self.memo_input


                _, cursor_y = ti.to_window(*ti.cursor_pos)


                sv_y = sv.to_window(sv.x, sv.y)[1]
                sv_top = sv_y + sv.height
                sv_bottom = sv_y


                margin = dp(50)
                if cursor_y < sv_bottom + margin or cursor_y > sv_top - margin:
                    sv.scroll_to(ti, padding=dp(200))  

            except Exception as e:
                print("스크롤 체크 실패:", e)


        def lock_maximum_height(instance, value):
            current = instance.minimum_height
            fixed = getattr(instance, 'fixed_height', 0)
            if current > fixed + 1:  
                instance.fixed_height = current
                instance.height = current
            else:
                instance.height = fixed


        self.memo_input.bind(text=lock_maximum_height)


        self.memo_input.bind(
            focus=lambda instance, value: scroll_if_cursor_hidden() if value else None
        )
        
        def on_enter_scroll(instance, value):
            if value and value[-1:] == '\n':  

                
                current = instance.minimum_height
                if current > getattr(instance, 'fixed_height', 0):
                    instance.fixed_height = current
                    instance.height = current
                else:
                    instance.height = instance.fixed_height

                
                Clock.schedule_once(lambda dt: scroll_if_cursor_hidden(), 0.05)

                
                Clock.schedule_once(lambda dt: setattr(self.memo_input, 'scroll_y', 1.05), 0.1)

        self.memo_input.bind(text=on_enter_scroll)


        
        btn_layout = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))

        save_btn = Button(text=self.translations[self.lang]['txt5'], font_name='Font')
        plain_load_btn = Button(text=self.translations[self.lang]['txt6'], font_name='Font')
        load_btn = Button(text=self.translations[self.lang]['txt7'], font_name='Font')
        plain_load_btn.bind(on_press=self.load_plain_memo)
        delete_btn = Button(text=self.translations[self.lang]['txt8'], font_name='Font')

        save_btn.bind(on_press=self.save_memo)
        load_btn.bind(on_press=self.load_memo)
        delete_btn.bind(on_press=self.delete_memo)

        btn_layout.add_widget(save_btn)
        btn_layout.add_widget(plain_load_btn)
        btn_layout.add_widget(load_btn)
        
        btn_layout.add_widget(delete_btn)

        layout.add_widget(btn_layout)

        
        self.status_label = Label(text='', size_hint_y=None, height=dp(30), font_name='Font')
        layout.add_widget(self.status_label)

        
        
        back_button = Button(
            text=self.translations[self.lang]['txt9'],
            font_name='Font',
            font_size=sp(20),
            size_hint=(1, None),
            height=dp(50)
        )
        back_button.bind(on_press=lambda x: setattr(self.manager, 'current', 'main'))
        layout.add_widget(back_button)

        self.add_widget(layout)

        
        try:
            from android.storage import app_storage_path
            memo_base_path = app_storage_path()
        except ImportError:
            memo_base_path = os.path.join(os.path.expanduser("~"), 'AppData', 'Roaming', 'lotto')

        self.memo_dir = os.path.join(memo_base_path, 'memos')
        os.makedirs(self.memo_dir, exist_ok=True)

        self.current_filename = None
        self.memo_spinner.values = self.get_memo_list()


        

        
        
    def get_memo_list(self):
        return sorted([f for f in os.listdir(self.memo_dir) if f.endswith('.txt')])

    def save_memo(self, instance):
        if not self.current_filename:
            self.status_label.text = self.translations[self.lang]['txt10']
            return
        filepath = os.path.join(self.memo_dir, self.current_filename)

        encrypted = self.cipher.encrypt(self.memo_input.text.encode('utf-8'))
        with open(filepath, 'wb') as f:
            f.write(encrypted)

        self.status_label.text = f'{self.translations[self.lang]['txt11']} {self.current_filename}'

    def load_memo(self, instance):
        if not self.current_filename:
            self.status_label.text = self.translations[self.lang]['txt12']
            return
        filepath = os.path.join(self.memo_dir, self.current_filename)
        try:
            with open(filepath, 'rb') as f:
                encrypted = f.read()
                decrypted = self.cipher.decrypt(encrypted).decode('utf-8') 
                self.memo_input.text = decrypted
                self.status_label.text = f'{self.translations[self.lang]['txt13']} {self.current_filename}'
        except Exception as e:
            self.status_label.text = f'{self.translations[self.lang]['txt14']} {str(e)}'
            
    def load_plain_memo(self, instance):
        if not self.current_filename:
            self.status_label.text = self.translations[self.lang]['txt15']
            return
        filepath = os.path.join(self.memo_dir, self.current_filename)
        try:
            with open(filepath, 'rb') as f:
                raw_data = f.read()
                self.memo_input.text = raw_data.decode('utf-8', errors='replace') 
                self.status_label.text = f'{self.translations[self.lang]['txt16']} {self.current_filename}'
        except Exception as e:
            self.status_label.text = f'{self.translations[self.lang]['txt17']} {str(e)}'
        
    def delete_memo(self, instance):
        if not self.current_filename:
            self.status_label.text = self.translations[self.lang]['txt18']
            return

        
        content = BoxLayout(orientation='vertical', padding=dp(20), spacing=dp(10))
        message = Label(text=f"'{self.current_filename}' {self.translations[self.lang]['txt19']}", font_name='Font')
        btn_box = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(10))

        yes_btn = Button(text=self.translations[self.lang]['txt8'], font_name='Font')
        no_btn = Button(text=self.translations[self.lang]['txt20'], font_name='Font')

        popup = Popup(title='delete',
                      content=content,
                      size_hint=(0.8, 0.4),
                      auto_dismiss=False)

        def confirm_delete(instance):
            filepath = os.path.join(self.memo_dir, self.current_filename)
            if os.path.exists(filepath):
                os.remove(filepath)
                self.status_label.text = f'{self.translations[self.lang]['txt21']} {self.current_filename}'
                self.memo_input.text = ''
                self.title_input.text = ''
                self.current_filename = None
                self.memo_spinner.values = self.get_memo_list()
                self.memo_spinner.text = self.translations[self.lang]['txt22']
            else:
                self.status_label.text = self.translations[self.lang]['txt23']
            popup.dismiss()

        def cancel_delete(instance):
            self.status_label.text = self.translations[self.lang]['txt24']
            popup.dismiss()

        yes_btn.bind(on_press=confirm_delete)
        no_btn.bind(on_press=cancel_delete)

        btn_box.add_widget(yes_btn)
        btn_box.add_widget(no_btn)

        content.add_widget(message)
        content.add_widget(btn_box)

        popup.open()

    def new_memo(self, instance):
        title = self.title_input.text.strip()
        if not title:
            title = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'{title}.txt'
        filepath = os.path.join(self.memo_dir, filename)
        
        # 중복 파일명 방지
        counter = 1
        while os.path.exists(filepath):
            filename = f'{title}_{counter}.txt'
            filepath = os.path.join(self.memo_dir, filename)
            counter += 1

        self.current_filename = filename
        self.memo_input.text = ''
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('')

        self.memo_spinner.values = self.get_memo_list()
        self.memo_spinner.text = filename
        self.status_label.text = f'{self.translations[self.lang]['txt25']} {filename}'

    def select_memo(self, spinner, text):
        self.current_filename = text
        self.load_memo(None)

    def load_or_create_key(self):
        if os.path.exists(self.key_path):
            with open(self.key_path, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_path, 'wb') as f:
                f.write(key)
        return Fernet(key)





class LottoApp(App):
    def build(self):
        self.sm = ScreenManager()
        
        # OS 언어 감지 함수
        def detect_language():
            if platform == 'android':
                Locale = autoclass('java.util.Locale')
                language_code = Locale.getDefault().getLanguage()
                if language_code in ('ko', 'en'):
                    return language_code
                return 'en'
            else:
                import locale
                lang, _ = locale.getdefaultlocale()
                if lang:
                    code = lang.split('_')[0]
                    if code in ('en', 'ko'):
                        return code
                return 'en' 
        
        lang = detect_language()
        self.lang = lang  
        
        
        self.sm.add_widget(MainScreen(name='main', lang=lang))
        
        self.title = "SecretDecoder"

        if platform == 'android':
            Window.bind(on_keyboard=self.on_back_button)
            
        return self.sm

    def switch_to_screen(self, screen_name):
        if not self.sm.has_screen(screen_name):
            lang = self.lang  
            if screen_name == 'encry':
                self.sm.add_widget(CipherApp(name='encry', lang=lang))  
            elif screen_name == 'memo':
                self.sm.add_widget(MemoScreen(name='memo', lang=lang))  
        self.sm.current = screen_name
        
    def on_back_button(self, window, key, *args):
        if key == 27:  
            current = self.sm.current
            if current == 'main':  
                return False  
            else:
                self.sm.current = 'main'  
                return True  
        return False


if __name__ == '__main__':
    LottoApp().run()
