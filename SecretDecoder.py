from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.core.text import LabelBase
import random
from kivy.graphics import Color, Rectangle #배경색
from kivy.clock import Clock
from kivy.uix.textinput import TextInput
from kivy.uix.spinner import Spinner
import base64
from kivy.core.clipboard import Clipboard #복사
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
from kivy.utils import platform #쓰기 가능한 앱전용 폴더
from kivy.metrics import dp, sp
from kivy.uix.spinner import SpinnerOption
from kivy.uix.image import Image

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

# 앱 시작 시 키 생성 (또는 저장된 키 로드)
# WARNING: 키는 안전하게 보관 필요
#key = Fernet.generate_key()
#cipher = Fernet(key)




# 📌 폰트 등록 (파일이 프로젝트 폴더에 있어야 함)
LabelBase.register(name='Font', fn_regular='NotoSansKR.ttf')

# AES 키는 고정 길이 (16, 24, 32바이트)
AES_KEY = b'mysecretaeskey12'  # 반드시 16, 24, 32바이트 중 하나!
AES_BLOCK_SIZE = 16

DES_KEY = b'8bytekey'   # 꼭 8바이트!
DES_BLOCK_SIZE = 8

AES_DEFAULT_KEY = b'myaesdefaultkey1'   # 16바이트
DES_DEFAULT_KEY = b'deskey88'            # 8바이트

BLOWFISH_BLOCK_SIZE = Blowfish.block_size  # 일반적으로 8바이트
TDES_BLOCK_SIZE = DES3.block_size  # 일반적으로 8바이트




class MainScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        layout = BoxLayout(
            orientation='vertical',
            padding=dp(20),
            spacing=dp(15)
        )

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

        # 버튼들
        btn1 = Button(text='암호화 도구', font_name='Font', font_size=sp(28),
                      size_hint_y=None, height=dp(80))
        btn2 = Button(text='보안 메모장', font_name='Font', font_size=sp(28),
                      size_hint_y=None, height=dp(80))


        btn1.bind(on_press=lambda x: App.get_running_app().switch_to_screen('encry'))
        btn2.bind(on_press=lambda x: App.get_running_app().switch_to_screen('memo'))


        layout.add_widget(btn1)
        layout.add_widget(btn2)

        self.add_widget(layout)




# 드롭다운에 한글폰트 적용된 옵션
class KoreanSpinnerOption(SpinnerOption):
    font_name = 'Font'  # ✅ 네가 등록한 한글 폰트
    font_size = sp(20)


class CipherApp(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self.algorithm_groups = {
            '대칭키 암호화': ['ChaCha20', 'AES', 'Blowfish', '3DES', 'DES' ],
            '비대칭키 암호화': ['RSA'],
            '해시': ['BLAKE2', 'SHA-512', 'SHA-256', 'SHA-1', 'MD5'],
            '고전 암호': ['Caesar', 'Reverse','Vigenere'],
            '인코딩': ['ASCII', 'Hex', 'Unicode', 'Base64', 'URL']
        }
        self.rsa_key = RSA.generate(2048)

        layout = BoxLayout(orientation='vertical', padding=dp(20), spacing=dp(10))

        # ✅ 스피너 레이아웃
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

        # ✅ 키 입력창
        self.key_input_layout = BoxLayout(orientation='vertical', size_hint_y=None, height=0)
        self.key_input = TextInput(
            hint_text="암호 키 입력 (키 없으면 자동 기본키)",
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
        
        # ✅ RSA 키 입력 레이아웃
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

        # ✅ 평문 입력창
        self.plain_input = TextInput(
            hint_text="여기에 평문 입력",
            font_name='Font',
            font_size=sp(20),
            multiline=True        # 여러 줄 입력 가능

        )
        layout.add_widget(self.plain_input)

        # ✅ 암호화 버튼
        self.encrypt_button = Button(
            text="암호화",
            font_name='Font',
            font_size=sp(22),
            size_hint=(1, None),
            height=dp(50)
        )
        self.encrypt_button.bind(on_press=self.encrypt_text)
        layout.add_widget(self.encrypt_button)

        # ✅ 암호문 출력
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

        # ✅ 복호화 입력
        self.cipher_input = TextInput(
            hint_text="여기에 암호문 입력",
            font_name='Font',
            font_size=sp(20),
            multiline=True        # 여러 줄 입력 가능
        )
        layout.add_widget(self.cipher_input)

        # ✅ 복호화 버튼
        self.decrypt_button = Button(
            text="복호화",
            font_name='Font',
            font_size=sp(22),
            size_hint=(1, None),
            height=dp(50)
        )
        self.decrypt_button.bind(on_press=self.decrypt_text)
        layout.add_widget(self.decrypt_button)

        # ✅ 복호화 결과 출력
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

        # ✅ 뒤로가기 버튼
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
        return ''.join(chr((ord(char) + shift) % 1114112) for char in text)  # 전체 유니코드 범위

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
            result = plain[::-1]  # 문자열 뒤집기
        elif algo == 'DES':
            result = self.des_encrypt(plain)
        elif algo == '3DES':
            result = self.triple_des_encrypt(plain)
        elif algo == 'RSA':
            result = self.rsa_encrypt(plain)
        elif algo == 'SHA-256':
            result = self.hash_text_sha256(plain)

        elif algo == 'ASCII':
            result = ' '.join(str(ord(c)) for c in plain)  # ex: "A" → "65"

        elif algo == 'Unicode':
            result = ' '.join(f'U+{ord(c):04X}' for c in plain)  # ex: "가" → "U+AC00"

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
                result = cipher[::-1]  # 뒤집으면 복호화
            elif algo == 'DES':
                result = self.des_decrypt(cipher)
            elif algo == 'RSA':
                result = self.rsa_decrypt(cipher)
            elif algo in ('SHA-1', 'SHA-256', 'SHA-512', 'BLAKE2', 'MD5'):
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

            elif algo == 'ChaCha20':
                result = self.chacha20_decrypt(cipher)
            elif algo == 'Vigenere':
                keyword = self.key_input.text.strip() or "KEY"
                result = self.vigenere_decrypt(cipher, keyword)
                            
            else:
                result = "지원되지 않는 알고리즘입니다."
            
            self.decrypted_output.text = f"평문: {result}"
        except Exception:
            self.decrypted_output.text = "복호화 오류: 형식을 확인하세요."

    def copy_to_clipboard(self, instance):
        text = self.encrypted_output.text.replace("암호문: ", "")
        Clipboard.copy(text)
        #self.encrypted_output.text = "복사 완료! "

    def copy_decrypted_text(self, instance):
        text = self.decrypted_output.text.replace("평문: ", "")
        Clipboard.copy(text)
        #self.decrypted_output.text = "복사 완료! "

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
                self.rsa_key = RSA.generate(2048)  # ❗ rsa_key가 없으면 새로 생성

            if self.rsa_pubkey_input.text.strip():
                pub_key = RSA.import_key(self.rsa_pubkey_input.text.strip().encode('utf-8'))
            else:
                pub_key = self.rsa_key.publickey()  # 기본 키 사용

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
            # 입력된 키가 있으면 base64 디코딩
            if key_input_str:
                key = base64.b64decode(key_input_str)
                include_key = False  # 키 포함하지 않음
            else:
                key = get_random_bytes(32)
                include_key = True  # 키 포함
        except Exception:
            return "키 형식이 잘못되었습니다. Base64로 인코딩된 문자열을 입력하세요."

        if len(key) != 32:
            return "ChaCha20 키는 정확히 32바이트여야 합니다."

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
                    return "ChaCha20 키는 정확히 32바이트여야 합니다."
                ciphertext = raw[12:]
            else:
                key = raw[12:44]
                ciphertext = raw[44:]

            cipher = ChaCha20.new(key=key, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext).decode('utf-8')
            return plaintext
        except Exception:
            return "복호화 실패"
        
    def blowfish_encrypt(self, plaintext):
        key_input_text = self.key_input.text.strip()
        key = key_input_text.encode('utf-8') if key_input_text else b'mydefaultkey123'  # 16바이트 정도 추천

        if not (4 <= len(key) <= 56):
            return "Blowfish 키는 4~56바이트여야 합니다."

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
                return "Blowfish 키는 4~56바이트여야 합니다."

            iv_b64, ct_b64 = ciphertext.split(":")
            iv = base64.b64decode(iv_b64)
            ct = base64.b64decode(ct_b64)
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), BLOWFISH_BLOCK_SIZE).decode('utf-8')
            return pt
        except Exception:
            return "복호화 실패"

    def triple_des_encrypt(self, plaintext):
        key_input_text = self.key_input.text.strip()
        key = key_input_text.encode('utf-8') if key_input_text else b'default3deskey1234567890'  # 16 또는 24 바이트

        # 3DES 키는 반드시 16 또는 24 바이트
        if len(key) not in [16, 24]:
            return "3DES 키는 16 또는 24바이트여야 합니다."

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
                return "3DES 키는 16 또는 24바이트여야 합니다."

            iv_b64, ct_b64 = ciphertext.split(":")
            iv = base64.b64decode(iv_b64)
            ct = base64.b64decode(ct_b64)
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), TDES_BLOCK_SIZE).decode('utf-8')
            return pt
        except Exception:
            return "복호화 실패"

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
            # 둘 다 숨기기
            self.key_input_layout.opacity = 0
            self.key_input_layout.disabled = True
            self.key_input_layout.height = 0

            self.rsa_key_line.opacity = 0
            self.rsa_key_line.disabled = True
            self.rsa_key_line.height = 0

class MemoScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        Window.softinput_mode = 'resize'

        # 저장 경로 설정
        try:
            from android.storage import app_storage_path
            memo_base_path = app_storage_path()
        except ImportError:
            memo_base_path = os.path.join(os.path.expanduser("~"), 'AppData', 'Roaming', 'lotto')

        self.memo_dir = os.path.join(memo_base_path, 'memos')
        os.makedirs(self.memo_dir, exist_ok=True)

        # 🔑 키 로딩 또는 생성
        self.key_path = os.path.join(self.memo_dir, 'secret.key')
        self.cipher = self.load_or_create_key()

        layout = BoxLayout(orientation='vertical', padding=dp(20), spacing=dp(10))

        # 제목 입력창 + 새 메모 버튼 수평 배치
        title_layout = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(10))

        self.title_input = TextInput(
            hint_text='제목 (생략 시 날짜)',
            multiline=False,
            font_name='Font',
            size_hint_x=0.7,
            font_size=sp(20)
        )
        new_btn = Button(text='새 메모', size_hint_x=0.3,  font_name='Font')
        new_btn.bind(on_press=self.new_memo)

        title_layout.add_widget(self.title_input)
        title_layout.add_widget(new_btn)

        layout.add_widget(title_layout)

        # 메모 선택 스피너
        self.memo_spinner = Spinner(
            text='메모 선택',
            values=[],
            size_hint_y=None,
            height=dp(40),
            font_name='Font',
            option_cls=KoreanSpinnerOption
        )
        self.memo_spinner.bind(text=self.select_memo)
        layout.add_widget(self.memo_spinner)

        # 메모 입력창을 ScrollView로 감싸기
        # ✅ ScrollView 설정
        self.memo_scroll = ScrollView(
            size_hint_y=0.7,
            do_scroll_x=False,
            do_scroll_y=True
        )


        # ScrollView 안에 감쌀 BoxLayout 생성
        self.memo_container = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            padding=(dp(10), dp(10)),
            spacing=dp(10)
        )
        self.memo_container.bind(minimum_height=self.memo_container.setter('height'))
            
        # ✅ TextInput 설정
        self.memo_input = TextInput(
            hint_text='내용을 입력해 주세요',
            multiline=True,
            font_size=sp(22),
            font_name='Font',
            size_hint_y=None,
            height=dp(400),  # ← 메모장처럼 넉넉한 높이
            padding =  [dp(10), dp(10), dp(10), dp(10)],
            background_normal='',
            background_active=''
        )
        
        # ✅ 스크롤 공간 확보용 더미 Label
        self.bottom_spacer = Label(size_hint_y=None, height=dp(50))  # ← 여백을 넉넉하게

        # 초기 상태 고정
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

                # 커서 윈도우 좌표
                _, cursor_y = ti.to_window(*ti.cursor_pos)

                # ScrollView 위치 계산
                sv_y = sv.to_window(sv.x, sv.y)[1]
                sv_top = sv_y + sv.height
                sv_bottom = sv_y

                # 커서가 너무 위나 아래에 있으면 스크롤
                margin = dp(50)
                if cursor_y < sv_bottom + margin or cursor_y > sv_top - margin:
                    # 커서 기준으로 직접 스크롤 위치 조정
                    sv.scroll_to(ti, padding=dp(200))  # 이건 TextInput 전체 기준이므로 필요 시 보정 가능

            except Exception as e:
                print("스크롤 체크 실패:", e)

        # 바인딩 함수: 줄어드는 건 무시하고, 늘어나는 경우만 반영
        def lock_maximum_height(instance, value):
            current = instance.minimum_height
            fixed = getattr(instance, 'fixed_height', 0)
            if current > fixed + 1:  # 1px 이상 커졌을 때만 변경
                instance.fixed_height = current
                instance.height = current
            else:
                instance.height = fixed

        # 바인딩 설정
        self.memo_input.bind(text=lock_maximum_height)

        
        # ✅ 유지: 포커스될 때만 스크롤 확인
        self.memo_input.bind(
            focus=lambda instance, value: scroll_if_cursor_hidden() if value else None
        )
        
        def on_enter_scroll(instance, value):
            if value and value[-1:] == '\n':  # 마지막 문자가 엔터일 때

                # 높이 자동 확장 처리
                current = instance.minimum_height
                if current > getattr(instance, 'fixed_height', 0):
                    instance.fixed_height = current
                    instance.height = current
                else:
                    instance.height = instance.fixed_height

                # 스크롤 커서 위치 보정
                Clock.schedule_once(lambda dt: scroll_if_cursor_hidden(), 0.05)

                # 첫 줄 잘림 방지용 scroll_y 조정
                Clock.schedule_once(lambda dt: setattr(self.memo_input, 'scroll_y', 1.05), 0.1)

        self.memo_input.bind(text=on_enter_scroll)


        # 버튼들
        btn_layout = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))

        save_btn = Button(text='저장', font_name='Font')
        plain_load_btn = Button(text='원문보기', font_name='Font')
        load_btn = Button(text='불러오기', font_name='Font')
        plain_load_btn.bind(on_press=self.load_plain_memo)
        delete_btn = Button(text='삭제', font_name='Font')

        save_btn.bind(on_press=self.save_memo)
        load_btn.bind(on_press=self.load_memo)
        delete_btn.bind(on_press=self.delete_memo)

        btn_layout.add_widget(save_btn)
        btn_layout.add_widget(plain_load_btn)
        btn_layout.add_widget(load_btn)
        
        btn_layout.add_widget(delete_btn)

        layout.add_widget(btn_layout)

        # 상태 메시지 라벨
        self.status_label = Label(text='', size_hint_y=None, height=dp(30), font_name='Font')
        layout.add_widget(self.status_label)

        
        # ✅ 뒤로가기 버튼
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

        # 저장 폴더 경로 (안드로이드 대응)
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
            self.status_label.text = '저장 실패: 메모 파일이 선택되지 않았습니다.'
            return
        filepath = os.path.join(self.memo_dir, self.current_filename)

        encrypted = self.cipher.encrypt(self.memo_input.text.encode('utf-8'))
        with open(filepath, 'wb') as f:
            f.write(encrypted)

        self.status_label.text = f'암호화 저장됨: {self.current_filename}'

    def load_memo(self, instance):
        if not self.current_filename:
            self.status_label.text = '불러오기 실패: 메모를 선택해주세요.'
            return
        filepath = os.path.join(self.memo_dir, self.current_filename)
        try:
            with open(filepath, 'rb') as f:
                encrypted = f.read()
                decrypted = self.cipher.decrypt(encrypted).decode('utf-8')  # ← 수정됨
                self.memo_input.text = decrypted
                self.status_label.text = f'불러오기 (복호화 완료): {self.current_filename}'
        except Exception as e:
            self.status_label.text = f'불러오기 실패: {str(e)}'
            
    def load_plain_memo(self, instance):
        if not self.current_filename:
            self.status_label.text = '불러오기 실패: 메모를 선택해주세요.'
            return
        filepath = os.path.join(self.memo_dir, self.current_filename)
        try:
            with open(filepath, 'rb') as f:
                raw_data = f.read()
                self.memo_input.text = raw_data.decode('utf-8', errors='replace')  # 복호화 없이 표시
                self.status_label.text = f'불러오기 (암호화된 원본): {self.current_filename}'
        except Exception as e:
            self.status_label.text = f'불러오기 실패: {str(e)}'
        
    def delete_memo(self, instance):
        if not self.current_filename:
            self.status_label.text = '삭제 실패: 메모를 선택해주세요.'
            return

        # 확인 팝업 구성
        content = BoxLayout(orientation='vertical', padding=dp(20), spacing=dp(10))
        message = Label(text=f"'{self.current_filename}' 메모를 삭제하시겠습니까?", font_name='Font')
        btn_box = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(10))

        yes_btn = Button(text='삭제', font_name='Font')
        no_btn = Button(text='취소', font_name='Font')

        popup = Popup(title='delete',
                      content=content,
                      size_hint=(0.8, 0.4),
                      auto_dismiss=False)

        def confirm_delete(instance):
            filepath = os.path.join(self.memo_dir, self.current_filename)
            if os.path.exists(filepath):
                os.remove(filepath)
                self.status_label.text = f'삭제됨: {self.current_filename}'
                self.memo_input.text = ''
                self.title_input.text = ''
                self.current_filename = None
                self.memo_spinner.values = self.get_memo_list()
                self.memo_spinner.text = '메모 선택'
            else:
                self.status_label.text = '삭제 완료.'
            popup.dismiss()

        def cancel_delete(instance):
            self.status_label.text = '삭제 취소됨'
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
        self.status_label.text = f'새 메모 생성: {filename}'

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
        self.sm.add_widget(MainScreen(name='main'))
        self.title = "SecretDecoder"  # ← 앱 이름(제목 바꾸기)
        return self.sm

    def switch_to_screen(self, screen_name):
        if not self.sm.has_screen(screen_name):
            if screen_name == 'encry':
                self.sm.add_widget(CipherApp(name='encry'))
            elif screen_name == 'memo':
                self.sm.add_widget(MemoScreen(name='memo'))  # 메모 화면 등록
        self.sm.current = screen_name

    def on_back_button(self, window, key, *args):
        if key == 27:  # Android back key
            current = self.sm.current
            if current == 'main':  # 메인화면이면 앱 종료
                return False  # 기본 동작 허용 → 앱 종료
            else:
                self.sm.current = 'main'  # 메인화면으로 이동
                return True  # 기본 동작 막기
        return False



if __name__ == '__main__':
    LottoApp().run()
