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

# 📌 폰트 등록 (파일이 프로젝트 폴더에 있어야 함)
LabelBase.register(name='Font', fn_regular='NotoSansKR.ttf')

# AES 키는 고정 길이 (16, 24, 32바이트)
AES_KEY = b'mysecretaeskey12'  # 반드시 16, 24, 32바이트 중 하나!
AES_BLOCK_SIZE = 16

DES_KEY = b'8bytekey'   # 꼭 8바이트!
DES_BLOCK_SIZE = 8

AES_DEFAULT_KEY = b'myaesdefaultkey1'   # 16바이트
DES_DEFAULT_KEY = b'deskey88'            # 8바이트



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
        btn1 = Button(text='암호문', font_name='Font', font_size=sp(28),
                      size_hint_y=None, height=dp(80))
        btn2 = Button(text='메모장', font_name='Font', font_size=sp(28),
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
            '대칭키 암호화': ['AES', 'DES', 'ChaCha20'],
            '비대칭키 암호화': ['RSA'],
            '해시': ['SHA-256', 'MD5'],
            '고전 암호': ['Caesar', 'Reverse'],
            '인코딩': ['Base64', 'ASCII', 'Unicode']
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
        elif algo == 'Reverse':
            result = plain[::-1]  # 문자열 뒤집기
        elif algo == 'DES':
            result = self.des_encrypt(plain)
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
        elif algo == 'ChaCha20':
            result = self.chacha20_encrypt(plain)
            
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
                result = cipher[::-1]  # 뒤집으면 복호화
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

            elif algo == 'MD5':
                result = "해시는 복호화가 불가능합니다."
            elif algo == 'ChaCha20':
                result = self.chacha20_decrypt(cipher)
                
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
        import hashlib
        return hashlib.md5(text.encode('utf-8')).hexdigest()

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
    
    def on_group_select(self, spinner, text):
        self.algo_spinner.values = self.algorithm_groups[text]
        self.algo_spinner.text = self.algorithm_groups[text][0]

    def on_algo_select(self, spinner, text):
        key_needed_algos = ['AES', 'DES', 'ChaCha20']
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

        layout = BoxLayout(orientation='vertical', padding=dp(20), spacing=dp(10))

        # 제목 입력창 + 새 메모 버튼 수평 배치
        title_layout = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(10))

        self.title_input = TextInput(
            hint_text='메모 제목 입력...없으면 날짜 저장',
            multiline=False,
            font_name='Font',
            size_hint_x=0.7,
            font_size=16
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

        # 메모 입력창
        self.memo_input = TextInput(
            hint_text='메모를 입력하세요...',
            multiline=True,
            size_hint_y=0.7,
            font_size=18,
            font_name='Font'
        )
        layout.add_widget(self.memo_input)

        # 버튼들
        btn_layout = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))

        save_btn = Button(text='저장', font_name='Font')
        load_btn = Button(text='불러오기', font_name='Font')
        delete_btn = Button(text='삭제', font_name='Font')

        save_btn.bind(on_press=self.save_memo)
        load_btn.bind(on_press=self.load_memo)
        delete_btn.bind(on_press=self.delete_memo)

        btn_layout.add_widget(save_btn)
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
        return [f for f in os.listdir(self.memo_dir) if f.endswith('.txt')]

    def save_memo(self, instance):
        if not self.current_filename:
            self.status_label.text = '저장 실패: 메모 파일이 선택되지 않았습니다.'
            return
        filepath = os.path.join(self.memo_dir, self.current_filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(self.memo_input.text)
        self.status_label.text = f'저장됨: {self.current_filename}'

    def load_memo(self, instance):
        if not self.current_filename:
            self.status_label.text = '불러오기 실패: 메모를 선택해주세요.'
            return
        filepath = os.path.join(self.memo_dir, self.current_filename)
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                self.memo_input.text = f.read()
            self.status_label.text = f'불러옴: {self.current_filename}'
        else:
            self.status_label.text = '파일이 존재하지 않습니다.'

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
        self.current_filename = filename

        # 빈 텍스트로 시작
        self.memo_input.text = ''
        
        # 파일 새로 만들기 (빈 상태로)
        filepath = os.path.join(self.memo_dir, self.current_filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('')

        # 스피너에 값 추가하고 선택 상태로 만들기
        self.memo_spinner.values = self.get_memo_list()
        self.memo_spinner.text = filename

        self.status_label.text = f'새 메모 생성: {filename}'

    def select_memo(self, spinner, text):
        self.current_filename = text
        self.load_memo(None)


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


if __name__ == '__main__':
    LottoApp().run()
