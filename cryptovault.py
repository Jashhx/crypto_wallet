import os
import json
import hashlib
import time
import base64
import logging
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict

import tkinter as tk
from tkinter import ttk, messagebox
import webbrowser

from dotenv import load_dotenv

# Cryptography imports
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import stripe

# Load .env from the script's directory
script_dir = os.path.dirname(os.path.abspath(__file__))
dotenv_path = os.path.join(script_dir, '.env')
load_dotenv(dotenv_path)

stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
STRIPE_PUBLIC_KEY = os.getenv('STRIPE_PUBLIC_KEY')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

KEYSTORE_BASE = r"C:\Users\asus\Downloads\wallet\keystore"


# ============================================================================
# CERTIFICATE AUTHORITY
# ============================================================================

class CertificateAuthority:
    """Certificate Authority for issuing and validating certificates"""
    
    def __init__(self, ca_name="CryptoWallet CA"):
        self.ca_name = ca_name
        self.ca_private_key = None
        self.ca_certificate = None
        self.issued_certificates = {}
        self.ca_path = os.path.join(KEYSTORE_BASE, "ca")
        self._initialize_ca()
    
    def _initialize_ca(self):
        os.makedirs(self.ca_path, exist_ok=True)
        ca_key_file = os.path.join(self.ca_path, 'ca_private_key.pem')
        ca_cert_file = os.path.join(self.ca_path, 'ca_certificate.pem')
        
        if os.path.exists(ca_key_file) and os.path.exists(ca_cert_file):
            self._load_ca()
        else:
            self._create_ca()
    
    def _create_ca(self):
        logger.info("Creating new Certificate Authority")
        
        self.ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptoWallet"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name),
        ])
        
        self.ca_certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.ca_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).sign(self.ca_private_key, hashes.SHA256(), default_backend())
        
        self._save_ca()
        logger.info("Certificate Authority created successfully")
    
    def _save_ca(self):
        ca_key_file = os.path.join(self.ca_path, 'ca_private_key.pem')
        with open(ca_key_file, 'wb') as f:
            f.write(self.ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        ca_cert_file = os.path.join(self.ca_path, 'ca_certificate.pem')
        with open(ca_cert_file, 'wb') as f:
            f.write(self.ca_certificate.public_bytes(serialization.Encoding.PEM))
    
    def _load_ca(self):
        logger.info("Loading existing Certificate Authority")
        
        ca_key_file = os.path.join(self.ca_path, 'ca_private_key.pem')
        with open(ca_key_file, 'rb') as f:
            self.ca_private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        
        ca_cert_file = os.path.join(self.ca_path, 'ca_certificate.pem')
        with open(ca_cert_file, 'rb') as f:
            self.ca_certificate = x509.load_pem_x509_certificate(
                f.read(), default_backend()
            )
    
    def issue_certificate(self, wallet_id, public_key, validity_days=365):
        logger.info(f"Issuing certificate for wallet: {wallet_id}")
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptoWallet"),
            x509.NameAttribute(NameOID.COMMON_NAME, wallet_id),
        ])
        
        issuer = self.ca_certificate.subject
        
        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(f"{wallet_id}.cryptowallet.local")
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).sign(self.ca_private_key, hashes.SHA256(), default_backend())
        
        cert_info = {
            'wallet_id': wallet_id,
            'serial_number': str(certificate.serial_number),
            'issued_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(days=validity_days)).isoformat(),
            'issuer': self.ca_name,
            'subject': wallet_id,
            'fingerprint': certificate.fingerprint(hashes.SHA256()).hex(),
            'certificate_pem': certificate.public_bytes(serialization.Encoding.PEM).decode()
        }
        
        self.issued_certificates[wallet_id] = cert_info
        return cert_info


# ============================================================================
# CRYPTO WALLET CORE (WITH SQLITE DATABASE)
# ============================================================================

class CryptoWallet:
    """Core cryptocurrency wallet with PKI, AES encryption, and SQLite ledger"""
    
    DB_PATH = os.path.join(KEYSTORE_BASE, "wallet.db")
    
    def __init__(self, wallet_id, password, certificate_authority):
        self.wallet_id = wallet_id
        self.password = password
        self.ca = certificate_authority
        self.keystore_path = os.path.join(KEYSTORE_BASE, wallet_id)
        self.private_key = None
        self.public_key = None
        self.certificate = None
    
    @staticmethod
    def _get_conn():
        conn = sqlite3.connect(CryptoWallet.DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_id TEXT UNIQUE NOT NULL,
                type TEXT NOT NULL,
                from_addr TEXT,
                to_addr TEXT NOT NULL,
                amount REAL NOT NULL,
                timestamp TEXT NOT NULL,
                nonce TEXT,
                signature TEXT,
                status TEXT NOT NULL
            )
        """)
        conn.commit()
        return conn
    
    @staticmethod
    def append_to_ledger(tx: Dict):
        conn = CryptoWallet._get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO transactions 
            (tx_id, type, from_addr, to_addr, amount, timestamp, nonce, signature, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            tx['transaction_id'],
            tx['type'],
            tx.get('from_addr'),
            tx['to_addr'],
            tx['amount'],
            tx['timestamp'],
            tx.get('nonce'),
            tx.get('signature'),
            tx['status']
        ))
        conn.commit()
        conn.close()
    
    def initialize(self):
        logger.info(f"Initializing wallet: {self.wallet_id}")
        
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        self.certificate = self.ca.issue_certificate(self.wallet_id, self.public_key)
        
        os.makedirs(self.keystore_path, exist_ok=True)
        
        self._save_encrypted_keys()
        
        logger.info(f"Wallet initialized: {self.wallet_id}")
    
    def load_wallet(self):
        logger.info(f"Loading wallet: {self.wallet_id}")
        
        key_file = os.path.join(self.keystore_path, 'private_key.enc')
        if not os.path.exists(key_file):
            raise ValueError("Wallet not found")
        
        with open(key_file, 'r') as f:
            encrypted_key = f.read()
        
        decrypted_key = self._decrypt_data(encrypted_key, self.password)
        self.private_key = serialization.load_pem_private_key(
            decrypted_key, password=None, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        cert_file = os.path.join(self.keystore_path, 'certificate.json')
        with open(cert_file, 'r') as f:
            self.certificate = json.load(f)
        
        logger.info(f"Wallet loaded: {self.wallet_id}")
    
    def _derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def _encrypt_data(self, data, password):
        salt = os.urandom(16)
        iv = os.urandom(12)
        key = self._derive_key(password, salt)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        encrypted = salt + iv + encryptor.tag + ciphertext
        return base64.b64encode(encrypted).decode()
    
    def _decrypt_data(self, encrypted_data, password):
        encrypted = base64.b64decode(encrypted_data.encode())
        
        salt = encrypted[:16]
        iv = encrypted[16:28]
        tag = encrypted[28:44]
        ciphertext = encrypted[44:]
        
        key = self._derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def _save_encrypted_keys(self):
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        encrypted_key = self._encrypt_data(private_pem, self.password)
        
        key_file = os.path.join(self.keystore_path, 'private_key.enc')
        with open(key_file, 'w') as f:
            f.write(encrypted_key)
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_key_file = os.path.join(self.keystore_path, 'public_key.pem')
        with open(pub_key_file, 'wb') as f:
            f.write(public_pem)
        
        cert_file = os.path.join(self.keystore_path, 'certificate.json')
        with open(cert_file, 'w') as f:
            json.dump(self.certificate, f, indent=2)
    
    def get_address(self):
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        address_hash = hashlib.sha256(public_pem).hexdigest()
        return f"0x{address_hash[:40]}"
    
    def get_balance(self):
        my_address = self.get_address()
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                COALESCE(SUM(CASE WHEN to_addr = ? THEN amount ELSE 0 END), 0) AS incoming,
                COALESCE(SUM(CASE WHEN from_addr = ? AND type = 'send' THEN amount ELSE 0 END), 0) AS outgoing
            FROM transactions
            WHERE status = 'completed'
        """, (my_address, my_address))
        row = cursor.fetchone()
        incoming, outgoing = row if row else (0.0, 0.0)
        conn.close()
        return incoming - outgoing
    
    def deposit(self, amount):
        if amount <= 0:
            raise ValueError("Amount must be positive")
        
        transaction = {
            'transaction_id': self._generate_transaction_id(),
            'type': 'deposit',
            'from_addr': None,
            'to_addr': self.get_address(),
            'amount': amount,
            'timestamp': datetime.now().isoformat(),
            'nonce': None,
            'signature': None,
            'status': 'completed'
        }
        
        self.append_to_ledger(transaction)
        
        logger.info(f"Deposited {amount} to wallet {self.wallet_id}")
        return transaction
    
    def create_transaction(self, recipient, amount, password):
        if password != self.password:
            raise ValueError("Invalid password")
        
        if amount <= 0:
            raise ValueError("Amount must be positive")
        
        if self.get_balance() < amount:
            raise ValueError("Insufficient balance")
        
        transaction_data = {
            'transaction_id': self._generate_transaction_id(),
            'type': 'send',
            'from_addr': self.get_address(),
            'to_addr': recipient,
            'amount': amount,
            'timestamp': datetime.now().isoformat(),
            'nonce': os.urandom(16).hex(),
            'status': 'completed'
        }
        
        message = json.dumps({
            k: v for k, v in transaction_data.items() 
            if k not in ['signature', 'status']
        }, sort_keys=True).encode()
        
        signature = self.private_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        
        transaction_data['signature'] = base64.b64encode(signature).decode()
        
        self.append_to_ledger(transaction_data)
        
        logger.info(f"Transaction created: {transaction_data['transaction_id']}")
        return transaction_data
    
    def get_transaction_history(self):
        my_address = self.get_address()
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM transactions
            WHERE (to_addr = ? OR from_addr = ?)
            AND status = 'completed'
            ORDER BY timestamp DESC
        """, (my_address, my_address))
        
        cols = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()
        history = []
        for row in rows:
            tx = dict(zip(cols, row))
            if tx['type'] == 'send':
                if tx['from_addr'] == my_address:
                    tx['display_type'] = 'send'
                    tx['counterparty'] = tx['to_addr']
                else:
                    tx['display_type'] = 'receive'
                    tx['counterparty'] = tx['from_addr']
            elif tx['type'] == 'deposit':
                tx['display_type'] = 'deposit'
                tx['counterparty'] = 'External'
            history.append(tx)
        
        conn.close()
        return history
    
    def _generate_transaction_id(self):
        data = f"{self.wallet_id}{time.time()}{os.urandom(8).hex()}"
        return hashlib.sha256(data.encode()).hexdigest()


# ============================================================================
# GUI APPLICATION (unchanged except balance refresh)
# ============================================================================

class CryptoWalletGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CryptoVault - Secure Digital Wallet")
        self.root.geometry("1200x800")
        self.root.configure(bg="#0a0e27")
        
        # Check Stripe keys
        if not stripe.api_key or not STRIPE_PUBLIC_KEY:
            messagebox.showerror("Configuration Error", "Stripe API keys not found. Please check your .env file.")
            root.destroy()
            return
        
        self.ca = CertificateAuthority()
        self.wallet = None
        
        self.colors = {
            'bg_primary': '#0a0e27',
            'bg_secondary': '#141b3d',
            'bg_card': '#1a2147',
            'accent_cyan': '#00ffff',
            'accent_purple': '#b600ff',
            'text_primary': '#ffffff',
            'text_secondary': '#a0a0c0',
            'success': '#00ff88',
            'danger': '#ff0066',
            'warning': '#ffaa00'
        }
        
        self.configure_styles()
        self.show_welcome_screen()
    
    def configure_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('Card.TFrame', background=self.colors['bg_card'])
        style.configure('Main.TFrame', background=self.colors['bg_primary'])
        style.configure('Secondary.TFrame', background=self.colors['bg_secondary'])
        
        style.configure('Title.TLabel', 
                       background=self.colors['bg_primary'],
                       foreground=self.colors['accent_cyan'],
                       font=('Arial', 24, 'bold'))
        
        style.configure('Heading.TLabel',
                       background=self.colors['bg_card'],
                       foreground=self.colors['accent_cyan'],
                       font=('Arial', 16, 'bold'))
        
        style.configure('Normal.TLabel',
                       background=self.colors['bg_card'],
                       foreground=self.colors['text_primary'],
                       font=('Arial', 10))
        
        style.configure('Secondary.TLabel',
                       background=self.colors['bg_card'],
                       foreground=self.colors['text_secondary'],
                       font=('Arial', 9))
    
    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def show_welcome_screen(self):
        self.clear_window()
        
        container = ttk.Frame(self.root, style='Main.TFrame')
        container.pack(fill='both', expand=True)
        
        welcome_frame = ttk.Frame(container, style='Card.TFrame', padding=50)
        welcome_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        title = ttk.Label(welcome_frame, 
                         text="🔐 CRYPTOVAULT",
                         style='Title.TLabel')
        title.pack(pady=(0, 10))
        
        subtitle = ttk.Label(welcome_frame,
                            text="Secure Digital Wallet",
                            style='Secondary.TLabel')
        subtitle.pack(pady=(0, 40))
        
        desc = ttk.Label(welcome_frame,
                        text="Create a secure wallet or access your existing one.\nYour keys, your crypto, your control.",
                        style='Normal.TLabel',
                        justify='center')
        desc.pack(pady=(0, 40))
        
        btn_frame = ttk.Frame(welcome_frame, style='Card.TFrame')
        btn_frame.pack()
        
        create_btn = tk.Button(btn_frame,
                              text="✨ Create New Wallet",
                              command=self.show_create_wallet,
                              bg=self.colors['accent_cyan'],
                              fg='#000000',
                              font=('Arial', 12, 'bold'),
                              padx=30,
                              pady=15,
                              border=0,
                              cursor='hand2')
        create_btn.pack(side='left', padx=10)
        
        access_btn = tk.Button(btn_frame,
                              text="🔓 Access Wallet",
                              command=self.show_access_wallet,
                              bg=self.colors['bg_secondary'],
                              fg=self.colors['text_primary'],
                              font=('Arial', 12, 'bold'),
                              padx=30,
                              pady=15,
                              border=0,
                              cursor='hand2')
        access_btn.pack(side='left', padx=10)
    
    def show_create_wallet(self):
        self.clear_window()
        
        container = ttk.Frame(self.root, style='Main.TFrame')
        container.pack(fill='both', expand=True)
        
        form_frame = ttk.Frame(container, style='Card.TFrame', padding=40)
        form_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        ttk.Label(form_frame, text="Create New Wallet", style='Heading.TLabel').pack(pady=(0, 30))
        
        ttk.Label(form_frame, text="Wallet ID:", style='Normal.TLabel').pack(anchor='w', pady=(10, 5))
        wallet_id_entry = tk.Entry(form_frame, 
                                   bg=self.colors['bg_secondary'],
                                   fg=self.colors['text_primary'],
                                   font=('Arial', 11),
                                   width=40,
                                   insertbackground=self.colors['text_primary'])
        wallet_id_entry.pack(pady=(0, 15))
        
        ttk.Label(form_frame, text="Password:", style='Normal.TLabel').pack(anchor='w', pady=(10, 5))
        password_entry = tk.Entry(form_frame,
                                 bg=self.colors['bg_secondary'],
                                 fg=self.colors['text_primary'],
                                 font=('Arial', 11),
                                 width=40,
                                 show='●',
                                 insertbackground=self.colors['text_primary'])
        password_entry.pack(pady=(0, 15))
        
        ttk.Label(form_frame, text="Confirm Password:", style='Normal.TLabel').pack(anchor='w', pady=(10, 5))
        confirm_entry = tk.Entry(form_frame,
                                bg=self.colors['bg_secondary'],
                                fg=self.colors['text_primary'],
                                font=('Arial', 11),
                                width=40,
                                show='●',
                                insertbackground=self.colors['text_primary'])
        confirm_entry.pack(pady=(0, 30))
        
        btn_frame = ttk.Frame(form_frame, style='Card.TFrame')
        btn_frame.pack()
        
        def create():
            wallet_id = wallet_id_entry.get().strip()
            password = password_entry.get()
            confirm = confirm_entry.get()
            
            if not wallet_id or not password:
                messagebox.showerror("Error", "Please fill in all fields")
                return
            
            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match")
                return
            
            if len(password) < 8 or not any(c.isdigit() for c in password) or not any(c.isalpha() for c in password):
                messagebox.showerror("Error", "Password must be at least 8 characters long and contain at least one letter and one digit")
                return
            
            try:
                self.wallet = CryptoWallet(wallet_id, password, self.ca)
                self.wallet.initialize()
                messagebox.showinfo("Success", "Wallet created successfully! 🎉")
                self.show_dashboard()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create wallet: {str(e)}")
        
        create_btn = tk.Button(btn_frame,
                             text="✨ Create Wallet",
                             command=create,
                             bg=self.colors['accent_cyan'],
                             fg='#000000',
                             font=('Arial', 11, 'bold'),
                             padx=20,
                             pady=10,
                             border=0,
                             cursor='hand2')
        create_btn.pack(side='left', padx=5)
        
        back_btn = tk.Button(btn_frame,
                           text="← Back",
                           command=self.show_welcome_screen,
                           bg=self.colors['bg_secondary'],
                           fg=self.colors['text_primary'],
                           font=('Arial', 11),
                           padx=20,
                           pady=10,
                           border=0,
                           cursor='hand2')
        back_btn.pack(side='left', padx=5)
    
    def show_access_wallet(self):
        self.clear_window()
        
        container = ttk.Frame(self.root, style='Main.TFrame')
        container.pack(fill='both', expand=True)
        
        form_frame = ttk.Frame(container, style='Card.TFrame', padding=40)
        form_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        ttk.Label(form_frame, text="Access Wallet", style='Heading.TLabel').pack(pady=(0, 30))
        
        ttk.Label(form_frame, text="Wallet ID:", style='Normal.TLabel').pack(anchor='w', pady=(10, 5))
        wallet_id_entry = tk.Entry(form_frame,
                                   bg=self.colors['bg_secondary'],
                                   fg=self.colors['text_primary'],
                                   font=('Arial', 11),
                                   width=40,
                                   insertbackground=self.colors['text_primary'])
        wallet_id_entry.pack(pady=(0, 15))
        
        ttk.Label(form_frame, text="Password:", style='Normal.TLabel').pack(anchor='w', pady=(10, 5))
        password_entry = tk.Entry(form_frame,
                                 bg=self.colors['bg_secondary'],
                                 fg=self.colors['text_primary'],
                                 font=('Arial', 11),
                                 width=40,
                                 show='●',
                                 insertbackground=self.colors['text_primary'])
        password_entry.pack(pady=(0, 30))
        
        btn_frame = ttk.Frame(form_frame, style='Card.TFrame')
        btn_frame.pack()
        
        def access():
            wallet_id = wallet_id_entry.get().strip()
            password = password_entry.get()
            
            if not wallet_id or not password:
                messagebox.showerror("Error", "Please fill in all fields")
                return
            
            try:
                self.wallet = CryptoWallet(wallet_id, password, self.ca)
                self.wallet.load_wallet()
                messagebox.showinfo("Success", "Welcome back! 👋")
                self.show_dashboard()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to access wallet: {str(e)}")
        
        access_btn = tk.Button(btn_frame,
                             text="🔓 Access Wallet",
                             command=access,
                             bg=self.colors['accent_cyan'],
                             fg='#000000',
                             font=('Arial', 11, 'bold'),
                             padx=20,
                             pady=10,
                             border=0,
                             cursor='hand2')
        access_btn.pack(side='left', padx=5)
        
        back_btn = tk.Button(btn_frame,
                           text="← Back",
                           command=self.show_welcome_screen,
                           bg=self.colors['bg_secondary'],
                           fg=self.colors['text_primary'],
                           font=('Arial', 11),
                           padx=20,
                           pady=10,
                           border=0,
                           cursor='hand2')
        back_btn.pack(side='left', padx=5)
    
    def show_dashboard(self):
        self.clear_window()
        
        main_container = ttk.Frame(self.root, style='Main.TFrame')
        main_container.pack(fill='both', expand=True, padx=20, pady=20)
        
        header = ttk.Frame(main_container, style='Main.TFrame')
        header.pack(fill='x', pady=(0, 20))
        
        ttk.Label(header, text="🔐 CRYPTOVAULT", style='Title.TLabel').pack(side='left')
        
        logout_btn = tk.Button(header,
                              text="🚪 Logout",
                              command=self.logout,
                              bg=self.colors['danger'],
                              fg='#ffffff',
                              font=('Arial', 10, 'bold'),
                              padx=15,
                              pady=8,
                              border=0,
                              cursor='hand2')
        logout_btn.pack(side='right')
        
        content = ttk.Frame(main_container, style='Main.TFrame')
        content.pack(fill='both', expand=True)
        
        sidebar = ttk.Frame(content, style='Card.TFrame', padding=20)
        sidebar.pack(side='left', fill='y', padx=(0, 20))
        
        ttk.Label(sidebar, text="💎 My Wallet", style='Heading.TLabel').pack(pady=(0, 10))
        
        wallet_id_label = ttk.Label(sidebar,
                                    text=f"ID: {self.wallet.wallet_id}",
                                    style='Normal.TLabel')
        wallet_id_label.pack(pady=5)
        
        address = self.wallet.get_address()
        address_label = ttk.Label(sidebar,
                                 text=f"Address: {address[:10]}...{address[-8:]}",
                                 style='Secondary.TLabel')
        address_label.pack(pady=5)
        
        balance_frame = ttk.Frame(sidebar, style='Card.TFrame')
        balance_frame.pack(pady=20, fill='x')
        
        ttk.Label(balance_frame, text="BALANCE", style='Secondary.TLabel').pack()
        
        self.balance_label = tk.Label(balance_frame,
                                      text=f"{self.wallet.get_balance():.2f}",
                                      bg=self.colors['bg_card'],
                                      fg=self.colors['accent_cyan'],
                                      font=('Arial', 32, 'bold'))
        self.balance_label.pack()
        
        ttk.Label(balance_frame, text="CRYPTO", style='Secondary.TLabel').pack()
        
        ttk.Label(sidebar, text="", style='Normal.TLabel').pack(pady=10)
        
        self.create_nav_button(sidebar, "📊 Dashboard", self.show_dashboard_tab)
        self.create_nav_button(sidebar, "💸 Send", self.show_send_tab)
        self.create_nav_button(sidebar, "📥 Receive", self.show_receive_tab)
        self.create_nav_button(sidebar, "📜 Transactions", self.show_transactions_tab)
        self.create_nav_button(sidebar, "➕ Deposit", self.show_deposit_dialog)
        
        self.main_content = ttk.Frame(content, style='Card.TFrame', padding=20)
        self.main_content.pack(side='left', fill='both', expand=True)
        
        self.show_dashboard_tab()
    
    def create_nav_button(self, parent, text, command):
        btn = tk.Button(parent,
                       text=text,
                       command=command,
                       bg=self.colors['bg_secondary'],
                       fg=self.colors['text_primary'],
                       font=('Arial', 11),
                       padx=20,
                       pady=12,
                       border=0,
                       cursor='hand2',
                       anchor='w',
                       width=20)
        btn.pack(pady=5, fill='x')
        
        btn.bind('<Enter>', lambda e: btn.config(bg=self.colors['accent_cyan'], fg='#000000'))
        btn.bind('<Leave>', lambda e: btn.config(bg=self.colors['bg_secondary'], fg=self.colors['text_primary']))
        
        return btn
    
    def clear_main_content(self):
        for widget in self.main_content.winfo_children():
            widget.destroy()
    
    def refresh_balance(self):
        self.balance_label.config(text=f"{self.wallet.get_balance():.2f}")
    
    def show_dashboard_tab(self):
        self.clear_main_content()
        
        ttk.Label(self.main_content, text="Dashboard", style='Heading.TLabel').pack(anchor='w', pady=(0, 20))
        
        transactions = self.wallet.get_transaction_history()
        
        total_sent = sum(tx['amount'] for tx in transactions if tx.get('display_type') == 'send')
        total_received = sum(tx['amount'] for tx in transactions if tx.get('display_type') in ('receive', 'deposit'))
        
        stats_frame = ttk.Frame(self.main_content, style='Card.TFrame')
        stats_frame.pack(fill='x', pady=(0, 20))
        
        self.create_stat_card(stats_frame, "Total Sent", f"{total_sent:.2f}", 0, 0)
        self.create_stat_card(stats_frame, "Total Received", f"{total_received:.2f}", 0, 1)
        self.create_stat_card(stats_frame, "Transactions", str(len(transactions)), 0, 2)
        
        ttk.Label(self.main_content, text="Recent Activity", style='Heading.TLabel').pack(anchor='w', pady=(20, 10))
        
        tx_frame = ttk.Frame(self.main_content, style='Card.TFrame')
        tx_frame.pack(fill='both', expand=True)
        
        recent = transactions[:5]
        if recent:
            for tx in recent:
                self.create_transaction_item(tx_frame, tx)
        else:
            ttk.Label(tx_frame, text="No transactions yet", style='Secondary.TLabel').pack(pady=40)
        
        self.refresh_balance()
    
    def create_stat_card(self, parent, label, value, row, col):
        card = ttk.Frame(parent, style='Secondary.TFrame', padding=15)
        card.grid(row=row, column=col, padx=10, pady=10, sticky='nsew')
        parent.columnconfigure(col, weight=1)
        
        ttk.Label(card, text=label, style='Secondary.TLabel').pack()
        
        value_label = tk.Label(card,
                              text=value,
                              bg=self.colors['bg_secondary'],
                              fg=self.colors['accent_cyan'],
                              font=('Arial', 20, 'bold'))
        value_label.pack(pady=10)
    
    def create_transaction_item(self, parent, tx):
        item_frame = ttk.Frame(parent, style='Secondary.TFrame', padding=10)
        item_frame.pack(fill='x', pady=5)
        
        info_frame = ttk.Frame(item_frame, style='Secondary.TFrame')
        info_frame.pack(side='left', fill='x', expand=True)
        
        display_type = tx.get('display_type', 'unknown').upper()
        type_label = ttk.Label(info_frame, text=display_type, style='Secondary.TLabel')
        type_label.pack(anchor='w')
        
        counterparty = tx.get('counterparty', '')
        if counterparty and counterparty != 'External':
            direction = 'To' if tx['display_type'] == 'send' else 'From'
            detail_text = f"{direction}: {counterparty[:10]}...{counterparty[-8:]}"
        else:
            detail_text = "From: External" if tx.get('display_type') == 'deposit' else ""
        
        if detail_text:
            detail_label = ttk.Label(info_frame, text=detail_text, style='Secondary.TLabel')
            detail_label.pack(anchor='w')
        
        if 'tx_id' in tx:
            id_text = tx['tx_id'][:16] + '...'
            id_label = ttk.Label(info_frame, text=f"ID: {id_text}", style='Normal.TLabel')
            id_label.pack(anchor='w')
        
        time_label = ttk.Label(info_frame,
                              text=datetime.fromisoformat(tx['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
                              style='Secondary.TLabel')
        time_label.pack(anchor='w')
        
        is_outgoing = tx['display_type'] == 'send'
        amount_text = f"-{tx['amount']:.2f}" if is_outgoing else f"+{tx['amount']:.2f}"
        amount_color = self.colors['danger'] if is_outgoing else self.colors['success']
        
        amount_label = tk.Label(item_frame,
                               text=amount_text,
                               bg=self.colors['bg_secondary'],
                               fg=amount_color,
                               font=('Arial', 16, 'bold'))
        amount_label.pack(side='right')
    
    def show_send_tab(self):
        self.clear_main_content()
        
        ttk.Label(self.main_content, text="Send Crypto", style='Heading.TLabel').pack(anchor='w', pady=(0, 20))
        
        form_frame = ttk.Frame(self.main_content, style='Card.TFrame')
        form_frame.pack(fill='x')
        
        ttk.Label(form_frame, text="Recipient Address:", style='Normal.TLabel').pack(anchor='w', pady=(10, 5))
        recipient_entry = tk.Entry(form_frame,
                                   bg=self.colors['bg_secondary'],
                                   fg=self.colors['text_primary'],
                                   font=('Arial', 11),
                                   insertbackground=self.colors['text_primary'])
        recipient_entry.pack(fill='x', pady=(0, 15))
        
        ttk.Label(form_frame, text="Amount:", style='Normal.TLabel').pack(anchor='w', pady=(10, 5))
        amount_entry = tk.Entry(form_frame,
                               bg=self.colors['bg_secondary'],
                               fg=self.colors['text_primary'],
                               font=('Arial', 11),
                               insertbackground=self.colors['text_primary'])
        amount_entry.pack(fill='x', pady=(0, 15))
        
        ttk.Label(form_frame, text="Password:", style='Normal.TLabel').pack(anchor='w', pady=(10, 5))
        password_entry = tk.Entry(form_frame,
                                 bg=self.colors['bg_secondary'],
                                 fg=self.colors['text_primary'],
                                 font=('Arial', 11),
                                 show='●',
                                 insertbackground=self.colors['text_primary'])
        password_entry.pack(fill='x', pady=(0, 20))
        
        def send():
            try:
                recipient = recipient_entry.get().strip()
                amount = float(amount_entry.get().strip())
                password = password_entry.get()
                
                if not recipient or not password:
                    messagebox.showerror("Error", "Please fill in all fields")
                    return
                
                tx = self.wallet.create_transaction(recipient, amount, password)
                self.refresh_balance()
                messagebox.showinfo("Success", f"Transaction sent successfully! 🚀\nID: {tx['transaction_id'][:16]}...")
                
                recipient_entry.delete(0, tk.END)
                amount_entry.delete(0, tk.END)
                password_entry.delete(0, tk.END)
                
                self.show_dashboard_tab()
                
            except ValueError as e:
                messagebox.showerror("Error", str(e))
            except Exception as e:
                messagebox.showerror("Error", f"Transaction failed: {str(e)}")
        
        send_btn = tk.Button(form_frame,
                           text="🚀 Send Transaction",
                           command=send,
                           bg=self.colors['accent_cyan'],
                           fg='#000000',
                           font=('Arial', 12, 'bold'),
                           padx=20,
                           pady=12,
                           border=0,
                           cursor='hand2')
        send_btn.pack()
    
    def show_receive_tab(self):
        self.clear_main_content()
        
        ttk.Label(self.main_content, text="Receive Crypto", style='Heading.TLabel').pack(anchor='w', pady=(0, 20))
        
        info_frame = ttk.Frame(self.main_content, style='Card.TFrame')
        info_frame.pack(fill='both', expand=True)
        
        ttk.Label(info_frame,
                 text="Share your wallet address to receive crypto",
                 style='Normal.TLabel').pack(pady=20)
        
        address = self.wallet.get_address()
        
        address_frame = ttk.Frame(info_frame, style='Secondary.TFrame', padding=20)
        address_frame.pack(pady=20, fill='x')
        
        address_text = tk.Text(address_frame,
                              height=2,
                              bg=self.colors['bg_secondary'],
                              fg=self.colors['accent_cyan'],
                              font=('Courier', 11),
                              wrap='word',
                              borderwidth=0)
        address_text.pack(fill='x')
        address_text.insert('1.0', address)
        address_text.config(state='disabled')
        
        def copy_address():
            self.root.clipboard_clear()
            self.root.clipboard_append(address)
            messagebox.showinfo("Success", "Address copied to clipboard! 📋")
        
        copy_btn = tk.Button(info_frame,
                           text="📋 Copy Address",
                           command=copy_address,
                           bg=self.colors['accent_cyan'],
                           fg='#000000',
                           font=('Arial', 11, 'bold'),
                           padx=20,
                           pady=10,
                           border=0,
                           cursor='hand2')
        copy_btn.pack(pady=20)
    
    def show_transactions_tab(self):
        self.clear_main_content()
        
        ttk.Label(self.main_content, text="Transaction History", style='Heading.TLabel').pack(anchor='w', pady=(0, 20))
        
        canvas = tk.Canvas(self.main_content, bg=self.colors['bg_card'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.main_content, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, style='Card.TFrame')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        transactions = self.wallet.get_transaction_history()
        
        if transactions:
            for tx in transactions:
                self.create_transaction_item(scrollable_frame, tx)
        else:
            ttk.Label(scrollable_frame, text="No transactions yet", style='Secondary.TLabel').pack(pady=40)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def show_deposit_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Deposit Funds")
        dialog.geometry("400x250")
        dialog.configure(bg=self.colors['bg_card'])
        dialog.transient(self.root)
        dialog.grab_set()
        
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f'+{x}+{y}')
        
        frame = ttk.Frame(dialog, style='Card.TFrame', padding=30)
        frame.pack(fill='both', expand=True)
        
        ttk.Label(frame, text="Deposit Funds", style='Heading.TLabel').pack(pady=(0, 20))
        
        ttk.Label(frame, text="Amount:", style='Normal.TLabel').pack(anchor='w', pady=(10, 5))
        amount_entry = tk.Entry(frame,
                               bg=self.colors['bg_secondary'],
                               fg=self.colors['text_primary'],
                               font=('Arial', 11),
                               insertbackground=self.colors['text_primary'])
        amount_entry.pack(fill='x', pady=(0, 20))
        amount_entry.focus()
        
        def deposit():
            try:
                amount = float(amount_entry.get().strip())
                if amount <= 0:
                    messagebox.showerror("Error", "Amount must be positive")
                    return
                
                session = stripe.checkout.Session.create(
                    payment_method_types=['card'],
                    line_items=[{
                        'price_data': {
                            'currency': 'usd',
                            'product_data': {
                                'name': 'Deposit to CryptoVault',
                            },
                            'unit_amount': int(amount * 100),
                        },
                        'quantity': 1,
                    }],
                    mode='payment',
                    success_url='https://example.com/success',
                    cancel_url='https://example.com/cancel',
                )
                
                webbrowser.open(session.url)
                
                # Wait for user to confirm payment (since no webhook in local app)
                confirm = messagebox.askyesno("Payment Confirmation", "Did you complete the payment successfully?")
                if confirm:
                    self.wallet.deposit(amount)
                    self.refresh_balance()
                    messagebox.showinfo("Success", f"Deposited {amount:.2f} successfully! 💰")
                    dialog.destroy()
                    self.show_dashboard_tab()
                else:
                    messagebox.showinfo("Cancelled", "Deposit cancelled.")
                
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid amount")
            except Exception as e:
                messagebox.showerror("Error", f"Deposit failed: {str(e)}")
        
        deposit_btn = tk.Button(frame,
                              text="💰 Deposit",
                              command=deposit,
                              bg=self.colors['accent_cyan'],
                              fg='#000000',
                              font=('Arial', 11, 'bold'),
                              padx=20,
                              pady=10,
                              border=0,
                              cursor='hand2')
        deposit_btn.pack()
    
    def logout(self):
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            self.wallet = None
            self.show_welcome_screen()


# ============================================================================
# MAIN
# ============================================================================

def main():
    os.makedirs(KEYSTORE_BASE, exist_ok=True)
    
    root = tk.Tk()
    app = CryptoWalletGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()