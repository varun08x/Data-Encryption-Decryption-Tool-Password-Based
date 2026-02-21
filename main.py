import os
import base64
import streamlit as st
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken


# ================= KEY DERIVATION =================
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,          # AES-256
        salt=salt,
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


# ================= ENCRYPT =================
def encrypt_text(password: str, text: str) -> str:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    encrypted = fernet.encrypt(text.encode())
    combined = salt + encrypted

    return base64.urlsafe_b64encode(combined).decode()


# ================= DECRYPT =================
def decrypt_text(password: str, encrypted_b64: str) -> str:
    combined = base64.urlsafe_b64decode(encrypted_b64.encode())

    salt = combined[:16]
    encrypted = combined[16:]

    key = derive_key(password, salt)
    fernet = Fernet(key)

    return fernet.decrypt(encrypted).decode()


# ================= STREAMLIT UI =================
st.set_page_config("AES Encryption Tool", "🔐")

page = st.sidebar.radio("Select Page", ["Encryption", "Decryption"])


# ================= ENCRYPTION PAGE =================
if page == "Encryption":
    st.title("🔐 Encryption")

    password = st.text_input("Enter password", type="password", key="enc_pass")
    text = st.text_area("Enter text to encrypt", key="enc_text")

    if st.button("Encrypt"):
        if not password or not text:
            st.warning("Please enter both password and text")
        else:
            try:
                encrypted = encrypt_text(password, text)
                st.success("Encrypted Text")
                st.text_area(
                    "Copy encrypted text",
                    encrypted,
                    height=150
                )
            except Exception as e:
                st.error(f"Encryption failed: {e}")


# ================= DECRYPTION PAGE =================
else:
    st.title("🔓 Decryption")

    encrypted_text = st.text_area(
        "Paste encrypted text (Base64)",
        key="dec_data"
    )

    password = st.text_input(
        "Enter password",
        type="password",
        key="dec_pass"
    )

    if st.button("Decrypt"):
        if not encrypted_text or not password:
            st.warning("Please enter encrypted text and password")
        else:
            try:
                decrypted = decrypt_text(password, encrypted_text)
                st.success("Decrypted Text")
                st.text_area(
                    "Decrypted Output",
                    decrypted,
                    height=150
                )
            except InvalidToken:
                st.error("❌ Wrong password or corrupted data")
            except Exception as e:
                st.error(f"Decryption failed: {e}")
