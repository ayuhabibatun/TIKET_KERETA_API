import streamlit as st
import json
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Load public key dari file
with open("public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())

# Kunci AES yang sama
AES_KEY = hashlib.sha256("kunciAESsederhana".encode()).digest()

def unpad(text):
    pad_len = ord(text[-1])
    return text[:-pad_len]

def decrypt_aes(encrypted_data):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decoded_data = base64.b64decode(encrypted_data)
    decrypted = cipher.decrypt(decoded_data).decode()
    return unpad(decrypted)

def verify_signature(data_str, signature_b64):
    hash_obj = SHA256.new(data_str.encode())
    signature = base64.b64decode(signature_b64)
    try:
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False

# Fungsi utama untuk halaman Streamlit
def halaman_dekripsi():
    st.title("🔐 Dekripsi dan Verifikasi Bukti")

    pilihan = st.radio("Pilih Jenis Bukti yang Ingin Didekripsi", ["Bukti Pembatalan", "Tiket Pemesanan"])

    uploaded_file = st.file_uploader("Unggah File Bukti", type=["txt"])
    if uploaded_file:
        content = uploaded_file.read().decode()
        parts = content.split("Signature:\n")
        if len(parts) != 2:
            st.error("Format file tidak sesuai. Pastikan ada bagian 'Signature:' di akhir file.")
            return

        encrypted_data = parts[0].split("Encrypted Data:\n")[-1].split("Log Encrypted:\n")[-1].strip()
        signature = parts[1].strip()

        try:
            decrypted_json_str = decrypt_aes(encrypted_data)
            data_dict = json.loads(decrypted_json_str)
            st.success("✅ Data berhasil didekripsi")
            st.json(data_dict)
        except Exception as e:
            st.error(f"❌ Gagal dekripsi: {e}")
            return

        # Verifikasi tanda tangan digital
        valid = verify_signature(decrypted_json_str, signature)
        if valid:
            st.success("🔏 Signature VALID – Data asli & belum dimodifikasi.")
        else:
            st.error("❌ Signature TIDAK VALID – Data mungkin telah dimodifikasi.")
