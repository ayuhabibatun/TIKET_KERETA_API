import streamlit as st
import json
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from datetime import datetime
import random
import string

from database import insert_ticket, get_user_by_username

# Key AES dan RSA statis untuk demo
AES_KEY = hashlib.sha256("kunciAESsederhana".encode()).digest()
from Crypto.PublicKey import RSA

with open("private.pem", "rb") as f:
    PRIVATE_KEY = RSA.import_key(f.read())

with open("public.pem", "rb") as f:
    PUBLIC_KEY = RSA.import_key(f.read())

# ✅ SIMPAN KUNCI PUBLIK KE FILE
with open("public.pem", "wb") as f:
    f.write(PUBLIC_KEY.export_key())

def pad(text):
    pad_len = 16 - (len(text) % 16)
    return text + chr(pad_len) * pad_len

def encrypt_aes(data_str):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded = pad(data_str)
    encrypted = cipher.encrypt(padded.encode())
    return base64.b64encode(encrypted).decode()

def sign_data_rsa(data_str):
    hash_obj = SHA256.new(data_str.encode())
    signature = pkcs1_15.new(PRIVATE_KEY).sign(hash_obj)
    return base64.b64encode(signature).decode()

def generate_kode_booking():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

def halaman_pemesanan():
    st.title("🚄 Pemesanan Tiket Kereta Api")

    if "username" not in st.session_state:
        st.warning("Silakan login terlebih dahulu.")
        return

    user = get_user_by_username(st.session_state["username"])
    if not user:
        st.error("User tidak ditemukan.")
        return

    with st.form("form_pemesanan"):
        nama = st.text_input("Nama Lengkap")
        nik = st.text_input("NIK")
        asal = st.text_input("Stasiun Asal")
        tujuan = st.text_input("Stasiun Tujuan")
        tanggal = st.date_input("Tanggal Berangkat")
        jam = st.time_input("Jam Berangkat")
        kelas = st.selectbox("Kelas", ["Ekonomi", "Bisnis", "Eksekutif"])
        submit = st.form_submit_button("Pesan Tiket")

    if submit:
        nama_kereta = random.choice(["Argo Bromo", "Taksaka", "Matarmaja", "Gajayana"])
        nomor_kereta = random.randint(100, 999)
        kode_booking = generate_kode_booking()

        data_tiket = {
            "nama": nama,
            "nik": nik,
            "asal": asal,
            "tujuan": tujuan,
            "tanggal": str(tanggal),
            "jam": str(jam),
            "kelas": kelas,
            "kereta": nama_kereta,
            "nomor_kereta": nomor_kereta,
            "kode_booking": kode_booking
        }

        # Format tampilan tiket
        tiket_kartu = f"""
+----------------------------------------+
|         TIKET KERETA API DIGITAL       |
+----------------------------------------+
| Nama         : {nama}
| NIK          : {nik}
| Asal         : {asal}
| Tujuan       : {tujuan}
| Tanggal      : {tanggal}
| Jam          : {jam}
| Kelas        : {kelas}
| Kereta       : {nama_kereta}
| Nomor Kereta : {nomor_kereta}
| Kode Booking : {kode_booking}
+----------------------------------------+
"""

        data_json = json.dumps(data_tiket)
        encrypted_data = encrypt_aes(data_json)
        signature = sign_data_rsa(data_json)

        # Simpan ke database
        insert_ticket(user[0], encrypted_data, signature)

        st.success("Tiket berhasil dipesan dan disimpan di database!")
        st.text(tiket_kartu)

        st.subheader("🔒 Enkripsi (AES)")
        st.code(encrypted_data[:150] + "...", language="text")

        st.subheader("✍️ Digital Signature (RSA + SHA-256)")
        st.code(signature[:150] + "...", language="text")

        # Unduh tiket
        file_content = tiket_kartu + "\n\n---\n\nEncrypted Data:\n" + encrypted_data + "\n\nSignature:\n" + signature
        st.download_button(
            label="⬇️ Download Tiket",
            data=file_content,
            file_name="tiket_kereta.txt",
            mime="text/plain"
        )

# ✅ Panggil fungsi agar halaman muncul saat file dijalankan langsung
if __name__ == "__main__":
    halaman_pemesanan()