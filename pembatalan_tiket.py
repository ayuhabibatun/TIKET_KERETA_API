import streamlit as st
import json
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from database import (
    get_user_by_username,
    get_ticket_by_user_id,
    delete_existing_ticket,
    insert_cancellation,
    create_cancellation_table
)

# Load kunci privat dari file
with open("private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())

# AES Helper
def pad(s):
    pad_len = 16 - len(s) % 16
    return s + chr(pad_len) * pad_len

def encrypt_aes(data_str, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(data_str).encode())
    return base64.b64encode(encrypted).decode()

def decrypt_aes(encrypted_text, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    decoded = base64.b64decode(encrypted_text)
    decrypted = cipher.decrypt(decoded).decode()
    pad_len = ord(decrypted[-1])
    return json.loads(decrypted[:-pad_len])

# Digital Signature (RSA + SHA256)
def sign_data_rsa(data_str):
    hash_obj = SHA256.new(data_str.encode())
    signature = pkcs1_15.new(private_key).sign(hash_obj)
    return base64.b64encode(signature).decode()

# Halaman utama

def halaman_pembatalan():
    st.title("❌ Pembatalan Tiket Kereta")
    create_cancellation_table()

    if "username" not in st.session_state:
        st.warning("Silakan login terlebih dahulu.")
        return

    user = get_user_by_username(st.session_state["username"])
    if not user:
        st.error("User tidak ditemukan.")
        return

    tiket = get_ticket_by_user_id(user[0])
    if not tiket:
        st.info("Anda belum memesan tiket.")
        return

    # Dekripsi tiket
    encrypted_data = tiket[2]
    aes_key = "kunciAESsederhana"
    try:
        data_tiket = decrypt_aes(encrypted_data, aes_key)
    except Exception:
        st.error("Gagal mendekripsi data tiket.")
        return

    # Format kapital awal
    formatted_data = {
        "Nama": data_tiket["nama"].title(),
        "NIK": data_tiket["nik"],
        "Asal": data_tiket["asal"].title(),
        "Tujuan": data_tiket["tujuan"].title(),
        "Tanggal": data_tiket["tanggal"],
        "Jam": data_tiket["jam"],
        "Kereta": data_tiket.get("kereta", "Tidak diketahui"),
        "Nomor Kereta": data_tiket.get("nomor_kereta", "Tidak diketahui"),
        "Kode Booking": data_tiket.get("kode_booking", "Tidak diketahui"),
        "Status": "Dibatalkan"
    }

    st.subheader("📋 Tiket Anda")
    st.json(formatted_data)

    if st.button("Batalkan Tiket"):
        log_str = json.dumps(formatted_data, sort_keys=True)

        # ✍️ Signature atas log asli
        signature = sign_data_rsa(log_str)

        st.subheader("🔒 Enkripsi (AES)")
        log_encrypted = encrypt_aes(log_str, aes_key)
        st.code(log_encrypted[:100] + "...", language="text")

        st.subheader("🔏 Digital Signature (RSA + SHA-256)")
        st.code(signature[:100] + "...", language="text")

        insert_cancellation(user[0], log_encrypted, signature)
        delete_existing_ticket(user[0])

        st.success("✅ Tiket berhasil dibatalkan dan dicatat ke database.")

        st.download_button(
            label="⬇️ Download Bukti Pembatalan",
            data=f"Log Encrypted:\n{log_encrypted}\n\nSignature:\n{signature}",
            file_name="bukti_pembatalan.txt",
            mime="text/plain"
        )

# Jalankan halaman
if __name__ == "__main__":
    halaman_pembatalan()
