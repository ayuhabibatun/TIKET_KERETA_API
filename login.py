import streamlit as st
import hashlib
from database import create_user_table, add_user, get_user

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_page():
    st.title("🚆 Login E-Tiket Kereta")

    create_user_table()

    menu = st.selectbox("Pilih Menu", ["Login", "Registrasi"])

    if menu == "Login":
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            hashed = hash_password(password)
            user = get_user(username, hashed)
            if user:
                st.session_state["login"] = True
                st.session_state["username"] = username
                st.success("Login berhasil!")
                st.rerun()  # ⬅ WAJIB AGAR LANJUT OTOMATIS
            else:
                st.error("Username atau password salah.")

    elif menu == "Registrasi":
        new_user = st.text_input("Buat Username")
        new_pass = st.text_input("Buat Password", type="password")
        if st.button("Daftar"):
            if new_user and new_pass:
                try:
                    hashed = hash_password(new_pass)
                    add_user(new_user, hashed)
                    st.success("Registrasi berhasil. Silakan login.")
                except:
                    st.error("Registrasi gagal. Username mungkin sudah digunakan.")
            else:
                st.warning("Harap isi semua kolom.")
