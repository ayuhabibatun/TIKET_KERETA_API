import streamlit as st
from login import login_page
from pesantiket import halaman_pemesanan
from pembatalan_tiket import halaman_pembatalan
from dekripsi import halaman_dekripsi 

def main():
    if "login" not in st.session_state:
        st.session_state["login"] = False

    if st.session_state["login"]:
        st.sidebar.success(f"Login sebagai {st.session_state['username']}")
        menu = st.sidebar.radio("Menu", [
            "Beranda", 
            "Pemesanan Tiket", 
            "Pembatalan Tiket",
            "Dekripsi Bukti", 
            "Logout"
        ])

        if menu == "Beranda":
            st.title(f"Selamat datang, {st.session_state['username']} 👋")
            st.write("Silakan pilih menu di samping.")

        elif menu == "Pemesanan Tiket":
            halaman_pemesanan()

        elif menu == "Pembatalan Tiket":
            halaman_pembatalan()
        
        elif menu == "Dekripsi Bukti":
            halaman_dekripsi()

        elif menu == "Logout":
            st.session_state["login"] = False
            st.session_state["username"] = ""
            st.rerun()
    else:
        login_page()

if __name__ == "__main__":
    main()
