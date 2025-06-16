from Crypto.PublicKey import RSA

# Hanya dijalankan satu kali untuk generate kunci
key = RSA.generate(2048)

with open("private.pem", "wb") as f:
    f.write(key.export_key())

with open("public.pem", "wb") as f:
    f.write(key.publickey().export_key())

print("Kunci RSA berhasil disimpan ke 'private.pem' dan 'public.pem'")
