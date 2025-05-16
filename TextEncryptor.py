import os
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

# Generate RSA Keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("private.pem", "wb") as private_file:
        private_file.write(private_key)
    with open("public.pem", "wb") as public_file:
        public_file.write(public_key)
    print("RSA Keys Generated.")

def encrypt_aes(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return cipher.iv, ct_bytes

def decrypt_aes(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return pt.decode('utf-8')

def encrypt_des(plaintext, key):
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), DES.block_size))
    return cipher.iv, ct_bytes

def decrypt_des(iv, ciphertext, key):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return pt.decode('utf-8')

def encrypt_rsa(plaintext, public_key_file):
    with open(public_key_file, 'rb') as key_file:
        public_key = RSA.import_key(key_file.read())
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return ciphertext

def decrypt_rsa(ciphertext, private_key_file):
    with open(private_key_file, 'rb') as key_file:
        private_key = RSA.import_key(key_file.read())
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')

if __name__ == "__main__":
    plaintext = input("Enter the text to encrypt: ")

    # AES Encryption and Decryption
    aes_key = os.urandom(16)
    iv_aes, ciphertext_aes = encrypt_aes(plaintext, aes_key)
    decrypted_aes = decrypt_aes(iv_aes, ciphertext_aes, aes_key)
    print("\n[AES Encryption]")
    print("Ciphertext (AES):", ciphertext_aes)
    print("Decrypted Text (AES):", decrypted_aes)

    # DES Encryption and Decryption
    des_key = os.urandom(8)
    iv_des, ciphertext_des = encrypt_des(plaintext, des_key)
    decrypted_des = decrypt_des(iv_des, ciphertext_des, des_key)
    print("\n[DES Encryption]")
    print("Ciphertext (DES):", ciphertext_des)
    print("Decrypted Text (DES):", decrypted_des)

    # RSA Encryption and Decryption
    generate_rsa_keys()
    rsa_ciphertext = encrypt_rsa(plaintext, "public.pem")
    decrypted_rsa = decrypt_rsa(rsa_ciphertext, "private.pem")
    print("\n[RSA Encryption]")
    print("Ciphertext (RSA):", rsa_ciphertext)
    print("Decrypted Text (RSA):", decrypted_rsa)
