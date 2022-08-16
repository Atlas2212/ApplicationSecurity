from os import environ, path
from dotenv import load_dotenv
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def get_fixed_key():
    basedir = path.abspath(path.dirname(__file__))
    load_dotenv(path.join(basedir, '.env'))
    key = (environ.get("AES_KEY")).encode("utf8")
    return key
    #use fixed AES key, 256 bits
    #return b"..."


def get_random_key():
    """ generate random AES key, keysize = 32*8 = 256 bits"""
    key = get_random_bytes(32)
    return key
    #return get_random_bytes(...)


# AES encrypt using CBC and IV, with default padding (PKCS7)
def encrypt(key, plaintext_utf8):
    encrypted_text = b""
    #cipher = AES.new(key, AES...) #Q6
    #ciphertext = cipher.encrypt(pad(..., ...))
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext_utf8,128))
    # write iv and ciphertext to file
    for x in (cipher.iv, ciphertext):
      encrypted_text += x

    return encrypted_text


# AES decrypt using CBC and IV, with default unpadding (PKCS7)
def decrypt(key, ciphertext):
    # read iv and ciphertext from file
    iv = ciphertext[:16]
    key = get_fixed_key()
    encrypted_text = ciphertext[16:]  
    cipher = AES.new(key, AES.MODE_CBC,iv) #Q6
    decryptedtext_utf = unpad(cipher.decrypt(encrypted_text),128)

    return decryptedtext_utf
