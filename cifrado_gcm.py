#Codigo modificado.
#Original -> https://cryptobook.nakov.com/symmetric-key-ciphers/aes-encrypt-decrypt-examples#aes-256-gcm-example

from Crypto.Cipher import AES
import binascii, os
import pyaes, pbkdf2, binascii, os, secrets, base64, mysql.connector, SecureString
import json

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(encryptedMsg, secretKey):
    (ciphertext, nonce, authTag) = encryptedMsg
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def conexion_db():
    db=[]
    with open('db_conexion.json') as file:
        data=json.load(file)

        for conexion in data['dataBase']:
            print('Base de datos: ', conexion['database'])
            db.append(conexion.append['user'])
            db.append(conexion.append['password'])
            db.append(conexion.append['host'])
            db.append(conexion.append['port'])
            db.append(conexion['database'])
    return db

#Main

#Datos del paciante a cifrar
name = "Jhon Connor"
diagnosis = "Heridas por ataque de T-800"
treatment = "Paracetamol cada 8 hrs"

secretKey = os.urandom(32)  # 256-bit random encryption key
print("Encryption key:", binascii.hexlify(secretKey))

msg = b'Message for AES-256-GCM + Scrypt encryption'
encryptedMsg = encrypt_AES_GCM(msg, secretKey)
print("encryptedMsg", {
    'ciphertext': binascii.hexlify(encryptedMsg[0]),
    'aesIV': binascii.hexlify(encryptedMsg[1]),
    'authTag': binascii.hexlify(encryptedMsg[2])
})

decryptedMsg = decrypt_AES_GCM(encryptedMsg, secretKey)
print("decryptedMsg", decryptedMsg)