import binascii
from Crypto.Cipher import ARC4, DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# ====================== XOR ==========================
def xor_cipher_encrypt(input_file, output_file, kunci):
    plainteks = input_file.read()
    cipherteks = bytearray()
    byte_kunci = bytearray(kunci, 'utf-8')
    n = len(kunci)
    indeks_kunci = 0
    for byte in plainteks:
        c = byte ^ byte_kunci[indeks_kunci]
        cipherteks.append(c)
        indeks_kunci = (indeks_kunci + 1) % n
    with open(output_file, 'wb') as file:
        file.write(cipherteks)

def xor_cipher_decrypt(input_file, output_file, kunci):
    cipherteks = input_file.read()
    plainteks = bytearray()
    byte_kunci = bytearray(kunci, 'utf-8')
    n = len(kunci)
    indeks_kunci = 0
    for byte in cipherteks:
        p = byte ^ byte_kunci[indeks_kunci]
        plainteks.append(p)
        indeks_kunci = (indeks_kunci + 1) % n
    with open(output_file, 'wb') as file:
        file.write(plainteks)

def xor_encrypt_decrypt(text, key):
    key_length = len(key)
    return ''.join(chr(ord(text[i]) ^ ord(key[i % key_length])) for i in range(len(text)))

# ======================= RC4 ========================
def RC4_encrypt(input_file, output_file, kunci):
    plainteks = input_file.read()
    kunci = kunci.encode()
    cipher = ARC4.new(kunci)
    cipherteks = cipher.encrypt(plainteks)
    hasil = base64.b64encode(cipherteks).decode()
    with open(output_file, 'wb') as file:
        file.write(hasil.encode())

def RC4_encrypt1(plainteks, kunci):
    kunci = kunci.encode()
    cipher = ARC4.new(kunci)
    cipherteks = cipher.encrypt(plainteks.encode())
    return base64.b64encode(cipherteks).decode()
                    
def RC4_decrypt(input_file, output_file, kunci):
    cipherteks = input_file.read()
    kunci = kunci.encode()
    plain = ARC4.new(kunci)
    plainteks_decoded = base64.b64decode(cipherteks)
    hasil = plain.decrypt(plainteks_decoded)
    with open(output_file, 'wb') as file:
        file.write(hasil)

def RC4_decrypt1(cipherteks, kunci):
    kunci = kunci.encode()
    plain = ARC4.new(kunci)
    plainteks_decoded = base64.b64decode(cipherteks)
    hasil = plain.decrypt(plainteks_decoded)
    return hasil.decode('utf-8')

# =================== DES ======================
def DES_encrypt1(plaintext, key, mode):
    key = key.ljust(8, '0') 
    plaintext = plaintext.encode()
    
    if mode == 'ECB':
        cipher = DES.new(key.encode(), DES.MODE_ECB)
        padded_data = pad(plaintext, DES.block_size)
        ciphertext = cipher.encrypt(padded_data)
    
    elif mode == 'CBC':
        iv = get_random_bytes(DES.block_size)
        cipher = DES.new(key.encode(), DES.MODE_CBC, iv)
        padded_data = pad(plaintext, DES.block_size)
        ciphertext = iv + cipher.encrypt(padded_data)
    
    elif mode == 'CTR':
        nonce = get_random_bytes(DES.block_size)
        cipher = DES.new(key.encode(), DES.MODE_CTR, nonce=nonce)
        ciphertext = nonce + cipher.encrypt(plaintext)
        
    return binascii.hexlify(ciphertext).decode() 

def DES_decrypt1(ciphertext, key, mode):
    key = key.ljust(8, '0') 
    ciphertext_bytes = binascii.unhexlify(ciphertext)

    if mode == 'ECB':
        cipher = DES.new(key.encode(), DES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(ciphertext_bytes), DES.block_size)
    
    elif mode == 'CBC':
        iv = ciphertext_bytes[:DES.block_size]
        cipher = DES.new(key.encode(), DES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext_bytes[DES.block_size:]), DES.block_size)
    
    elif mode == 'CTR':
        nonce = ciphertext_bytes[:DES.block_size]
        cipher = DES.new(key.encode(), DES.MODE_CTR, nonce=nonce)
        decrypted_data = cipher.decrypt(ciphertext_bytes[DES.block_size:])

    return decrypted_data.decode()

def DES_encrypt(input_file, output_file, key, mode):
    key = key.ljust(8, '0')  
    plaintext = input_file.read()

    ciphertext = None

    if mode == 'ECB':
        cipher = DES.new(key.encode(), DES.MODE_ECB)
        padded_data = pad(plaintext, DES.block_size)
        ciphertext = cipher.encrypt(padded_data)
    
    elif mode == 'CBC':
        iv = get_random_bytes(DES.block_size)
        cipher = DES.new(key.encode(), DES.MODE_CBC, iv)
        padded_data = pad(plaintext, DES.block_size)
        ciphertext = iv + cipher.encrypt(padded_data)
    
    elif mode == 'CTR':
        nonce = get_random_bytes(DES.block_size)
        cipher = DES.new(key.encode(), DES.MODE_CTR, nonce=nonce)
        ciphertext = nonce + cipher.encrypt(plaintext)

    with open(output_file, 'wb') as output_file:
        output_file.write(ciphertext)

def DES_decrypt(input_file, output_file, key, mode):
    key = key.ljust(8, '0')  
    ciphertext = input_file.read()
    if mode == 'ECB':
        cipher = DES.new(key.encode(), DES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(ciphertext), DES.block_size)
    elif mode == 'CBC':
        iv = ciphertext[:DES.block_size] 
        cipher = DES.new(key.encode(), DES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext[DES.block_size:]), DES.block_size)
    elif mode == 'CTR':
        nonce = ciphertext[:DES.block_size] 
        cipher = DES.new(key.encode(), DES.MODE_CTR, nonce=nonce)
        decrypted_data = cipher.decrypt(ciphertext[DES.block_size:])
    with open(output_file, 'wb') as output_file:
        output_file.write(decrypted_data)

# ======================== AES ========================
def AES_encrypt1(plaintext, key, mode):
    if isinstance(key, str):
        key = key.encode('utf-8')
    key = key.ljust(16, b'\0')
    plaintext_padded = pad(plaintext.encode(), AES.block_size)
    
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(plaintext_padded)
    elif mode == 'CBC':
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = iv + cipher.encrypt(plaintext_padded)
    elif mode == 'CTR':
        nonce = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        ciphertext = nonce + cipher.encrypt(plaintext.encode())

    return base64.b64encode(ciphertext).decode('utf-8')

def AES_decrypt1(ciphertext, key, mode):
    if isinstance(key, str):
        key = key.encode('utf-8')
    key = key.ljust(16, b'\0')
    ciphertext = base64.b64decode(ciphertext)

    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext_padded = cipher.decrypt(ciphertext)
        plaintext = unpad(plaintext_padded, AES.block_size).decode('utf-8')

    elif mode == 'CBC':
        iv = ciphertext[:AES.block_size] 
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext_padded = cipher.decrypt(ciphertext[AES.block_size:])
        plaintext = unpad(plaintext_padded, AES.block_size).decode('utf-8')
    
    elif mode == 'CTR':
        nonce = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:]).decode('utf-8')

    return plaintext

def AES_encrypt(input_file, output_file, key, mode):
    key = key.ljust(16, '0') 
    plaintext = input_file.read()
    
    if mode == 'ECB':
        cipher = AES.new(key.encode(), AES.MODE_ECB)
        padded_data = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
    
    elif mode == 'CBC':
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
        padded_data = pad(plaintext, AES.block_size)
        ciphertext = iv + cipher.encrypt(padded_data) 
    
    elif mode == 'CTR':
        nonce = get_random_bytes(AES.block_size)
        cipher = AES.new(key.encode(), AES.MODE_CTR, nonce=nonce)
        ciphertext = nonce + cipher.encrypt(plaintext)

    with open(output_file, 'wb') as out_file:
        out_file.write(ciphertext)

def AES_decrypt(input_file, output_file, key, mode):
    key = key.ljust(16, '0') 
    ciphertext = input_file.read()

    if mode == 'ECB':
        cipher = AES.new(key.encode(), AES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)

    elif mode == 'CBC':
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)

    elif mode == 'CTR':
        nonce = ciphertext[:AES.block_size]
        cipher = AES.new(key.encode(), AES.MODE_CTR, nonce=nonce)
        decrypted_data = cipher.decrypt(ciphertext[AES.block_size:])

    with open(output_file, 'wb') as out_file:
        out_file.write(decrypted_data)

        
