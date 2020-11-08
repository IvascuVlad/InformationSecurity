import socket
import string
import secrets
from Crypto.Cipher import AES

def string_to_binary(parametru):
    res = ''
    for x in parametru:
        aux = format(ord(x), 'b')
        while len(aux) < 8:
            aux = '0' + aux
        res += aux
    return res

def binary_to_string(parametru):
    rezultat = ''
    for i in range(0, len(parametru), 8):
        aux = parametru[i:i + 8]
        decoded = 0
        pow = 1
        for _ in range(len(aux)):
            decoded += int(aux[-1]) * pow
            pow = pow * 2
            aux = aux[:-1]
        rezultat += chr(decoded)
    return rezultat

def xor(first, second):
    result = ''
    for i in range(len(first)):
        result += str(int(first[i]) ^ int(second[i]))
    return result

def CBC_encrypting(initialization_vector, key, text):
    number_of_iterations = len(text) // 128
    previous = ""
    result = ""
    if len(text) % 128:
        number_of_iterations += 1
        while len(text) % 128 != 0:
            text += string_to_binary("t")

    for i in range(number_of_iterations):
        if i == 0:
            block_cipher = xor(text[i*128 : (i+1)*128],initialization_vector)
            ciphertext = xor(block_cipher, key)
            result += ciphertext
            previous = ciphertext
        else:
            block_cipher = xor(text[i * 128: (i + 1) * 128],previous)
            ciphertext = xor(block_cipher,key)
            result += ciphertext
            previous = ciphertext
    return result

def CBC_decrypting(initialization_vector, key, text):
    number_of_iterations = len(text) // 128
    print("Number of iter",number_of_iterations)
    previous = ""
    result = ""

    for i in range(number_of_iterations):
        if i == 0:
            block_cipher = xor(text[i * 128: (i + 1) * 128],key)
            plaintext = xor(block_cipher,initialization_vector)
            result += plaintext
            previous = text[i * 128: (i + 1) * 128]
        else:
            block_cipher = xor(text[i * 128: (i + 1) * 128],key)
            plaintext = xor(block_cipher,previous)
            result += plaintext
            previous = text[i * 128: (i + 1) * 128]
    return result

def OFB_encrypting(initialization_vector, key, text):
    number_of_iterations = len(text) // 128
    previous = ""
    ciphertext = ""
    if len(text) % 128:
        number_of_iterations += 1
        while len(text) % 128 != 0:
            text += "0"

    for i in range(number_of_iterations):
        if not i:
            previous = xor(initialization_vector,key)
            result = xor(previous, text[i*128 : (i+1)*128])
            ciphertext += result
        else:
            previous = xor(previous, key)
            result = xor(previous, text[i * 128: (i + 1) * 128])
            ciphertext += result
    return ciphertext

def OFB_decrypting(initialization_vector, key, text):
    number_of_iterations = len(text) // 128
    previous = ""
    plaintext = ""
    if len(text) % 128:
        number_of_iterations += 1
        while len(text) % 128 != 0:
            text += "0"

    for i in range(number_of_iterations):
        if not i:
            previous = xor(initialization_vector, key)
            result = xor(previous, text[i * 128: (i + 1) * 128])
            plaintext += result
        else:
            previous = xor(previous, key)
            result = xor(previous, text[i * 128: (i + 1) * 128])
            plaintext += result
    return plaintext

host = '127.0.0.1'

port = 5000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, port))

alphabet = string.ascii_letters + string.digits
password = ''.join(secrets.choice(alphabet) for i in range(16))
key_k = string_to_binary(password) #random 128
key_k_prime = "01010100011010000110100101110011001000000110100101110011001000000111010001101000011001010010000001110000011100100110100101101101" #This is the prim
initialization_vector = "01001001011011100110100101110100011010010110000101101100011010010111101001100001011101000110100101101111011011100010000001101011" #Initialization k

message = "I am the KM"

s.send(message.encode('ascii'))

data = s.recv(1024)

print('Received from the server :', str(data.decode('ascii')))

key_type = data.decode('ascii')

print(binary_to_string(key_k))

if data.decode('ascii') == "CBC":
    #aux = CBC_encrypting(initialization_vector, key_k_prime, key_k)
    aes = AES.new("This is the prim".encode('ascii'), AES.MODE_CBC, "Initialization k".encode('ascii'))
    aux = aes.encrypt(key_k.encode('ascii'))
else:
    #aux = OFB_encrypting(initialization_vector, key_k_prime, key_k)
    aes = AES.new("This is the prim".encode('ascii'), AES.MODE_OFB, "Initialization k".encode('ascii'))
    aux = aes.encrypt(key_k.encode('ascii'))

print(aux)

s.send(aux)

print("Send the key for ",key_type,". Have a nice day!")

s.close()
