import socket

from _thread import *
import threading

from Crypto.Cipher import AES

print_lock = threading.Lock()

key_k = ""
key_k_prime = "01010100011010000110100101110011001000000110100101110011001000000111010001101000011001010010000001110000011100100110100101101101" #This is the prim
initialization_vector = "01001001011011100110100101110100011010010110000101101100011010010111101001100001011101000110100101101111011011100010000001101011" #Initialization k

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
            text += "0" #string_to_binary("t")

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

key_type = ''
ok = True
while ok:
    key_type = input("Introduceti modul de operare CBC sau OFB: ")
    if key_type == 'CBC' or key_type == 'OFB':
        ok = False

def threaded(c):
    global key_k
    data = c.recv(1024)
    if data.decode('ascii') == "I am the KM":
        data = key_type.encode('ascii')
        c.send(data)
        key_k = c.recv(1024)
        if key_type == "CBC":
            #key_k = CBC_decrypting(initialization_vector,key_k_prime,key_k)
            aes = AES.new("This is the prim".encode('ascii'), AES.MODE_CBC, "Initialization k".encode('ascii'))
            key_k = aes.decrypt(key_k)
            key_k = key_k.decode('ascii')
        else:
            #key_k = OFB_decrypting(initialization_vector,key_k_prime,key_k)
            aes = AES.new("This is the prim".encode('ascii'), AES.MODE_OFB, "Initialization k".encode('ascii'))
            key_k = aes.decrypt(key_k)
            key_k = key_k.decode('ascii')
        print(binary_to_string(key_k))

        print("I recived the key from KM for ",key_type,".")

        print_lock.release()
    else:
        data = key_type.encode('ascii')
        c.send(data)
        flag = c.recv(1024)
        c.send(key_k.encode('ascii'))
        flag = c.recv(1024)
        print(flag.decode('ascii'))
        print("He told me that he received a valid key")

        f = open("input.txt", "r")
        text = f.read()
        if key_type == "CBC":
            text = CBC_encrypting(initialization_vector,key_k,string_to_binary(text))
        else:
            text = OFB_encrypting(initialization_vector,key_k,string_to_binary(text))
        c.send(text.encode('ascii'))
        print("I sent him the data.")

        print_lock.release()
    c.close()


host = '127.0.0.1'

port = 5000
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host, port))

s.listen(2)

while True:
    c, addr = s.accept()

    print_lock.acquire()

    start_new_thread(threaded, (c,))

s.close()
