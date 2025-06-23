import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import struct
import time
import psutil

def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            break
        data += packet
    return data

def deserialize_public_key(data):
    return serialization.load_pem_public_key(data)

def encrypt_with_public_key(public_key, message):
    return public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def encrypt_aes(key, iv, plaintext):
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    padded = plaintext + b' ' * (16 - len(plaintext) % 16)
    return encryptor.update(padded) + encryptor.finalize()

def decrypt_aes(key, iv, ciphertext):
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

HOST = '127.0.0.1'
PORT = 65432

# Performance Metrics:
overall_start = time.time()
process = psutil.Process(os.getpid())
initial_memory = process.memory_info().rss

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print('Client: Connected to server.')

    # Handshake/Public Key Receive
    handshake_start = time.time()
    pubkey_bytes = b''
    while True:
        part = s.recv(1024)
        pubkey_bytes += part
        if b'-----END PUBLIC KEY-----' in pubkey_bytes:
            break
    server_public_key = deserialize_public_key(pubkey_bytes)
    print('Client: Server public key received.')
    handshake_end = time.time()

    # Key Exchange (send session key)
    key_exchange_start = time.time()
    session_key = os.urandom(32)  # 256-bit AES key
    enc_session_key = encrypt_with_public_key(server_public_key, session_key)
    s.sendall(enc_session_key)
    print('Client: Session key sent (encrypted).')
    key_exchange_end = time.time()

    # Encryption and message send
    encryption_start = time.time()
    message = b'Hello from client (secured via TLS)!'
    iv = os.urandom(16)
    enc_message = encrypt_aes(session_key, iv, message)
    encryption_end = time.time()

    send_start = time.time()
    s.sendall(iv)
    s.sendall(struct.pack('!I', len(enc_message)))
    s.sendall(enc_message)
    print('Client: Secure message sent.')
    send_end = time.time()

    # Receive IV, length, and encrypted response
    recv_start = time.time()
    new_iv = recvall(s, 16)
    resp_len_data = recvall(s, 4)
    (resp_len,) = struct.unpack('!I', resp_len_data)
    enc_response = recvall(s, resp_len)
    recv_end = time.time()

    # Decrypt response
    decryption_start = time.time()
    decrypted_response = decrypt_aes(session_key, new_iv, enc_response)
    decryption_end = time.time()
    print('Client: Received (decrypted):', decrypted_response.decode().strip())

# Performance Metrics:
overall_end = time.time()
final_memory = process.memory_info().rss

print("\n--- Performance Metrics ---")
print(f"Handshake/Public Key Receive Time: {handshake_end - handshake_start:.6f} s")
print(f"Session Key Generation/Send Time: {key_exchange_end - key_exchange_start:.6f} s")
print(f"Message Encryption Time: {encryption_end - encryption_start:.6f} s")
print(f"Message Send Time: {send_end - send_start:.6f} s")
print(f"Response Receive Time: {recv_end - recv_start:.6f} s")
print(f"Response Decryption Time: {decryption_end - decryption_start:.6f} s")
print(f"Total Protocol Runtime: {overall_end - overall_start:.6f} s")
print(f"Peak Memory Usage: {(final_memory - initial_memory)/1024:.2f} KB")
