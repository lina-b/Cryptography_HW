import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
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

server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_public_key = server_private_key.public_key()

def serialize_public_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def decrypt_with_private_key(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_aes(key, iv, ciphertext):
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

HOST = '127.0.0.1'
PORT = 65432

# Performance Metrics
overall_start = time.time()
process = psutil.Process(os.getpid())
initial_memory = process.memory_info().rss

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print('Server: Listening for connections...')
    conn, addr = s.accept()
    with conn:
        print(f'Server: Connected by {addr}')

        # Handshake/Public Key Send
        handshake_start = time.time()
        pubkey_bytes = serialize_public_key(server_public_key)
        conn.sendall(pubkey_bytes)
        handshake_end = time.time()

        # Key Exchange (receive session key)
        key_exchange_start = time.time()
        enc_session_key = recvall(conn, 256)
        session_key = decrypt_with_private_key(server_private_key, enc_session_key)
        print('Server: Session key received and decrypted.')
        key_exchange_end = time.time()

        # Receive IV and encrypted message
        iv = recvall(conn, 16)
        msg_len_data = recvall(conn, 4)
        (msg_len,) = struct.unpack('!I', msg_len_data)
        enc_message = recvall(conn, msg_len)

        # Decryption timing
        decryption_start = time.time()
        decrypted_message = decrypt_aes(session_key, iv, enc_message)
        print('Server: Received (decrypted):', decrypted_message.decode().strip())
        decryption_end = time.time()

        # Encryption and response
        encryption_start = time.time()
        response = b'Hello from server (secured via TLS)!'
        padded_response = response + b' ' * (16 - len(response) % 16)
        new_iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(session_key), modes.CBC(new_iv)).encryptor()
        enc_response = encryptor.update(padded_response) + encryptor.finalize()
        encryption_end = time.time()

        # Send IV, length, and encrypted response
        send_start = time.time()
        conn.sendall(new_iv)
        conn.sendall(struct.pack('!I', len(enc_response)))
        conn.sendall(enc_response)
        send_end = time.time()
        print('Server: Secure response sent.')

# Performance Metrics
overall_end = time.time()
final_memory = process.memory_info().rss

print("\n--- Performance Metrics ---")
print(f"Handshake/Public Key Send Time: {handshake_end - handshake_start:.6f} s")
print(f"Session Key Receive/Decrypt Time: {key_exchange_end - key_exchange_start:.6f} s")
print(f"Message Decryption Time: {decryption_end - decryption_start:.6f} s")
print(f"Response Encryption Time: {encryption_end - encryption_start:.6f} s")
print(f"Response Send Time: {send_end - send_start:.6f} s")
print(f"Total Protocol Runtime: {overall_end - overall_start:.6f} s")
print(f"Peak Memory Usage: {(final_memory - initial_memory)/1024:.2f} KB")
