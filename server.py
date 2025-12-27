import socket
import struct
import os
import time

# Import the functions for the server code
import server_func

# Cryptography libraries for RSA decryption
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


def load_private_key():
    """Loads the private key from server.key file"""
    try:
        with open("server.key", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        return private_key
    except FileNotFoundError:
        print("[-] Error: server.key not found. Run generation script first.")
        return None


def decrypt_pre_master_secret(private_key, packet_data):
    """
    Extracts encrypted data from packet and decrypts using Private Key.
    """
    try:
        # Client Key Exchange Structure for RSA:
        # [0:5] Record Header
        # [5:9] Handshake Header
        # [9:11] Encrypted Data Length (2 bytes)
        # [11:] Encrypted Data itself
        encrypted_len = struct.unpack('!H', packet_data[9:11])[0]
        print(f"[*] Parsed Encrypted Length: {encrypted_len} bytes")

        # Skip headers to get to the Encrypted Data
        encrypted_bytes = packet_data[11 : 11 + encrypted_len]

        if len(encrypted_bytes) != private_key.key_size // 8:
            print(f"[-] Warning: Expected {private_key.key_size // 8} bytes, got {len(encrypted_bytes)}")

        print(f"[*] Decrypting {len(encrypted_bytes)} bytes...")

        # Decrypt using RSA PKCS1v15 padding
        pre_master_secret = private_key.decrypt(
            encrypted_bytes,
            padding.PKCS1v15()
        )
        return pre_master_secret
    except Exception as e:
        print(f"[-] Decryption failed: {e}")
        import traceback
        traceback.print_exc()
        return None
        return None

def start_server():
    host = '0.0.0.0'
    port = 4433
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)

    private_key = load_private_key()
    if not private_key: return

    print("[*] Server listening on port 4433...")

    while True:
        client, addr = server_socket.accept()
        print(f"\n[*] Connection from {addr}")

        try:
            # 1. Read Record Header (5 bytes)
            header = client.recv(5)
            if not header: break

            # Unpack header
            content_type, version, length = struct.unpack('!BHH', header)

            if content_type != 22:  # Handshake
                print(f"[-] Error: Expected Handshake (22), got {content_type}")
                break

            # 2. Read the body
            body = client.recv(length)

            # 3. Parse details (Prints everything + returns data)
            session_id, client_ciphers, client_random = server_func.parse_client_hello(body)

            # 4. Logic: Choose Cipher
            chosen_cipher = None
            for server_c in server_func.SERVER_PREFERRED_CIPHERS:
                if server_c in client_ciphers:
                    chosen_cipher = server_c
                    break

            if chosen_cipher:
                print(f"[V] Agreed on Cipher: 0x{chosen_cipher:04x}")

                # Generate Server Random (New random for each connection)
                server_random = os.urandom(32)

                # 5. Build and Send Response
                response = server_func.build_server_hello(session_id, server_random, chosen_cipher)
                client.send(response)
                print("[V] Server Hello sent successfully.")

                # 6. Send Certificate
                cert_packet = server_func.build_certificate_message()
                if cert_packet:
                    client.send(cert_packet)
                    print("[V] Certificate sent.")

                # 7. Send Server Hello Done
                done_packet = server_func.build_server_hello_done()
                client.send(done_packet)
                print("[V] Server Hello Done sent.")

                # 8. Receive Client Key Exchange
                print("[*] Waiting for Client response...")
                client_response = client.recv(4096)
                if client_response:
                    print(f"[V] Received {len(client_response)} bytes from client!")

                    # Check if it looks like a Handshake record (0x16)
                    if client_response[0] == 0x16:

                        # --- DECRYPTION STEP ---
                        pre_master = decrypt_pre_master_secret(private_key, client_response)

                        if pre_master:
                            print("\n" + "=" * 50)
                            print("[!!!] SUCCESS! Decrypted Pre-Master Secret [!!!]")
                            print("=" * 50)
                            print(f"Secret Hex: {pre_master.hex()}")

                            # Validation: Should start with TLS version (03 03)
                            if pre_master[:2] == b'\x03\x03':
                                print("[V] Secret looks valid (Version 0303 found).")
                            else:
                                print(f"[!] Warning: Secret starts with {pre_master[:2].hex()}")
                        else:
                            print("[-] Failed to decrypt secret.")
                else:
                    print("[-] Client closed connection without sending data.")

                # 9. Wait briefly before closing
                print("[*] Waiting 2 seconds...")
                time.sleep(2)
            else:
                print("[X] No shared cipher found.")

        except Exception as e:
            print(f"Error: {e}")
        finally:
            client.close()


if __name__ == "__main__":
    start_server()