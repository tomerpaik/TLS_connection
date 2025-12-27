import socket
import struct
import os
import time

# Import the functions for the server code
import server_func

# Cryptography libraries for RSA decryption
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec


def load_rsa_private_key():
    """Loads the static RSA private key (for signing)"""
    try:
        with open("server.key", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        return private_key
    except FileNotFoundError:
        print("[-] Error: server.key not found.")
        return None


def create_ephemeral_key():
    """
    Generates a temporary (ephemeral) private/public key pair
    on the curve SECP256R1.
    """
    # Generate private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Serialize public key to bytes (uncompressed format) for sending
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return private_key, public_key_bytes

def derive_shared_secret(server_ephemeral_private, client_pub_key_bytes):
    """
    Performs the ECDH math: (ServerPriv * ClientPub) = Shared Secret
    """
    try:
        # 1. Load the client's public key from bytes
        # ECDHE public key is usually 1 byte length + 65 bytes key (0x04 + X + Y)
        # We assume the packet contains just the length + key.

        # Extract the key part (skip the length byte)
        key_length = client_pub_key_bytes[0]
        actual_key_data = client_pub_key_bytes[1: 1 + key_length]

        print(f"[*] Client Public Key Length: {key_length}")

        client_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            actual_key_data
        )

        # 2. Derive shared secret
        shared_secret = server_ephemeral_private.exchange(ec.ECDH(), client_pub_key)
        return shared_secret

    except Exception as e:
        print(f"[-] Key derivation failed: {e}")
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

    # Load static RSA key (used ONLY for signing now!)
    rsa_signing_key = load_rsa_private_key()
    if not rsa_signing_key: return

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

                # 7. Generate Ephemeral Keys
                emph_private, emph_public_bytes = create_ephemeral_key()
                print("[V] Ephemeral keys generated.")

                # 8. Send Server Key Exchange
                # We send the public key, SIGNED by our RSA key
                key_exchange_packet = server_func.build_server_key_exchange(
                    client_random, server_random, emph_public_bytes, rsa_signing_key
                )
                client.send(key_exchange_packet)
                print("[V] Server Key Exchange sent (Signed).")

                # 9. Send Server Hello Done
                done_packet = server_func.build_server_hello_done()
                client.send(done_packet)
                print("[V] Server Hello Done sent.")

                # 10. Receive Client Key Exchange
                print("[*] Waiting for Client response...")
                client_response = client.recv(4096)

                if client_response and client_response[0] == 0x16:
                    # In ECDHE, the client sends its Public Key here (not encrypted secret)
                    # Extract the body (skip headers)
                    # [0:5] Record Header, [5:9] Handshake Header
                    # Data starts at index 9 for ClientKeyExchange in ECDHE (usually)

                    # NOTE: Parsing is slightly different. The body is just length(1) + key.
                    # We skip the headers (5 bytes Record + 4 bytes Handshake)
                    client_pub_key_raw = client_response[9:]

                    # 11. Derive Shared Secret
                    shared_secret = derive_shared_secret(emph_private, client_pub_key_raw)

                    if shared_secret:
                        print("\n" + "=" * 50)
                        print("[!!!] SUCCESS! Calculated Shared Secret (ECDHE) [!!!]")
                        print("=" * 50)
                        print(f"Secret Hex: {shared_secret.hex()}")
                        print(f"Length:     {len(shared_secret)} bytes (Expect 32)")
                    else:
                        print("[-] Failed to derive secret.")

                else:
                    print("[-] Invalid response from client.")

                time.sleep(1)
            else:
                print("[X] No shared cipher found.")

        except Exception as e:
            print(f"Error: {e}")
        finally:
            client.close()


if __name__ == "__main__":
    start_server()