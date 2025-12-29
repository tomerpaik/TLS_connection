import socket
import struct
import os
import time

# Import the functions for the server code
import server_func

# Cryptography libraries for RSA decryption
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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
    """Generates a temporary (ephemeral) private/public key pair on SECP256R1."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return private_key, public_key_bytes

def derive_shared_secret(server_ephemeral_private, client_pub_key_bytes):
    """Performs the ECDH math: (ServerPriv * ClientPub) = Shared Secret"""
    try:
        # Determine where the key starts. Usually byte 0 is length (e.g. 0x41)
        if len(client_pub_key_bytes) == 66:
            actual_key_data = client_pub_key_bytes[1:]
        elif len(client_pub_key_bytes) == 65:
            actual_key_data = client_pub_key_bytes
        else:
            print(f"[-] Unexpected key length: {len(client_pub_key_bytes)}")
            return None

        client_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            actual_key_data
        )

        return server_ephemeral_private.exchange(ec.ECDH(), client_pub_key)
    except Exception as e:
        print(f"[-] Key derivation failed: {e}")
        return None

def decrypt_gcm_record(key, iv_salt, full_record, seq_num_bytes):
    """
    Decrypts a TLS 1.2 AES-GCM record.
    Constructs the Nonce and AAD required for GCM verification.
    """
    try:
        # full_record contains: Header (5) + ExplicitNonce (8) + Ciphertext + Tag (16)

        # 1. Parse Header
        rec_type = full_record[0]
        rec_ver = full_record[1:3]
        rec_len = struct.unpack('!H', full_record[3:5])[0]

        # 2. Extract Explicit Nonce (8 bytes)
        # Body starts at index 5. First 8 bytes of body are Explicit Nonce.
        explicit_nonce = full_record[5: 5 + 8]

        # 3. Extract Ciphertext + Tag
        # Everything after the explicit nonce
        ciphertext_with_tag = full_record[5 + 8:]

        # 4. Construct GCM Nonce (12 bytes)
        # Nonce = Implicit Salt (4 bytes) + Explicit Nonce (8 bytes)
        nonce = iv_salt + explicit_nonce

        # 5. Construct AAD (Additional Authenticated Data)
        # AAD = SeqNum + Type + Ver + Length_of_Plaintext
        # Note: Length in AAD is NOT rec_len. It is length of plaintext.
        # Plaintext len = Total Body len - Explicit Nonce len (8) - Tag len (16)
        plaintext_len = rec_len - 8 - 16
        aad_len_bytes = struct.pack('!H', plaintext_len)

        aad = seq_num_bytes + bytes([rec_type]) + rec_ver + aad_len_bytes

        # 6. Decrypt
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)

        return plaintext
    except Exception as e:
        print(f"[-] GCM Decryption Error: {e}")
        return None


def start_server():
    host = '0.0.0.0'
    port = 4433
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)

    rsa_signing_key = load_rsa_private_key()
    if not rsa_signing_key: return

    print("[*] Server listening on port 4433...")

    while True:
        client, addr = server_socket.accept()
        print(f"\n[*] Connection from {addr}")

        try:
            # 1. Read Record Header
            header = client.recv(5)
            if not header: break
            content_type, version, length = struct.unpack('!BHH', header)

            if content_type != 22:
                client.close()
                continue

            # 2. Read Client Hello Body
            body = client.recv(length)
            session_id, client_ciphers, client_random = server_func.parse_client_hello(body)

            # 3. Logic: Choose Cipher
            chosen_cipher = None
            for server_c in server_func.SERVER_PREFERRED_CIPHERS:
                if server_c in client_ciphers:
                    chosen_cipher = server_c
                    break

            if not chosen_cipher:
                print("[X] No shared cipher found.")
                continue

            print(f"[V] Agreed on Cipher: 0x{chosen_cipher:04x}")
            server_random = os.urandom(32)

            # 4-9. Send Handshake Messages
            client.send(server_func.build_server_hello(session_id, server_random, chosen_cipher))
            client.send(server_func.build_certificate_message())

            emph_private, emph_public_bytes = create_ephemeral_key()
            print("[V] Ephemeral keys generated.")

            client.send(server_func.build_server_key_exchange(
                client_random, server_random, emph_public_bytes, rsa_signing_key
            ))
            print("[V] Server Key Exchange sent (Signed).")

            client.send(server_func.build_server_hello_done())
            print("[V] Server Hello Done sent.")

            # --- 10. Buffer Handling ---
            print("[*] Waiting for Client response...")
            raw_buffer = client.recv(4096)

            if not raw_buffer:
                print("[-] Client disconnected.")
                continue

            if raw_buffer[0] != 0x16:
                print("[-] First packet was not a Handshake record.")
                continue

            # --- PROCESS PACKET 1: Client Key Exchange ---
            key_exchange_len = struct.unpack('!H', raw_buffer[3:5])[0]
            record_end = 5 + key_exchange_len

            key_exchange_record = raw_buffer[:record_end]
            remaining_buffer = raw_buffer[record_end:]

            client_pub_key_raw = key_exchange_record[9:]

            # 11. Derive Shared Secret
            shared_secret = derive_shared_secret(emph_private, client_pub_key_raw)

            if not shared_secret:
                print("[-] Failed to derive secret.")
                continue

            print("\n" + "=" * 50)
            print("[!!!] SUCCESS! Calculated Shared Secret (ECDHE) [!!!]")
            print("=" * 50)

            # 12. Calculate Master Secret
            master_secret = server_func.calculate_master_secret(
                shared_secret, client_random, server_random
            )
            print("[V] Calculated Master Secret.")

            # 13. Key Expansion
            c_key, s_key, c_iv, s_iv = server_func.generate_session_keys(
                master_secret, client_random, server_random
            )

            print("=" * 30)
            print("SESSION KEYS GENERATED")
            print("=" * 30)
            print(f"Client Write Key: {c_key.hex()}")
            print(f"Client Write IV:  {c_iv.hex()}")

            # --- PROCESS PACKET 2: Change Cipher Spec ---
            print("\n[*] Looking for Change Cipher Spec...")

            ccs_record = None
            if len(remaining_buffer) > 0:
                ccs_record = remaining_buffer
            else:
                ccs_record = client.recv(1024)

            # Guard Clause 4: Validate CCS Structure
            if not ccs_record or ccs_record[0] != 0x14:
                print(f"[-] Expected CCS (20), got {ccs_record[0] if ccs_record else 'None'}")
                continue

            # Guard Clause 5: Validate CCS Payload
            if len(ccs_record) < 6 or ccs_record[5] != 0x01:
                print("[-] Invalid CCS Payload.")
                continue

            print("[V] Client signaled: Switch to Encryption Mode!")

            # --- PROCESS PACKET 3: Encrypted Finished Message ---
            if len(ccs_record) <= 6:
                print("[*] Waiting for Encrypted Finished Message...")
                continue

            encrypted_msg = ccs_record[6:]
            print(f"[*] Found Encrypted Handshake Message ({len(encrypted_msg)} bytes).")

            seq_num = b'\x00' * 8
            print("[*] Attempting to decrypt with AES-GCM...")

            plaintext = decrypt_gcm_record(
                c_key,  # Key
                c_iv,  # Salt
                encrypted_msg,
                seq_num  # SeqNum for AAD
            )

            if plaintext:
                print("\n" + "*" * 60)
                print("   [!!!] DECRYPTION SUCCESSFUL [!!!]")
                print("*" * 60)
                print(f"Decrypted Hex: {plaintext.hex()}")
                if plaintext[0] == 0x14:
                    print("[V] Content Type is 0x14 (Finished Message).")
                    print("[V] HANDSHAKE COMPLETED SUCCESSFULLY!")
            else:
                print("[-] Decryption Failed (Bad Key or Tag).")

            time.sleep(2)

        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            client.close()


if __name__ == "__main__":
    start_server()