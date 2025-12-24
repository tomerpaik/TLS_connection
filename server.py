import socket
import struct


def parse_client_hello(data):
    # 'data' starts after the Record Header (5 bytes)

    ptr = 0  # Pointer to current position in data

    # --- Handshake Header ---
    # Handshake Type (1 byte)
    hs_type = data[ptr]
    ptr += 1

    # Handshake Length (3 bytes)
    # Unpack 3 bytes as 4 bytes integer
    hs_len_bytes = b'\x00' + data[ptr:ptr + 3]
    hs_len = struct.unpack('!I', hs_len_bytes)[0]
    ptr += 3

    print(f"[+] Handshake Type: {hs_type} (1 = Client Hello)")
    print(f"[+] Handshake Length: {hs_len} bytes")

    if hs_type != 1:
        print("[-] Not a Client Hello!")
        return

    # --- Client Hello Body ---

    # TLS Version (2 bytes)
    client_version = data[ptr:ptr + 2]
    ptr += 2
    print(f"[+] Client Version: {client_version.hex()}")

    # Client Random (32 bytes)
    client_random = data[ptr:ptr + 32]
    ptr += 32
    print(f"[+] Client Random: {client_random.hex()[:10]}... (truncated)")

    # Session ID
    session_id_len = data[ptr]
    ptr += 1

    if session_id_len > 0:
        session_id = data[ptr:ptr + session_id_len]
        ptr += session_id_len
        print(f"[+] Session ID: {session_id.hex()}")
    else:
        print("[+] Session ID: (empty)")

    # Cipher Suites
    # Length is 2 bytes
    cipher_suites_len = struct.unpack('!H', data[ptr:ptr + 2])[0]
    ptr += 2

    print(f"[+] Cipher Suites Length: {cipher_suites_len} bytes")

    # Extract the list of ciphers
    ciphers_data = data[ptr:ptr + cipher_suites_len]
    ptr += cipher_suites_len

    # Iterate over ciphers (each is 2 bytes)
    print("[*] Client supports these Ciphers (Hex):")
    for i in range(0, len(ciphers_data), 2):
        cipher = ciphers_data[i:i + 2]
        print(f"    - 0x{cipher.hex()}")

    # Compression Methods
    comp_methods_len = data[ptr]
    ptr += 1
    # Skip compression methods bytes for now
    ptr += comp_methods_len

    print(f"[+] Remaining bytes (Extensions): {len(data) - ptr}")


def start_server():
    host = '0.0.0.0'
    port = 4433

    # Create TCP Socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Allow reusing the address (avoids "Address already in use" error)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((host, port))
    server_socket.listen(1)

    print(f"[*] TLS Server listening on {host}:{port}...")

    while True:
        client_sock, addr = server_socket.accept()
        print(f"\n[*] Connection from {addr}")

        try:
            # 1. Read TLS Record Header (5 bytes)
            # Content Type (1), Version (2), Length (2)
            header = client_sock.recv(5)
            if not header:
                break

            content_type, version, length = struct.unpack('!BHH', header)

            print(f"[*] Record Header: Type={content_type} (22=Handshake), Ver=0x{version:x}, Len={length}")

            if content_type == 22:  # 0x16 = Handshake
                # 2. Read the rest of the message based on 'length'
                body = client_sock.recv(length)
                parse_client_hello(body)
            else:
                print("[-] Received non-handshake record.")

        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_sock.close()


if __name__ == "__main__":
    start_server()