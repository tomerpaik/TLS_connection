import struct
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

"""
Contains additional functions for server.py - Protocol Handling
"""

SERVER_PREFERRED_CIPHERS = [0xc02f] # 0xC02F = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
#SERVER_PREFERRED_CIPHERS = [0x002f] # TLS_RSA_WITH_AES_128_CBC_SHA

def parse_client_hello(data):
    """
    Parses the full Client Hello packet.
    Prints all details and returns necessary data for the handshake.
    """
    # --- 1. Handshake Header ---
    ptr = 0
    hs_type = data[ptr]
    ptr += 1

    hs_len_bytes = b'\x00' + data[ptr:ptr + 3]
    hs_len = struct.unpack('!I', hs_len_bytes)[0]
    ptr += 3

    print(f"[+] Handshake Type: {hs_type} (1 = Client Hello)")
    print(f"[+] Handshake Length: {hs_len} bytes")

    # --- 2. Client Hello Body ---
    client_version = data[ptr:ptr + 2]
    ptr += 2
    print(f"[+] Client Version: 0x{client_version.hex()}")

    client_random = data[ptr:ptr + 32]
    ptr += 32
    print(f"[+] Client Random: {client_random.hex()[:10]}... (truncated)")

    session_id_len = data[ptr]
    ptr += 1

    session_id = b''
    if session_id_len > 0:
        session_id = data[ptr:ptr + session_id_len]
        ptr += session_id_len
        print(f"[+] Session ID: {session_id.hex()}")
    else:
        print("[+] Session ID: (empty)")

    cipher_suites_len = struct.unpack('!H', data[ptr:ptr + 2])[0]
    ptr += 2
    print(f"[+] Cipher Suites Length: {cipher_suites_len}")

    ciphers_data = data[ptr: ptr + cipher_suites_len]
    ptr += cipher_suites_len

    client_ciphers = []
    print("[*] Client supports these Ciphers (Hex):")
    for i in range(0, len(ciphers_data), 2):
        # Unpack returns an int (tuple)
        c_code = struct.unpack('!H', ciphers_data[i: i + 2])[0]
        print(f"    - 0x{c_code:04x}")
        client_ciphers.append(c_code)

    print(f"[+] Parsed {len(client_ciphers)} ciphers from client.")

    comp_len = data[ptr]
    ptr += 1
    ptr += comp_len  # Skip compression bytes

    print(f"[+] Ignored Compression & Extensions ({len(data) - ptr} bytes remaining)")

    # Return only what we need for the Server Hello logic
    return session_id, client_ciphers, client_random

def build_server_hello(session_id, server_random, chosen_cipher_int):
    """Constructs the Server Hello binary packet"""

    # --- 1. Server Hello Body ---
    # Version: TLS 1.2 (0x0303)
    server_version = bytes.fromhex("0303")

    # Session ID: Echo back what client sent (or empty)
    s_id_part = bytes([len(session_id)]) + session_id

    # Cipher Suite: The one we selected
    cipher_suite = struct.pack("!H", chosen_cipher_int)

    # Compression: Null (0x00)
    compression = bytes.fromhex("00")

    body = server_version + server_random + s_id_part + cipher_suite + compression

    # --- 2. Handshake Header ---
    # Type 0x02 = Server Hello
    msg_type = bytes.fromhex("02")
    msg_len = struct.pack("!I", len(body))[1:]  # 3 bytes length
    handshake_msg = msg_type + msg_len + body

    # --- 3. Record Header ---
    # Type 0x16 = Handshake
    rec_type = bytes.fromhex("16")
    rec_ver = bytes.fromhex("0303")
    rec_len = struct.pack("!H", len(handshake_msg))

    return rec_type + rec_ver + rec_len + handshake_msg

def build_certificate_message():
    """Reads server.der and builds the Certificate handshake message"""

    # 1. Read the raw certificate file (DER format)
    try:
        with open("server.der", "rb") as f:
            cert_data = f.read()
    except FileExistsError:
        print("[-] Error: server.der not found! Run the OpenSSL/Python generation script first.")
        return None

    # 2. Build Length Fields (TLS uses 3-byte integers for these)
    l3_len = struct.pack("!I", len(cert_data))[1:]
    total_certs_len = len(cert_data) + 3

    l2_len = struct.pack("!I", total_certs_len)[1:]
    cert_body = l2_len + l3_len + cert_data

    msg_type = bytes.fromhex("0b")
    msg_len = struct.pack("!I", len(cert_body))[1:]
    handshake_msg = msg_type + msg_len + cert_body

    rec_type = bytes.fromhex("16")  # Handshake
    rec_ver = bytes.fromhex("0303")  # TLS 1.2
    rec_len = struct.pack("!H", len(handshake_msg))

    return rec_type + rec_ver + rec_len + handshake_msg


def build_server_key_exchange(client_random, server_random, ephemeral_pub_key_bytes, rsa_private_key):
    """
    Builds the Server Key Exchange packet (Critical for ECDHE).
    Constructs the curve parameters and SIGNS them with the RSA private key.
    """

    # --- 1. Construct ServerECDHParams ---
    # Curve Type: Named Curve (3)
    curve_type = bytes([3])
    # Named Curve: secp256r1 (0x0017)
    named_curve = bytes.fromhex("0017")
    # Public Key Length (1 byte)
    pub_key_len = bytes([len(ephemeral_pub_key_bytes)])

    # The actual parameters block
    server_params = curve_type + named_curve + pub_key_len + ephemeral_pub_key_bytes

    # --- 2. Create the Signature ---
    # The signature covers: ClientRandom + ServerRandom + ServerParams
    data_to_sign = client_random + server_random + server_params

    # Sign using SHA256 and RSA (using the static server.key)
    signature = rsa_private_key.sign(
        data_to_sign,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # --- 3. Construct the DigitallySigned struct ---
    # Hash Algorithm: SHA256 (4), Signature Algorithm: RSA (1) -> 0x0401
    sig_algorithm = bytes.fromhex("0401")
    # Signature Length (2 bytes)
    sig_len = struct.pack("!H", len(signature))

    # Combine everything
    body = server_params + sig_algorithm + sig_len + signature

    # --- 4. Add Handshake & Record Headers ---
    # Type 0x0c = Server Key Exchange
    msg_type = bytes.fromhex("0c")
    msg_len = struct.pack("!I", len(body))[1:]
    handshake_msg = msg_type + msg_len + body

    rec_type = bytes.fromhex("16")
    rec_ver = bytes.fromhex("0303")
    rec_len = struct.pack("!H", len(handshake_msg))

    return rec_type + rec_ver + rec_len + handshake_msg

def build_server_hello_done():
    """
    Builds the Server Hello Done message (Empty handshake message)
    """
    # --- Handshake Header ---
    # Type 0x0e = Server Hello Done
    msg_type = bytes.fromhex("0e")
    # Length: 0 bytes (no body)
    msg_len = bytes.fromhex("000000")

    handshake_msg = msg_type + msg_len

    # --- Record Header ---
    rec_type = bytes.fromhex("16")  # Handshake
    rec_ver = bytes.fromhex("0303")  # TLS 1.2
    rec_len = struct.pack("!H", len(handshake_msg))

    return rec_type + rec_ver + rec_len + handshake_msg