# hospital_node.py
# P2P node that can send and receive files securely between two hospitals.

import socket
import threading
import json
import os
import base64
import sys

import crypto_utils

# === Configuration ===
# IMPORTANT:
# - 'host' is where THIS node listens (bind address).
# - For real machines, use "0.0.0.0" or the machine's local IP.
# - Ports must be reachable between the two machines (firewall/router must allow).
CONFIG = {
    "Hospital_A": {
        "host": "0.0.0.0",                 # Listen on all interfaces on Machine A
        "port": 65001,
        "private_key": "Hospital_A_private.pem",
        "public_key": "Hospital_A_public.pem",
        "data_dir": "hospital_A_data",
        "received_dir": "hospital_A_received",
    },
    "Hospital_B": {
        "host": "0.0.0.0",                 # Listen on all interfaces on Machine B
        "port": 65002,
        "private_key": "Hospital_B_private.pem",
        "public_key": "Hospital_B_public.pem",
        "data_dir": "hospital_B_data",
        "received_dir": "hospital_B_received",
    },
}

# Global dictionary to hold all loaded public keys
ALL_PUBLIC_KEYS = {}


def log(node_name: str, message: str):
    print(f"[{node_name}] {message}")


# ========== SERVER SIDE ==========

def handle_request(conn: socket.socket, my_name: str, my_priv_key):
    """Handle an incoming request from another peer."""
    requester_name = "UNKNOWN"
    try:
        data = conn.recv(4096)
        if not data:
            return

        request = json.loads(data.decode("utf-8"))
        message = request["message"]
        signature = base64.b64decode(request["signature"])
        requester_name = request["from"]

        log(my_name, f"Received request from {requester_name} for: {message}")

        # 1. Authentication: verify signature
        requester_pub_key = ALL_PUBLIC_KEYS.get(requester_name)
        if not requester_pub_key:
            log(my_name, f"FAILURE: Unknown requester {requester_name}.")
            conn.sendall(b"Authentication Failed (Unknown Peer).")
            return

        if not crypto_utils.verify_signature(message, signature, requester_pub_key):
            log(my_name, "FAILURE: Invalid signature. Closing connection.")
            conn.sendall(b"Authentication Failed (Invalid Signature).")
            return

        log(my_name, "SUCCESS: Requester signature is valid (Authenticated).")

        # 2. Authorization: manual approval
        try:
            _, file_to_send = message.split(":", 1)
            file_to_send = file_to_send.strip()
        except ValueError:
            log(my_name, "Invalid request format.")
            conn.sendall(b"Invalid Request Format.")
            return

        file_path = os.path.join(CONFIG[my_name]["data_dir"], file_to_send)
        if not os.path.exists(file_path):
            log(my_name, f"File not found: {file_path}")
            conn.sendall(b"File Not Found.")
            return

        approval = input(
            f"\n[SERVER INPUT] Approve request from {requester_name} "
            f"for {file_to_send}? (y/n): "
        ).lower()

        if approval != "y":
            log(my_name, "Request denied by staff.")
            conn.sendall(b"Request Denied.")
            return

        # 3. Prepare secure package
        log(my_name, "Request approved. Preparing secure package...")

        with open(file_path, "rb") as f:
            file_data = f.read()

        aes_key = os.urandom(32)
        hmac_key = os.urandom(32)

        ciphertext, iv = crypto_utils.aes_encrypt(file_data, aes_key)
        hmac_tag = crypto_utils.generate_hmac(ciphertext, hmac_key)

        # Encrypt AES+HMAC keys with requester public key
        combined_keys = aes_key + hmac_key
        encrypted_keys = crypto_utils.rsa_encrypt(combined_keys, requester_pub_key)

        # 4. Send JSON package
        response = {
            "encrypted_keys": base64.b64encode(encrypted_keys).decode("utf-8"),
            "iv": base64.b64encode(iv).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "hmac": base64.b64encode(hmac_tag).decode("utf-8"),
        }

        conn.sendall(json.dumps(response).encode("utf-8"))
        log(my_name, f"Secure package for {file_to_send} sent to {requester_name}.")

    except Exception as e:
        log(my_name, f"Error handling request: {e}")
    finally:
        conn.close()
        log(my_name, f"Connection from {requester_name} closed.")


def start_server_loop(my_name: str, my_config: dict, my_priv_key):
    """Background server loop: listens for incoming connections."""
    # Ensure dirs exist
    os.makedirs(my_config["data_dir"], exist_ok=True)
    os.makedirs(my_config["received_dir"], exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((my_config["host"], my_config["port"]))
        s.listen()
        log(my_name, f"Server listening on {my_config['host']}:{my_config['port']}")

        while True:
            try:
                conn, addr = s.accept()
                log(my_name, f"Accepted connection from {addr}")
                threading.Thread(
                    target=handle_request,
                    args=(conn, my_name, my_priv_key),
                    daemon=True,
                ).start()
            except Exception as e:
                log(my_name, f"Server loop error: {e}")
                break


# ========== CLIENT SIDE ==========

def request_record(
    my_name: str,
    my_priv_key,
    my_received_dir: str,
    target_name: str,
    target_ip: str,
    target_port: int,
    file_name: str,
):
    """Send a secure file request to another hospital."""
    target_public_key = ALL_PUBLIC_KEYS.get(target_name)
    if not target_public_key:
        log(my_name, f"Error: Unknown hospital '{target_name}'.")
        return

    try:
        # 1. Create and sign request
        message = f"Request:{file_name}"
        signature = crypto_utils.sign_message(message, my_priv_key)

        request_packet = {
            "from": my_name,
            "message": message,
            "signature": base64.b64encode(signature).decode("utf-8"),
        }

        # 2. Connect to target (real IP/port)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            log(my_name, f"Connecting to {target_name} at {target_ip}:{target_port}...")
            s.connect((target_ip, target_port))

            log(my_name, f"Sending secure request for {file_name}...")
            s.sendall(json.dumps(request_packet).encode("utf-8"))

            # 3. Receive response
            response_data = s.recv(8192)
            if not response_data:
                log(my_name, "Connection closed by server.")
                return

        if response_data.startswith(b"Authentication Failed") or \
           response_data in [b"File Not Found.", b"Request Denied.", b"Invalid Request Format."]:
            log(my_name, f"Server responded with error: {response_data.decode('utf-8')}")
            return

        log(my_name, "Received secure package from server.")
        response = json.loads(response_data.decode("utf-8"))

        # 4. Unpack
        encrypted_keys = base64.b64decode(response["encrypted_keys"])
        iv = base64.b64decode(response["iv"])
        ciphertext = base64.b64decode(response["ciphertext"])
        hmac_tag = base64.b64decode(response["hmac"])

        # Decrypt keys
        combined_keys = crypto_utils.rsa_decrypt(encrypted_keys, my_priv_key)
        aes_key = combined_keys[:32]
        hmac_key = combined_keys[32:]
        log(my_name, "SUCCESS: Session keys decrypted (RSA).")

        # Verify HMAC
        if not crypto_utils.verify_hmac(ciphertext, hmac_key, hmac_tag):
            log(my_name, "FAILURE: HMAC verification failed. Aborting.")
            return

        log(my_name, "SUCCESS: Data integrity verified (HMAC-SHA256).")

        # Decrypt file
        decrypted_data = crypto_utils.aes_decrypt(ciphertext, aes_key, iv)
        log(my_name, "SUCCESS: File decrypted (AES-256).")

        # 5. Save
        os.makedirs(my_received_dir, exist_ok=True)
        output_path = os.path.join(my_received_dir, f"RECEIVED_{file_name}")
        with open(output_path, "wb") as f:
            f.write(decrypted_data)

        log(my_name, f"Saved record to {output_path}")
        print("\n--- DECRYPTED CONTENT ---")
        try:
            print(decrypted_data.decode("utf-8"))
        except UnicodeDecodeError:
            print("[Binary data]")
        print("-------------------------")

    except ConnectionRefusedError:
        log(my_name, f"Connection refused. Is {target_ip}:{target_port} running?")
    except socket.gaierror:
        log(my_name, f"Invalid IP/hostname: {target_ip}")
    except Exception as e:
        log(my_name, f"An error occurred: {e}")


# ========== MAIN ==========

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in CONFIG:
        print("Usage: python hospital_node.py [Hospital_A | Hospital_B]")
        sys.exit(1)

    my_name = sys.argv[1]
    my_conf = CONFIG[my_name]

    log(my_name, "Starting node...")

    # Load my private key
    log(my_name, "Loading my private key...")
    my_private_key = crypto_utils.load_private_key(my_conf["private_key"])

    # Load all public keys
    log(my_name, "Loading all public keys...")
    for name, conf in CONFIG.items():
        ALL_PUBLIC_KEYS[name] = crypto_utils.load_public_key(conf["public_key"])

    # Start server thread
    server_thread = threading.Thread(
        target=start_server_loop,
        args=(my_name, my_conf, my_private_key),
        daemon=True,
    )
    server_thread.start()

    # Simple client menu
    while True:
        print("\n" + "=" * 30)
        print(f"Hospital {my_name} - P2P Client")
        print("1. Request a file from another hospital")
        print("2. Quit")

        choice = input("Enter your choice (1-2): ").strip()

        if choice == "1":
            target_name = input("Target hospital NAME (e.g., Hospital_B): ").strip()

            if target_name not in ALL_PUBLIC_KEYS:
                log(my_name, f"No public key for '{target_name}'. Check CONFIG.")
                continue

            if target_name == my_name:
                log(my_name, "Cannot request from yourself.")
                continue

            target_ip = input(f"IP address for {target_name}: ").strip()
            try:
                target_port = int(input(f"PORT for {target_name}: ").strip())
            except ValueError:
                log(my_name, "Port must be a number.")
                continue

            file_name = input("File name to request (e.g., patient_123.txt): ").strip()

            if not (target_ip and target_port and file_name):
                log(my_name, "All fields are required.")
                continue

            request_record(
                my_name,
                my_private_key,
                my_conf["received_dir"],
                target_name,
                target_ip,
                target_port,
                file_name,
            )

        elif choice == "2":
            log(my_name, "Shutting down...")
            break
        else:
            print("Invalid choice, try again.")


if __name__ == "__main__":
    main()
