# hospital_node.py
# A full P2P node that can send and receive.
import socket
import threading
import json
import os
import base64
import sys
import crypto_utils

# --- Configuration ---

CONFIG = {
    'Hospital_A': {
        'host': '127.0.0.1',
        'port': 65001,
        'private_key': 'Hospital_A_private.pem',
        'public_key': 'Hospital_A_public.pem',
        'data_dir': 'hospital_A_data',
        'received_dir': 'hospital_A_received'
    },
    'Hospital_B': {
        'host': '127.0.0.1',
        'port': 65002,
        'private_key': 'Hospital_B_private.pem',
        'public_key': 'Hospital_B_public.pem',
        'data_dir': 'hospital_B_data',
        'received_dir': 'hospital_B_received'
    }
}
# ---------------------

# Global dictionary to hold all loaded public keys
ALL_PUBLIC_KEYS = {}


def log(node_name, message):
    """Helper for logging with the node's name."""
    print(f"[{node_name}] {message}")

# SERVER COMPONENT (Runs in a background thread)

def handle_request(conn, my_name, my_priv_key):
    """Handles an incoming request from another peer."""
    try:
        data = conn.recv(4096)
        if not data:
            return

        request = json.loads(data.decode('utf-8'))
        message = request['message']
        signature = base64.b64decode(request['signature'])
        requester_name = request['from']

        log(my_name, f"Received request from {requester_name} for: {message}")

        # 1. Authentication: Verify the signature
        requester_pub_key = ALL_PUBLIC_KEYS.get(requester_name)
        if not requester_pub_key:
            log(my_name, f"FAILURE: Unknown requester {requester_name}.")
            conn.sendall(b"Authentication Failed (Unknown Peer).")
            return

        if crypto_utils.verify_signature(message, signature, requester_pub_key):
            log(my_name, "SUCCESS: Requester signature is valid (Authenticated).")
        else:
            log(my_name, "FAILURE: Invalid signature. Closing connection.")
            conn.sendall(b"Authentication Failed (Invalid Signature).")
            return

        # 2. Authorization (Manual Approval)
        file_to_send = message.split(':')[1].strip()
        file_path = os.path.join(CONFIG[my_name]['data_dir'], file_to_send)

        if not os.path.exists(file_path):
            log(my_name, f"File not found: {file_path}")
            conn.sendall(b"File Not Found.")
            return

        # NOTE: We print to the console, so the user must approve it
        approval = input(f"\n[SERVER INPUT] Approve request from {requester_name} for {file_to_send}? (y/n): ").lower()

        if approval != 'y':
            log(my_name, "Request denied by staff.")
            conn.sendall(b"Request Denied.")
            return

        # 3. Prepare Secure Package (Encryption, Integrity, Key Exchange)
        log(my_name, "Request approved. Preparing secure package...")
        with open(file_path, 'rb') as f:
            file_data = f.read()

        aes_key = os.urandom(32)
        hmac_key = os.urandom(32)

        ciphertext, iv = crypto_utils.aes_encrypt(file_data, aes_key)
        hmac_tag = crypto_utils.generate_hmac(ciphertext, hmac_key)

        # Encrypt symmetric keys with the *requester's* public key
        combined_keys = aes_key + hmac_key
        encrypted_keys = crypto_utils.rsa_encrypt(combined_keys, requester_pub_key)

        # 4. Send the secure package back
        response = {
            'encrypted_keys': base64.b64encode(encrypted_keys).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'hmac': base64.b64encode(hmac_tag).decode('utf-8')
        }

        conn.sendall(json.dumps(response).encode('utf-8'))
        log(my_name, f"Secure package for {file_to_send} sent to {requester_name}.")

    except Exception as e:
        log(my_name, f"Error handling request: {e}")
    finally:
        conn.close()
        log(my_name, f"Connection from {requester_name} closed.")


def start_server_loop(my_name, my_config, my_priv_key):
    """The main loop for the server thread."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Server binds to its OWN configured host and port
        s.bind((my_config['host'], my_config['port']))
        s.listen()
        log(my_name, f"Server listening on {my_config['host']}:{my_config['port']}...")

        while True:
            try:
                conn, addr = s.accept()
                log(my_name, f"Accepted connection from {addr}")
                # Handle each request in its own thread
                handler_thread = threading.Thread(
                    target=handle_request,
                    args=(conn, my_name, my_priv_key)
                )
                handler_thread.start()
            except Exception as e:
                log(my_name, f"Server loop error: {e}")
                break


# CLIENT COMPONENT (Runs in the main thread)


def request_record(my_name, my_priv_key, my_received_dir, target_name, target_ip, target_port, file_name):
    """
    The main function for sending a request.
    It now takes target_ip and target_port directly.
    """

    # We still need the target_name to find their public key
    target_public_key = ALL_PUBLIC_KEYS.get(target_name)
    if not target_public_key:
        log(my_name, f"Error: Unknown hospital name '{target_name}'. Cannot find public key.")
        return

    try:
        # 1. Create the secure request
        message = f"Request:{file_name}"
        # Sign with our private key
        signature = crypto_utils.sign_message(message, my_priv_key)

        request_packet = {
            'from': my_name,  # This is crucial for the server to verify us
            'message': message,
            'signature': base64.b64encode(signature).decode('utf-8')
        }

        # 2. Connect and send the request
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            log(my_name, f"Connecting to {target_name} at {target_ip}:{target_port}...")
            # *** MODIFIED: Connect to the user-provided IP and port ***
            s.connect((target_ip, target_port))

            log(my_name, f"Sending secure request for {file_name}...")
            s.sendall(json.dumps(request_packet).encode('utf-8'))

            # 3. Wait for and receive the response
            response_data = s.recv(8192)  # Increase buffer for file
            if not response_data:
                log(my_name, "Connection closed by server.")
                return

            if response_data in [b"Authentication Failed.", b"File Not Found.", b"Request Denied.",
                                 b"Authentication Failed (Invalid Signature).",
                                 b"Authentication Failed (Unknown Peer)."]:
                log(my_name, f"Server responded with error: {response_data.decode('utf-8')}")
                return

            log(my_name, "Received secure package from server.")
            response = json.loads(response_data.decode('utf-8'))

            # 4. Unpack and Decrypt the Package
            encrypted_keys = base64.b64decode(response['encrypted_keys'])
            iv = base64.b64decode(response['iv'])
            ciphertext = base64.b64decode(response['ciphertext'])
            hmac_tag = base64.b64decode(response['hmac'])

            # Decrypt symmetric keys with our private key
            combined_keys = crypto_utils.rsa_decrypt(encrypted_keys, my_priv_key)
            aes_key = combined_keys[:32]
            hmac_key = combined_keys[32:]

            log(my_name, "SUCCESS: Session keys decrypted (RSA).")

            # Verify the HMAC
            if crypto_utils.verify_hmac(ciphertext, hmac_key, hmac_tag):
                log(my_name, "SUCCESS: Data integrity verified (HMAC-SHA256).")
            else:
                log(my_name, "FAILURE: HMAC verification failed! Data may be tampered.")
                return

            # Decrypt the file data
            decrypted_data = crypto_utils.aes_decrypt(ciphertext, aes_key, iv)
            log(my_name, "SUCCESS: File decrypted (AES-256).")

            # 5. Save the final record
            output_path = f"{my_received_dir}/RECEIVED_{file_name}"
            with open(output_path, "wb") as f:
                f.write(decrypted_data)

            log(my_name, f"Successfully received and saved record to {output_path}")
            print("\n--- DECRYPTED CONTENT ---")
            print(decrypted_data.decode('utf-8'))
            print("-------------------------")

    except ConnectionRefusedError:
        log(my_name, f"Error: Connection refused. Is the server at {target_ip}:{target_port} running?")
    except socket.gaierror:
        log(my_name, f"Error: Invalid IP address or hostname '{target_ip}'.")
    except Exception as e:
        log(my_name, f"An error occurred: {e}")


# MAIN PROGRAM


def main():
    # --- Identity Setup ---
    if len(sys.argv) < 2 or sys.argv[1] not in CONFIG:
        print("Usage: python hospital_node.py [Hospital_A | Hospital_B]")
        print("Please specify which hospital this node is.")
        sys.exit(1)

    MY_NAME = sys.argv[1]
    MY_CONFIG = CONFIG[MY_NAME]

    log(MY_NAME, "Starting node...")

    # --- Load Keys ---
    log(MY_NAME, "Loading my private key...")
    my_private_key = crypto_utils.load_private_key(MY_CONFIG['private_key'])

    log(MY_NAME, "Loading all public keys (keychain)...")
    for name, conf in CONFIG.items():
        ALL_PUBLIC_KEYS[name] = crypto_utils.load_public_key(conf['public_key'])

    # --- Start Server Thread ---
    # This thread listens for INCOMING requests
    server_thread = threading.Thread(
        target=start_server_loop,
        args=(MY_NAME, MY_CONFIG, my_private_key),
        daemon=True
    )
    server_thread.start()

    # --- Client User Interface (Main Thread) ---
    # This loop sends OUTGOING requests
    while True:
        print("\n" + "=" * 30)
        print(f"Hospital {MY_NAME} - P2P Client")
        print("1. Request a file from another hospital")
        print("2. Quit")
        choice = input("Enter your choice (1-2): ")

        if choice == '1':
            # *** MODIFIED: Ask for Name (for key) and IP/Port (for connection) ***
            target_name = input("Enter target hospital's NAME (e.g., Hospital_B): ")

            # Check if we have the public key for this hospital
            if target_name not in ALL_PUBLIC_KEYS:
                log(MY_NAME, f"Error: No public key found for '{target_name}'. Check CONFIG.")
                continue

            if target_name == MY_NAME:
                log(MY_NAME, "Cannot request a file from yourself.")
                continue

            target_ip = input(f"Enter IP address for {target_name}: ")
            try:
                target_port = int(input(f"Enter PORT for {target_name}: "))
            except ValueError:
                log(MY_NAME, "Error: Port must be a number.")
                continue

            file_name = input("Enter file name to request (e.g., patient_123.txt): ")

            if target_name and target_ip and target_port and file_name:
                request_record(
                    MY_NAME,
                    my_private_key,
                    MY_CONFIG['received_dir'],
                    target_name,  # The ID (for the key)
                    target_ip,  # The network location
                    target_port,  # The network port
                    file_name
                )
            else:
                log(MY_NAME, "Invalid input. All fields are required.")

        elif choice == '2':
            log(MY_NAME, "Shutting down...")
            break

        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    main()
