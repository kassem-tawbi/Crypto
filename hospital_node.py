# hospital_node.py
# UI-ready P2P node for secure file exchange between hospitals, with detailed crypto logging.

import socket
import threading
import json
import os
import base64
import sys
import uuid
from queue import Queue
import logging
from logging.handlers import RotatingFileHandler

import crypto_utils


CONFIG = {
    "Hospital_A": {
        "host": "0.0.0.0",
        "port": 65001,
        "private_key": "Hospital_A_private.pem",
        "public_key": "Hospital_A_public.pem",
        "data_dir": "hospital_A_data",
        "received_dir": "hospital_A_received",
    },
    "Hospital_B": {
        "host": "0.0.0.0",
        "port": 65002,
        "private_key": "Hospital_B_private.pem",
        "public_key": "Hospital_B_public.pem",
        "data_dir": "hospital_B_data",
        "received_dir": "hospital_B_received",
    },
}


def get_logger(node_name: str) -> logging.Logger:
    logger = logging.getLogger(node_name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    os.makedirs("logs", exist_ok=True)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter(f"[{node_name}] %(message)s"))

    fh_path = os.path.join("logs", f"{node_name}.log")
    fh = RotatingFileHandler(
        fh_path,
        maxBytes=1_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] " + f"[{node_name}] %(message)s",
        "%Y-%m-%d %H:%M:%S",
    ))

    logger.addHandler(ch)
    logger.addHandler(fh)
    logger.propagate = False

    return logger


def _short_hex(data: bytes, length: int = 16) -> str:
    if not isinstance(data, (bytes, bytearray)):
        return str(data)
    h = data.hex()
    return (h[: 2 * length] + ("..." if len(h) > 2 * length else "")) or "∅"


def _log_crypto(logger: logging.Logger, op: str, **fields):
    parts = [op]
    for k, v in fields.items():
        parts.append(f"{k}={v}")
    logger.info(" | ".join(parts))


class ApprovalRequest:
    def __init__(self, request_id: str, requester_name: str, file_to_send: str,
                 file_path: str, requester_pub_key, node_name: str,
                 logger: logging.Logger):
        self.id = request_id
        self.requester_name = requester_name
        self.file_to_send = file_to_send
        self.file_path = file_path
        self.requester_pub_key = requester_pub_key
        self.node_name = node_name
        self.logger = logger

        self._event = threading.Event()
        self._approved = False

    def wait_for_decision(self) -> bool:
        self.logger.debug(
            f"Waiting for decision: id={self.id}, requester={self.requester_name}, file={self.file_to_send}"
        )
        self._event.wait()
        return self._approved

    def set_decision(self, approved: bool):
        self._approved = approved
        self._event.set()

    def to_dict(self):
        return {
            "id": self.id,
            "requester": self.requester_name,
            "file": self.file_to_send,
            "node": self.node_name,
        }


class HospitalNode:
    def __init__(self, my_name: str):
        if my_name not in CONFIG:
            raise ValueError(f"Unknown node name '{my_name}'. Must be one of: {list(CONFIG.keys())}")

        self.name = my_name
        self.conf = CONFIG[my_name]
        self.logger = get_logger(self.name)

        self.logger.info("Initializing node with cryptographic material...")
        self.logger.info(f"Loading private key from '{self.conf['private_key']}'...")
        self.my_private_key = crypto_utils.load_private_key(self.conf["private_key"])
        _log_crypto(self.logger, "PrivateKeyLoaded", source=self.conf["private_key"])

        self.all_public_keys = {}
        for peer_name, cfg in CONFIG.items():
            self.logger.info(f"Loading public key for {peer_name} from '{cfg['public_key']}'...")
            self.all_public_keys[peer_name] = crypto_utils.load_public_key(cfg["public_key"])
            _log_crypto(self.logger, "PublicKeyLoaded", owner=peer_name, source=cfg["public_key"])

        self._pending_lock = threading.Lock()
        self._pending_by_id = {}
        self._pending_queue: "Queue[ApprovalRequest]" = Queue()

        self._server_thread = None
        self._server_stop = threading.Event()

        os.makedirs(self.conf["data_dir"], exist_ok=True)
        os.makedirs(self.conf["received_dir"], exist_ok=True)
        self.logger.info(
            f"Directories ready: data_dir='{self.conf['data_dir']}', "
            f"received_dir='{self.conf['received_dir']}'"
        )

    # ===== Public API =====

    def start_server(self):
        if self._server_thread and self._server_thread.is_alive():
            return
        self._server_stop.clear()
        self._server_thread = threading.Thread(
            target=self._server_loop,
            name=f"{self.name}_server",
            daemon=True,
        )
        self._server_thread.start()
        self.logger.info("Background server thread started.")

    def stop_server(self):
        self._server_stop.set()
        self.logger.info("Server stop signaled.")

    def get_pending_approvals(self):
        while not self._pending_queue.empty():
            req: ApprovalRequest = self._pending_queue.get()
            with self._pending_lock:
                self._pending_by_id[req.id] = req

        with self._pending_lock:
            pending = [req.to_dict() for req in self._pending_by_id.values()]

        if pending:
            self.logger.info(f"Pending approvals count={len(pending)}")

        return pending

    def resolve_approval(self, request_id: str, approved: bool):
        with self._pending_lock:
            req = self._pending_by_id.pop(request_id, None)

        if not req:
            self.logger.warning(f"resolve_approval: no pending request id={request_id}")
            return

        decision = "APPROVED" if approved else "DENIED"
        self.logger.info(
            f"Staff {decision} request_id={request_id} from={req.requester_name} file={req.file_to_send}"
        )
        req.set_decision(approved)

    def request_record(self, target_name: str, target_ip: str,
                       target_port: int, file_name: str) -> bool:
        """
        Send a secure file request.
        Returns:
          True  = request succeeded, file received & decrypted
          False = any failure (connection, crypto, etc.)
        """
        if target_name not in self.all_public_keys:
            self.logger.error(f"Unknown target hospital '{target_name}'.")
            return False

        if target_name == self.name:
            self.logger.error("Cannot request from self.")
            return False

        if not (target_ip and file_name and isinstance(target_port, int)):
            self.logger.error("Target IP, port, and file name are required.")
            return False

        try:
            message = f"Request:{file_name}"
            _log_crypto(self.logger, "SignMessage_Start",
                        algo="RSA", hash="SHA-256",
                        message_preview=message)

            signature = crypto_utils.sign_message(message, self.my_private_key)

            _log_crypto(self.logger, "SignMessage_Done",
                        signature_len=len(signature),
                        signature_preview=_short_hex(signature))

            packet = {
                "from": self.name,
                "message": message,
                "signature": base64.b64encode(signature).decode("utf-8"),
            }

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                self.logger.info(f"Connecting to {target_name} at {target_ip}:{target_port}...")
                s.settimeout(5.0)
                s.connect((target_ip, target_port))

                self.logger.info(f"Sending secure request for '{file_name}'...")
                s.sendall(json.dumps(packet).encode("utf-8"))

                response_data = s.recv(8192)
                if not response_data:
                    self.logger.error("No response from server.")
                    return False

            # Handle plain error responses
            if (
                response_data in [
                    b"File Not Found.",
                    b"Request Denied.",
                    b"Invalid Request Format.",
                ]
                or response_data.startswith(b"Authentication Failed")
            ):
                self.logger.warning(
                    f"Server error response: {response_data.decode('utf-8')}"
                )
                return False

            self.logger.info("Encrypted package received, decoding JSON...")
            response = json.loads(response_data.decode("utf-8"))

            encrypted_keys = base64.b64decode(response["encrypted_keys"])
            iv = base64.b64decode(response["iv"])
            ciphertext = base64.b64decode(response["ciphertext"])
            hmac_tag = base64.b64decode(response["hmac"])

            _log_crypto(self.logger, "EncryptedPackage_Received",
                        enc_keys_len=len(encrypted_keys),
                        iv_hex=_short_hex(iv),
                        ciphertext_len=len(ciphertext),
                        hmac_len=len(hmac_tag),
                        hmac_preview=_short_hex(hmac_tag))

            # Decrypt session keys
            _log_crypto(self.logger, "RSA_DecryptKeys_Start",
                        algo="RSA", enc_keys_len=len(encrypted_keys))
            combined_keys = crypto_utils.rsa_decrypt(encrypted_keys, self.my_private_key)
            _log_crypto(self.logger, "RSA_DecryptKeys_Done",
                        combined_len=len(combined_keys),
                        combined_preview=_short_hex(combined_keys))

            aes_key = combined_keys[:32]
            hmac_key = combined_keys[32:]

            _log_crypto(self.logger, "SessionKeys_Derived",
                        aes_key_len=len(aes_key),
                        aes_key_preview=_short_hex(aes_key, 8),
                        hmac_key_len=len(hmac_key),
                        hmac_key_preview=_short_hex(hmac_key, 8))

            # Verify HMAC
            _log_crypto(self.logger, "HMAC_Verify_Start",
                        algo="HMAC-SHA256", ciphertext_len=len(ciphertext))
            if not crypto_utils.verify_hmac(ciphertext, hmac_key, hmac_tag):
                _log_crypto(self.logger, "HMAC_Verify_Failed", note="Tag mismatch")
                self.logger.error("HMAC verification failed.")
                return False
            _log_crypto(self.logger, "HMAC_Verify_Success", note="Integrity OK")

            # Decrypt file
            _log_crypto(self.logger, "AES_Decrypt_Start",
                        algo="AES-256-CBC",
                        ciphertext_len=len(ciphertext),
                        iv_hex=_short_hex(iv))
            decrypted_data = crypto_utils.aes_decrypt(ciphertext, aes_key, iv)
            _log_crypto(self.logger, "AES_Decrypt_Done",
                        plaintext_len=len(decrypted_data),
                        plaintext_preview=_short_hex(decrypted_data, 16))

            # Save file
            os.makedirs(self.conf["received_dir"], exist_ok=True)
            output_path = os.path.join(self.conf["received_dir"], f"RECEIVED_{file_name}")
            with open(output_path, "wb") as f:
                f.write(decrypted_data)

            self.logger.info(f"Decrypted record saved to '{output_path}'")
            return True

        except ConnectionRefusedError:
            self.logger.error(f"Connection refused. Is {target_ip}:{target_port} running?")
            return False
        except socket.timeout:
            self.logger.error(f"Connection to {target_ip}:{target_port} timed out.")
            return False
        except socket.gaierror:
            self.logger.error(f"Invalid IP/hostname: {target_ip}")
            return False
        except Exception as e:
            self.logger.exception(f"Error in request_record: {e}")
            return False

    # ===== Internal server =====

    def _server_loop(self):
        host = self.conf["host"]
        port = self.conf["port"]

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen()
            self.logger.info(f"Server listening on {host}:{port}")

            while not self._server_stop.is_set():
                try:
                    s.settimeout(1.0)
                    conn, addr = s.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                self.logger.info(f"Accepted connection from {addr}")
                t = threading.Thread(
                    target=self._handle_request_wrapper,
                    args=(conn,),
                    daemon=True,
                )
                t.start()

    def _handle_request_wrapper(self, conn: socket.socket):
        try:
            self._handle_request(conn)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle_request(self, conn: socket.socket):
        requester_name = "UNKNOWN"
        try:
            data = conn.recv(4096)
            if not data:
                return

            request = json.loads(data.decode("utf-8"))
            message = request.get("message", "")
            sig_b64 = request.get("signature", "")
            requester_name = request.get("from", "UNKNOWN")

            try:
                signature = base64.b64decode(sig_b64)
            except Exception:
                self.logger.error("Invalid signature encoding.")
                conn.sendall(b"Authentication Failed (Bad Encoding).")
                return

            _log_crypto(self.logger, "Request_Received",
                        from_hospital=requester_name,
                        message_preview=message,
                        signature_len=len(signature),
                        signature_preview=_short_hex(signature))

            requester_pub_key = self.all_public_keys.get(requester_name)
            if not requester_pub_key:
                self.logger.error(f"Unknown requester '{requester_name}'.")
                conn.sendall(b"Authentication Failed (Unknown Peer).")
                return

            _log_crypto(self.logger, "VerifySignature_Start",
                        algo="RSA", hash="SHA-256")
            if not crypto_utils.verify_signature(message, signature, requester_pub_key):
                _log_crypto(self.logger, "VerifySignature_Failed", note="Signature mismatch")
                self.logger.error("Invalid signature.")
                conn.sendall(b"Authentication Failed (Invalid Signature).")
                return
            _log_crypto(self.logger, "VerifySignature_Success", note="Requester authenticated")

            try:
                prefix, file_to_send = message.split(":", 1)
            except ValueError:
                self.logger.error("Invalid request format: missing ':'.")
                conn.sendall(b"Invalid Request Format.")
                return

            if prefix != "Request":
                self.logger.error(f"Invalid request prefix: {prefix}")
                conn.sendall(b"Invalid Request Format.")
                return

            file_to_send = file_to_send.strip()
            if not file_to_send:
                self.logger.error("Empty file name.")
                conn.sendall(b"Invalid Request Format.")
                return

            file_path = os.path.join(self.conf["data_dir"], file_to_send)
            if not os.path.exists(file_path):
                self.logger.warning(f"Requested file not found: {file_path}")
                conn.sendall(b"File Not Found.")
                return

            self.logger.info(f"Valid request for '{file_to_send}' from {requester_name}")

            request_id = str(uuid.uuid4())
            approval_req = ApprovalRequest(
                request_id=request_id,
                requester_name=requester_name,
                file_to_send=file_to_send,
                file_path=file_path,
                requester_pub_key=requester_pub_key,
                node_name=self.name,
                logger=self.logger,
            )

            self._pending_queue.put(approval_req)
            self.logger.info(
                f"Approval pending: id={request_id}, from={requester_name}, file={file_to_send}"
            )

            approved = approval_req.wait_for_decision()

            if not approved:
                self.logger.info(f"Request {request_id} denied.")
                conn.sendall(b"Request Denied.")
                return

            self.logger.info(f"Request {request_id} approved. Encrypting and sending...")

            with open(file_path, "rb") as f:
                file_data = f.read()

            _log_crypto(self.logger, "File_Read",
                        file=file_to_send,
                        size=len(file_data),
                        preview=_short_hex(file_data, 16))

            aes_key = os.urandom(32)
            hmac_key = os.urandom(32)
            _log_crypto(self.logger, "SessionKeys_Generated",
                        aes_key_len=len(aes_key),
                        aes_key_preview=_short_hex(aes_key, 8),
                        hmac_key_len=len(hmac_key),
                        hmac_key_preview=_short_hex(hmac_key, 8))

            ciphertext, iv = crypto_utils.aes_encrypt(file_data, aes_key)
            _log_crypto(self.logger, "AES_Encrypt_Done",
                        iv_hex=_short_hex(iv),
                        plaintext_len=len(file_data),
                        ciphertext_len=len(ciphertext),
                        ciphertext_preview=_short_hex(ciphertext, 16))

            hmac_tag = crypto_utils.generate_hmac(ciphertext, hmac_key)
            _log_crypto(self.logger, "HMAC_Generate_Done",
                        tag_len=len(hmac_tag),
                        tag_preview=_short_hex(hmac_tag))

            combined_keys = aes_key + hmac_key
            _log_crypto(self.logger, "RSA_EncryptKeys_Start",
                        combined_len=len(combined_keys),
                        combined_preview=_short_hex(combined_keys))
            encrypted_keys = crypto_utils.rsa_encrypt(combined_keys, requester_pub_key)
            _log_crypto(self.logger, "RSA_EncryptKeys_Done",
                        enc_keys_len=len(encrypted_keys),
                        enc_keys_preview=_short_hex(encrypted_keys))

            response = {
                "encrypted_keys": base64.b64encode(encrypted_keys).decode("utf-8"),
                "iv": base64.b64encode(iv).decode("utf-8"),
                "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
                "hmac": base64.b64encode(hmac_tag).decode("utf-8"),
            }

            conn.sendall(json.dumps(response).encode("utf-8"))
            self.logger.info(
                f"Secure package for '{file_to_send}' sent to {requester_name}."
            )

        except Exception as e:
            self.logger.exception(f"Error handling request: {e}")
        finally:
            self.logger.info(f"Connection from {requester_name} closed.")
            try:
                conn.close()
            except Exception:
                pass


# CLI harness omitted for brevity; keep it or remove it as you like.
if __name__ == "__main__":
    print("Run via hospital_webui.py or your own harness.")
