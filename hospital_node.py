# hospital_node.py
# UI-ready P2P node for secure file exchange between hospitals,
# with detailed crypto logging and MongoDB-backed registry.

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

from cryptography.hazmat.primitives import serialization

from registry import register_hospital, get_hospital
import crypto_utils


CONFIG = {
    "Hospital_A": {
        "host": "0.0.0.0",
        "port": 65001,
        "sign_private_key": "Hospital_A_sign_private.pem",
        "enc_private_key": "Hospital_A_enc_private.pem",
        "data_dir": "hospital_A_data",
        "received_dir": "hospital_A_received",
        # optional: "public_host": "public-ip-or-dns"
    },
    "Hospital_B": {
        "host": "0.0.0.0",
        "port": 65002,
        "sign_private_key": "Hospital_B_sign_private.pem",
        "enc_private_key": "Hospital_B_enc_private.pem",
        "data_dir": "hospital_B_data",
        "received_dir": "hospital_B_received",
        # optional: "public_host": "public-ip-or-dns"
    },
}


def get_logger(node_name: str) -> logging.Logger:
    logger = logging.getLogger(node_name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # Ensure logs directory exists
    os.makedirs("logs", exist_ok=True)

    # --- FRESH LOGS PER RUN -----------------------------------
    # If a previous log file exists for this node, delete it so
    # every new process starts with an empty log file.
    log_path = os.path.join("logs", f"{node_name}.log")
    if os.path.exists(log_path):
        try:
            os.remove(log_path)
        except OSError:
            # If deletion fails for some reason, we just overwrite via handler
            pass
    # -----------------------------------------------------------

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter(f"[{node_name}] %(message)s"))

    # File handler (will create a fresh file because we removed the old one)
    fh = RotatingFileHandler(
        log_path,
        maxBytes=1_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] " + f"[{node_name}] %(message)s",
            "%Y-%m-%d %H:%M:%S",
        )
    )

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
    def __init__(
        self,
        request_id: str,
        requester_name: str,
        file_to_send: str,
        file_path: str,
        node_name: str,
        logger: logging.Logger,
    ):
        self.id = request_id
        self.requester_name = requester_name
        self.file_to_send = file_to_send
        self.file_path = file_path
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
    def __init__(self, my_name: str, public_host: str | None = None):
        if my_name not in CONFIG:
            raise ValueError(
                f"Unknown node name '{my_name}'. Must be one of: {list(CONFIG.keys())}"
            )

        self.name = my_name
        self.conf = CONFIG[my_name]
        self.public_host = public_host
        self.logger = get_logger(self.name)

        self.logger.info("Initializing node with cryptographic material...")

        # --- Load SIGNING private key ---
        self.logger.info(
            f"Loading SIGNING private key from '{self.conf['sign_private_key']}'..."
        )
        self.sign_private_key = crypto_utils.load_private_key(
            self.conf["sign_private_key"]
        )
        _log_crypto(
            self.logger,
            "SignPrivateKeyLoaded",
            source=self.conf["sign_private_key"],
        )

        # --- Load ENCRYPTION private key ---
        self.logger.info(
            f"Loading ENCRYPTION private key from '{self.conf['enc_private_key']}'..."
        )
        self.enc_private_key = crypto_utils.load_private_key(
            self.conf["enc_private_key"]
        )
        _log_crypto(
            self.logger,
            "EncPrivateKeyLoaded",
            source=self.conf["enc_private_key"],
        )

        # --- Derive our public keys (PEM) from private keys ---
        self.sign_public_pem: bytes = self.sign_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.enc_public_pem: bytes = self.enc_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        _log_crypto(
            self.logger,
            "SignPublicKeyDerived",
            length=len(self.sign_public_pem),
        )
        _log_crypto(
            self.logger,
            "EncPublicKeyDerived",
            length=len(self.enc_public_pem),
        )

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

        # Register / update this hospital's network info in the central registry
        self._register_self_in_registry()

    # ===== Registry helpers =====

    def _get_public_host(self) -> str:
        """
        Decide what hostname/IP we publish in the registry so others can reach us.
        Priority:
          1) explicit public_host passed to ctor
          2) PUBLIC_HOST env var
          3) 'public_host' in CONFIG entry
          4) listening host from CONFIG
        """
        return (
            self.public_host
            or os.getenv("PUBLIC_HOST")
            or self.conf.get("public_host")
            or self.conf["host"]
        )

    def _register_self_in_registry(self):
        public_host = self._get_public_host()
        public_port = self.conf["port"]

        try:
            sign_pem_str = self.sign_public_pem.decode("utf-8")
            enc_pem_str = self.enc_public_pem.decode("utf-8")

            register_hospital(
                self.name,
                public_host,
                public_port,
                sign_pub_pem=sign_pem_str,
                enc_pub_pem=enc_pem_str,
            )
            self.logger.info(
                f"Registry updated for {self.name}: host={public_host}, "
                f"port={public_port}"
            )
        except Exception as e:
            # If this fails, the node still runs, but others won't discover it by name.
            self.logger.error(f"Failed to register hospital in registry: {e}")

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
            f"Staff {decision} request_id={request_id} from={req.requester_name} "
            f"file={req.file_to_send}"
        )
        req.set_decision(approved)

    def request_record(self, target_name: str, file_name: str) -> bool:
        """
        Send a secure file request to another hospital identified by NAME only.
        Host/port and public keys are resolved from the MongoDB registry.

        Returns:
          True  = request succeeded, file received & decrypted
          False = any failure (registry, connection, crypto, etc.)
        """
        if target_name == self.name:
            self.logger.error("Cannot request from self.")
            return False

        # Look up target connection info in Mongo/registry
        try:
            entry = get_hospital(target_name)
        except Exception as e:
            self.logger.error(f"Failed to query registry for '{target_name}': {e}")
            return False

        if not entry:
            self.logger.error(f"Unknown target hospital '{target_name}' in registry.")
            return False

        target_ip = entry.get("p2p_host")
        target_port = entry.get("p2p_port")

        if not target_ip or target_port is None:
            self.logger.error(
                f"Registry entry for '{target_name}' is missing host/port fields."
            )
            return False

        try:
            target_port = int(target_port)
        except Exception:
            self.logger.error(
                f"Registry entry for '{target_name}' has invalid port value: "
                f"{target_port!r}"
            )
            return False

        if not file_name:
            self.logger.error("File name is required.")
            return False

        try:
            message = f"Request:{file_name}"
            _log_crypto(
                self.logger,
                "SignMessage_Start",
                algo="RSA",
                hash="SHA-256",
                message_preview=message,
            )

            signature = crypto_utils.sign_message(message, self.sign_private_key)

            _log_crypto(
                self.logger,
                "SignMessage_Done",
                signature_len=len(signature),
                signature_preview=_short_hex(signature),
            )

            packet = {
                "from": self.name,
                "message": message,
                "signature": base64.b64encode(signature).decode("utf-8"),
            }

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                self.logger.info(
                    f"Connecting to {target_name} at {target_ip}:{target_port}..."
                )
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

            _log_crypto(
                self.logger,
                "EncryptedPackage_Received",
                enc_keys_len=len(encrypted_keys),
                iv_hex=_short_hex(iv),
                ciphertext_len=len(ciphertext),
                hmac_len=len(hmac_tag),
                hmac_preview=_short_hex(hmac_tag),
            )

            # Decrypt session keys (we are the receiver, so use our ENC private key)
            _log_crypto(
                self.logger,
                "RSA_DecryptKeys_Start",
                algo="RSA",
                enc_keys_len=len(encrypted_keys),
            )
            combined_keys = crypto_utils.rsa_decrypt(
                encrypted_keys, self.enc_private_key
            )
            _log_crypto(
                self.logger,
                "RSA_DecryptKeys_Done",
                combined_len=len(combined_keys),
                combined_preview=_short_hex(combined_keys),
            )

            aes_key = combined_keys[:32]
            hmac_key = combined_keys[32:]

            _log_crypto(
                self.logger,
                "SessionKeys_Derived",
                aes_key_len=len(aes_key),
                aes_key_preview=_short_hex(aes_key, 8),
                hmac_key_len=len(hmac_key),
                hmac_key_preview=_short_hex(hmac_key, 8),
            )

            # Verify HMAC
            _log_crypto(
                self.logger,
                "HMAC_Verify_Start",
                algo="HMAC-SHA256",
                ciphertext_len=len(ciphertext),
            )
            if not crypto_utils.verify_hmac(ciphertext, hmac_key, hmac_tag):
                _log_crypto(
                    self.logger,
                    "HMAC_Verify_Failed",
                    note="Tag mismatch",
                )
                self.logger.error("HMAC verification failed.")
                return False
            _log_crypto(
                self.logger,
                "HMAC_Verify_Success",
                note="Integrity OK",
            )

            # Decrypt file
            _log_crypto(
                self.logger,
                "AES_Decrypt_Start",
                algo="AES-256-CBC",
                ciphertext_len=len(ciphertext),
                iv_hex=_short_hex(iv),
            )
            decrypted_data = crypto_utils.aes_decrypt(ciphertext, aes_key, iv)
            _log_crypto(
                self.logger,
                "AES_Decrypt_Done",
                plaintext_len=len(decrypted_data),
                plaintext_preview=_short_hex(decrypted_data, 16),
            )

            # Save file
            os.makedirs(self.conf["received_dir"], exist_ok=True)
            output_path = os.path.join(
                self.conf["received_dir"], f"RECEIVED_{file_name}"
            )
            with open(output_path, "wb") as f:
                f.write(decrypted_data)

            self.logger.info(f"Decrypted record saved to '{output_path}'")
            return True

        except ConnectionRefusedError:
            self.logger.error(
                f"Connection refused. Is {target_ip}:{target_port} running?"
            )
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

            _log_crypto(
                self.logger,
                "Request_Received",
                from_hospital=requester_name,
                message_preview=message,
                signature_len=len(signature),
                signature_preview=_short_hex(signature),
            )

            # Look up requester in registry to obtain their public keys
            try:
                requester_entry = get_hospital(requester_name)
            except Exception as e:
                self.logger.error(
                    f"Failed to query registry for requester '{requester_name}': {e}"
                )
                conn.sendall(b"Authentication Failed (Registry Error).")
                return

            if not requester_entry:
                self.logger.error(
                    f"Unknown requester '{requester_name}' in registry."
                )
                conn.sendall(b"Authentication Failed (Unknown Peer).")
                return

            # NOTE: field names must match register_hospital / get_hospital
            sign_public_pem = requester_entry.get("sign_pub_key")
            enc_public_pem = requester_entry.get("enc_pub_key")

            if not sign_public_pem or not enc_public_pem:
                self.logger.error(
                    f"Registry entry for '{requester_name}' missing public keys."
                )
                conn.sendall(b"Authentication Failed (Missing Keys).")
                return

            requester_sign_pub_key = serialization.load_pem_public_key(
                sign_public_pem.encode("utf-8")
            )
            requester_enc_pub_key = serialization.load_pem_public_key(
                enc_public_pem.encode("utf-8")
            )

            _log_crypto(
                self.logger,
                "VerifySignature_Start",
                algo="RSA",
                hash="SHA-256",
            )
            if not crypto_utils.verify_signature(
                message, signature, requester_sign_pub_key
            ):
                _log_crypto(
                    self.logger,
                    "VerifySignature_Failed",
                    note="Signature mismatch",
                )
                self.logger.error("Invalid signature.")
                conn.sendall(b"Authentication Failed (Invalid Signature).")
                return
            _log_crypto(
                self.logger,
                "VerifySignature_Success",
                note="Requester authenticated",
            )

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

            self.logger.info(
                f"Valid request for '{file_to_send}' from {requester_name}"
            )

            request_id = str(uuid.uuid4())
            approval_req = ApprovalRequest(
                request_id=request_id,
                requester_name=requester_name,
                file_to_send=file_to_send,
                file_path=file_path,
                node_name=self.name,
                logger=self.logger,
            )

            self._pending_queue.put(approval_req)
            self.logger.info(
                f"Approval pending: id={request_id}, from={requester_name}, "
                f"file={file_to_send}"
            )

            approved = approval_req.wait_for_decision()

            if not approved:
                self.logger.info(f"Request {request_id} denied.")
                conn.sendall(b"Request Denied.")
                return

            self.logger.info(
                f"Request {request_id} approved. Encrypting and sending..."
            )

            with open(file_path, "rb") as f:
                file_data = f.read()

            _log_crypto(
                self.logger,
                "File_Read",
                file=file_to_send,
                size=len(file_data),
                preview=_short_hex(file_data, 16),
            )

            # Generate fresh AES and HMAC keys for this transfer
            aes_key = os.urandom(32)
            hmac_key = os.urandom(32)
            _log_crypto(
                self.logger,
                "SessionKeys_Generated",
                aes_key_len=len(aes_key),
                aes_key_preview=_short_hex(aes_key, 8),
                hmac_key_len=len(hmac_key),
                hmac_key_preview=_short_hex(hmac_key, 8),
            )

            ciphertext, iv = crypto_utils.aes_encrypt(file_data, aes_key)
            _log_crypto(
                self.logger,
                "AES_Encrypt_Done",
                iv_hex=_short_hex(iv),
                plaintext_len=len(file_data),
                ciphertext_len=len(ciphertext),
                ciphertext_preview=_short_hex(ciphertext, 16),
            )

            hmac_tag = crypto_utils.generate_hmac(ciphertext, hmac_key)
            _log_crypto(
                self.logger,
                "HMAC_Generate_Done",
                tag_len=len(hmac_tag),
                tag_preview=_short_hex(hmac_tag),
            )

            combined_keys = aes_key + hmac_key

            _log_crypto(
                self.logger,
                "RSA_EncryptKeys_Start",
                combined_len=len(combined_keys),
                combined_preview=_short_hex(combined_keys),
            )

            # Encrypt session keys with requester's ENCRYPTION public key
            encrypted_keys = crypto_utils.rsa_encrypt(
                combined_keys, requester_enc_pub_key
            )
            _log_crypto(
                self.logger,
                "RSA_EncryptKeys_Done",
                enc_keys_len=len(encrypted_keys),
                enc_keys_preview=_short_hex(encrypted_keys),
            )

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


if __name__ == "__main__":
    print("Run via hospital_webui.py or your own harness.")
