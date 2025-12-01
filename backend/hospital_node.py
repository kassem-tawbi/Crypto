# hospital_node.py

import socket
import threading
import json
import os
import base64
import sys
import uuid
from queue import Queue
import logging

from cryptography.hazmat.primitives import serialization

from backend.registry import register_hospital, get_hospital
from util import crypto_utils


# ===== Logging helpers =====


def get_logger(node_name: str, log_path: str) -> logging.Logger:
    """
    Logger that logs to stdout + per-hospital file.

    - One stdout handler (console)
    - One file handler per log_path
    - Log level = INFO (crypto + key events; no debug spam)
    """
    logger = logging.getLogger(node_name)

    # Always normalize to absolute path so UI + backend agree
    log_path = os.path.abspath(log_path)

    has_file_for_this_path = False
    has_stdout_handler = False

    for h in logger.handlers:
        if isinstance(h, logging.FileHandler):
            existing = os.path.abspath(getattr(h, "baseFilename", ""))
            if existing == log_path:
                has_file_for_this_path = True
        if isinstance(h, logging.StreamHandler) and getattr(h, "stream", None) is sys.stdout:
            has_stdout_handler = True

    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    # First time we configure this logger → start with a fresh file
    if not has_file_for_this_path and not logger.handlers:
        try:
            if os.path.exists(log_path):
                os.remove(log_path)
        except OSError:
            pass

    logger.setLevel(logging.INFO)      # <— key change: no DEBUG by default
    logger.propagate = False

    # stdout handler
    if not has_stdout_handler:
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter(f"[{node_name}] %(message)s"))
        logger.addHandler(ch)

    # file handler
    if not has_file_for_this_path:
        fh = logging.FileHandler(log_path, mode="a", encoding="utf-8")
        fh.setLevel(logging.INFO)
        fh.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] " + f"[{node_name}] %(message)s",
                "%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(fh)

    return logger



def _short_hex(data: bytes, length: int = 16) -> str:
    if not isinstance(data, (bytes, bytearray)):
        return str(data)
    h = data.hex()
    return (h[: 2 * length] + ("..." if len(h) > 2 * length else "")) or "∅"

def _log_crypto(logger: logging.Logger, op: str, **fields):
    """
    Structured crypto log helper.

    - Prefixes each line with [CRYPTO] so it stands out in the raw log file.
    - Keeps a machine-friendly "op | key=value | ..." format.
    - Sorts keys alphabetically so repeated operations line up nicely.
    """
    # Sort fields so logs are stable & easy to scan
    if fields:
        ordered = sorted(fields.items(), key=lambda kv: kv[0])
        kv_str = " | ".join(f"{k}={v}" for k, v in ordered)
        message = f"[CRYPTO] {op} | {kv_str}"
    else:
        message = f"[CRYPTO] {op}"

    logger.info(message)



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
            f"Waiting for decision: id={self.id}, requester={self.requester_name}, "
            f"file={self.file_to_send}"
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
    def __init__(
        self,
        my_name: str,
        p2p_host: str = "0.0.0.0",
        p2p_port: int = 65001,
        public_host: str | None = None,
        data_dir: str | None = None,
        received_dir: str | None = None,
        log_dir: str = "logs",
    ):
        """
        my_name:      Logical hospital name (used in Mongo registry & UI)
        p2p_host:     Host to bind the TCP server on (e.g. 0.0.0.0)
        p2p_port:     Port to bind the TCP server on
        public_host:  IP/DNS to store in Mongo so others can reach this node
                      (if None, we fall back to env PUBLIC_HOST or p2p_host)
        data_dir:     Folder with local records to share (defaults to f"{my_name}_data")
        received_dir: Folder where received records are stored (defaults to f"{my_name}_received")
        log_dir:      Directory for log files (default "logs")
        """
        # IMPORTANT: set name first so we can use it in get_logger
        self.name = my_name

        # Use an absolute path for the log file
        log_file = os.path.abspath(os.path.join(log_dir, f"{my_name}.log"))

        self.conf = {
            "host": p2p_host,
            "port": int(p2p_port),
            "sign_private_key": f"{my_name}_sign_private.pem",
            "enc_private_key": f"{my_name}_enc_private.pem",
            "data_dir": data_dir or f"{my_name}_data",
            "received_dir": received_dir or f"{my_name}_received",
            "log_file": log_file,
        }
        self.public_host = public_host

        # Now we can safely use self.name
        self.logger = get_logger(self.name, log_file)

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

        # --- Derive public keys (PEM) from private keys ---
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

        # Pending approvals (for UI)
        self._pending_lock = threading.Lock()
        self._pending_by_id: dict[str, ApprovalRequest] = {}
        self._pending_queue: "Queue[ApprovalRequest]" = Queue()

        self._server_thread: threading.Thread | None = None
        self._server_stop = threading.Event()

        # Ensure local directories
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
        Host/IP we publish in Mongo so peers can connect to us.
        Priority:
          1) explicit public_host argument
          2) PUBLIC_HOST env var
          3) our P2P listen host
        """
        return self.public_host or os.getenv("PUBLIC_HOST") or self.conf["host"]

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
                f"Registry updated for {self.name}: host={public_host}, port={public_port}"
            )
        except Exception as e:
            # Node still runs, but others won't discover it by name.
            self.logger.error(f"Failed to register hospital in registry: {e}")

    # ===== Public API used by the web UI =====

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
        self.logger.info("Background server worker started.")

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
        self.logger.info(
            f"request_record called: target={target_name}, file_name={file_name}"
        )

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

    # ===== Internal TCP server =====

    def _server_loop(self):
        host = self.conf["host"]
        port = self.conf["port"]

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # Helps when restarting quickly on the same port
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

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
                        self.logger.warning(
                            "Server socket closed or error in accept(); "
                            "stopping server loop."
                        )
                        break

                    self.logger.info(f"Accepted connection from {addr}")
                    t = threading.Thread(
                        target=self._handle_request_wrapper,
                        args=(conn,),
                        daemon=True,
                    )
                    t.start()

        except Exception as e:
            self.logger.exception(
                f"Fatal error in server loop (host={host}, port={port}): {e}"
            )

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
