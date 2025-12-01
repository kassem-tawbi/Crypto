# crypto_utils.py
# A helper module for all cryptographic operations.
# NOTE: HospitalNode now uses separate RSA key pairs for:
#   - signing (sign_message / verify_signature)
#   - encryption (rsa_encrypt / rsa_decrypt)

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import (
    serialization,
    padding as sym_padding,
    hashes,
    hmac,
)


# --- RSA Functions (for Key Exchange & Signatures) ---


def load_private_key(filename):
    """Loads an RSA private key from a PEM file."""
    with open(filename, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )


def load_public_key(filename):
    """Loads an RSA public key from a PEM file."""
    with open(filename, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())


def sign_message(message, private_key):
    """Signs a message with a private key (Authentication)."""
    if isinstance(message, str):
        message = message.encode("utf-8")

    return private_key.sign(
        message,
        rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            salt_length=rsa_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(message, signature, public_key):
    """Verifies a signature with a public key (Authentication)."""
    if isinstance(message, str):
        message = message.encode("utf-8")

    try:
        public_key.verify(
            signature,
            message,
            rsa_padding.PSS(
                mgf=rsa_padding.MGF1(hashes.SHA256()),
                salt_length=rsa_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def rsa_encrypt(data, public_key):
    """Encrypts data with an RSA public key (for Key Exchange)."""
    return public_key.encrypt(
        data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(encrypted_data, private_key):
    """Decrypts data with an RSA private key (for Key Exchange)."""
    return private_key.decrypt(
        encrypted_data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# --- AES & HMAC Functions (for Data Encryption & Integrity) ---


def aes_encrypt(data, key):
    """Encrypts data using AES-256-CBC."""
    # Generate a random 16-byte IV (Initialization Vector)
    iv = os.urandom(16)

    # Pad the data to be a multiple of AES block size
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Create AES cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext, iv


def aes_decrypt(ciphertext, key, iv):
    """Decrypts data using AES-256-CBC."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the data
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data


def generate_hmac(data, key):
    """Generates an HMAC-SHA256 tag for data (Integrity)."""
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def verify_hmac(data, key, hmac_to_check):
    """Verifies an HMAC-SHA256 tag (Integrity)."""
    try:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        h.verify(hmac_to_check)
        return True
    except Exception:
        return False
