# setup_keys.py
# Run this file on EACH hospital node to create its own keys and local test data.

import os
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def _generate_rsa_keypair():
    """Generate an RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def _save_private_key(private_key, filename: str):
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(filename, "wb") as f:
        f.write(priv_pem)


def _save_public_key(public_key, filename: str):
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(filename, "wb") as f:
        f.write(pub_pem)


def generate_and_save_keys(hospital_name: str):
    """
    Generates two RSA key pairs for a hospital:
      - one for SIGNING
      - one for ENCRYPTION
    and saves them to PEM files.
    """

    # Signing key pair
    sign_private, sign_public = _generate_rsa_keypair()
    _save_private_key(sign_private, f"{hospital_name}_sign_private.pem")
    _save_public_key(sign_public, f"{hospital_name}_sign_public.pem")

    # Encryption key pair
    enc_private, enc_public = _generate_rsa_keypair()
    _save_private_key(enc_private, f"{hospital_name}_enc_private.pem")
    _save_public_key(enc_public, f"{hospital_name}_enc_public.pem")

    print(f"Generated signing and encryption keys for {hospital_name}")


def create_dummy_data_for(hospital_name: str):
    """
    Minimal test data:
      - For Hospital_B: create a dummy record in hospital_B_data.
      - For Hospital_A: ensure hospital_A_received exists.
    """
    if hospital_name == "Hospital_B":
        os.makedirs("hospital_B_data", exist_ok=True)
        with open("hospital_B_data/patient_123.txt", "w") as f:
            f.write("PATIENT RECORD: John Doe\n")
            f.write("DOB: 1980-01-15\n")
            f.write("Blood Type: O+\n")
            f.write("Allergies: Penicillin\n")
            f.write("--- END OF RECORD ---")
        print("Created dummy data for Hospital_B (hospital_B_data/patient_123.txt)")

    if hospital_name == "Hospital_A":
        os.makedirs("hospital_A_received", exist_ok=True)
        print("Created receive directory for Hospital_A (hospital_A_received/)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "hospital",
        choices=["Hospital_A", "Hospital_B"],
        help="Hospital name whose keys should be generated.",
    )
    args = parser.parse_args()

    generate_and_save_keys(args.hospital)
    create_dummy_data_for(args.hospital)
    print("\nSetup complete for", args.hospital)


if __name__ == "__main__":
    main()
