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
    and saves them to PEM files named:

      <hospital>_sign_private.pem
      <hospital>_sign_public.pem
      <hospital>_enc_private.pem
      <hospital>_enc_public.pem
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


def _dir_prefix_for(hospital_name: str) -> str:
    """
    Map a hospital name to the directory prefix used by the node.

    For your existing setup:
      - Hospital_A -> hospital_A
      - Hospital_B -> hospital_B
    For any other name, we just use the hospital_name as-is.

    Then data/received directories are:
      <prefix>_data, <prefix>_received
    """
    if hospital_name == "Hospital_A":
        return "hospital_A"
    if hospital_name == "Hospital_B":
        return "hospital_B"
    # Generic case: use the name directly (you can align CONFIG with this).
    return hospital_name


def create_dummy_data_for(hospital_name: str):
    """
    Create minimal local test data for this hospital:

      - <prefix>_data/
      - <prefix>_received/
      - <prefix>_data/patient_123.txt  (dummy patient record)

    Where <prefix> = _dir_prefix_for(hospital_name).
    """
    prefix = _dir_prefix_for(hospital_name)
    data_dir = f"{prefix}_data"
    recv_dir = f"{prefix}_received"

    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(recv_dir, exist_ok=True)

    # Always drop one dummy record into this hospital's data dir
    patient_path = os.path.join(data_dir, "patient_123.txt")
    if not os.path.exists(patient_path):
        with open(patient_path, "w", encoding="utf-8") as f:
            f.write("PATIENT RECORD: John Doe\n")
            f.write("DOB: 1980-01-15\n")
            f.write("Blood Type: O+\n")
            f.write("Allergies: Penicillin\n")
            f.write("--- END OF RECORD ---")
        print(f"Created dummy data for {hospital_name} ({patient_path})")
    else:
        print(f"Dummy data already exists for {hospital_name} ({patient_path})")

    print(f"Receive directory ready for {hospital_name} ({recv_dir}/)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "hospital",
        help="Hospital name whose keys should be generated (e.g., Hospital_A, Hospital_B, MyHospital).",
    )
    args = parser.parse_args()

    hospital_name = args.hospital

    generate_and_save_keys(hospital_name)
    create_dummy_data_for(hospital_name)
    print("\nSetup complete for", hospital_name)


if __name__ == "__main__":
    main()
