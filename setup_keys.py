# setup_keys.py
# Run this file ONCE to create keys and dummy data.

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_and_save_keys(hospital_name):
    """Generates an RSA key pair and saves it to PEM files."""

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate public key
    public_key = private_key.public_key()

    # Serialize private key
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,  # <--- FIX: Added encoding
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save keys to files
    with open(f"{hospital_name}_private.pem", "wb") as f:
        f.write(priv_pem)

    with open(f"{hospital_name}_public.pem", "wb") as f:
        f.write(pub_pem)

    print(f"Generated keys for {hospital_name}")


def create_dummy_data():
    """Creates a dummy medical record for testing."""
    os.makedirs("hospital_B_data", exist_ok=True)
    with open("hospital_B_data/patient_123.txt", "w") as f:
        f.write("PATIENT RECORD: John Doe\n")
        f.write("DOB: 1980-01-15\n")
        f.write("Blood Type: O+\n")
        f.write("Allergies: Penicillin\n")
        f.write("--- END OF RECORD ---")

    # Directory for the requester to save received files
    os.makedirs("hospital_A_received", exist_ok=True)

    print("Created dummy data for Hospital B")


if __name__ == "__main__":
    generate_and_save_keys("hospital_A")  # The Requester
    generate_and_save_keys("hospital_B")  # The Data Owner
    create_dummy_data()
    print("\nSetup complete. You can now run the server and client.")