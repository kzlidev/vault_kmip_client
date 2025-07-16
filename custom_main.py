# Configure your KMIP client to connect to the Vault KMIP endpoint
import os
import secrets
import random

from kmip.core import enums, objects
from kmip.core.enums import CryptographicUsageMask, ObjectType, AttributeType
from kmip.pie.objects import SymmetricKey, SecretData
from cryptography.hazmat.primitives import padding

from custom_client import ProxyKmipClient

hostname = "vault.kz-li.sbx.hashidemos.io"  # Change this to your Vault server's hostname
port = 5696  # KMIP port, typically 5696 for Vault
client_cert_path = "./certs/client_cert.pem"
client_key_path = "./certs/client_key.pem"
ca_cert_path = "./certs/kmip_ca.pem"

plain_text = "hello vault"

def create_key(client):
    # Specify the key creation parameters
    key_algorithm = enums.CryptographicAlgorithm.AES
    key_length = 256  # Length for AES-256

    # Perform the create operation
    key_id = client.create(
        algorithm=key_algorithm,  # Algorithm for the key
        length=key_length,  # Key length in bits
        cryptographic_usage_mask=[
            enums.CryptographicUsageMask.ENCRYPT,
            enums.CryptographicUsageMask.DECRYPT,
            enums.CryptographicUsageMask.WRAP_KEY,
            enums.CryptographicUsageMask.UNWRAP_KEY
        ]
    )
    client.activate(key_id)
    print(f"Key created successfully with ID: {key_id}")


def import_key(client, key_material):
    # Create a SymmetricKey object with the correct attributes
    symmetric_key = SymmetricKey(
        algorithm=enums.CryptographicAlgorithm.AES,  # Encryption algorithm
        length=256,  # Key length in bits
        value=key_material,  # Key material
        name=f"CustomName{random.random()}",
        masks=[CryptographicUsageMask.ENCRYPT, CryptographicUsageMask.DECRYPT, enums.CryptographicUsageMask.WRAP_KEY, enums.CryptographicUsageMask.UNWRAP_KEY]
    )

    # Perform the Register operation to import the key
    key_id = client.register(symmetric_key)
    client.activate(key_id)
    print(f"Key imported successfully with ID: {key_id}")
    return key_id

def list_keys(client):
    # Perform the Locate operation to list keys
    # Optionally, you can pass search criteria (e.g., by name, object type)
    key_ids = client.locate(
        maximum_items=100,  # Limit the number of results, adjust as needed
    )

    if key_ids:
        print("Found the following keys:")
        for key_id in key_ids:
            print(f"- {key_id}")
        return key_ids
    else:
        print("No keys found.")


def encrypt(client, key_id, plain_text):
    plain_text_bytes = bytes(plain_text, "utf-8")
    # Pad plaintext to be a multiple of block size
    padder = padding.PKCS7(64).padder()
    padded_plaintext = padder.update(plain_text_bytes) + padder.finalize()

    # Define cryptographic parameters
    cryptographic_parameters = {
        "block_cipher_mode": enums.BlockCipherMode.CBC
    }

    # Perform the Encrypt operation
    encrypted_data = client.encrypt(
        data=padded_plaintext,  # Data to encrypt
        uid=key_id,  # ID of the symmetric key
        cryptographic_parameters=cryptographic_parameters,  # Algorithm used
        iv_counter_nonce=b"\x00" * 16
    )

    print(f"Encrypted Data: {encrypted_data[0]}")

    return encrypted_data[0]


def decrypt(client, key_id, cipher_text):
    # Define cryptographic parameters
    cryptographic_parameters = {
        "block_cipher_mode": enums.BlockCipherMode.CBC
    }

    decrypted_data = client.decrypt(
        data=cipher_text,  # Data to encrypt
        uid=key_id,  # ID of the symmetric key
        cryptographic_parameters=cryptographic_parameters,  # Algorithm used
        iv_counter_nonce=b"\x00" * 16
    )

    # Unpad decrypted data
    unpadder = padding.PKCS7(64).unpadder()
    decrypted_data = (unpadder.update(decrypted_data) + unpadder.finalize()).decode("utf-8")

    print(f"Decrypted Data: {decrypted_data}")
    return decrypted_data


client = ProxyKmipClient(
    hostname=hostname,
    port=port,
    cert=client_cert_path,
    key=client_key_path,
    ca=ca_cert_path,

    ssl_version="PROTOCOL_TLS_CLIENT"  # Ensure secure TLS connection
)

os.system("ls")
# Open the connection to the Vault KMIP server
client.open()
try:
    print("Performing KMIP operations")
    # create_key(client)
    #
    # key_material = secrets.token_bytes(32)
    # import_key(client, os.urandom(32))
    #
    keys = list_keys(client)

    # Choose one of the key_id from the listed keys
    key_id = keys[0]
    print(f"Using {key_id} for encryption and decryption")
    # cipher_text = encrypt(client, key_id, plain_text)
    # original_text = decrypt(client, key_id, cipher_text)
finally:
    # Close the connection
    client.close()
