from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os
from cryptography.hazmat.primitives import serialization
import base64

def generate_key_pair():
    """ Generate a private and public key pair using X25519 """
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(message, receiver_public_key, sender_private_key):
    """ Encrypt a message using X25519 and ChaCha20-Poly1305 """
    # Generate a shared secret
    shared_secret = sender_private_key.exchange(receiver_public_key)
    
    # Derive a key from the shared secret using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_secret)
    
    # Encrypt the message using ChaCha20-Poly1305
    aead = ChaCha20Poly1305(derived_key)
    nonce = os.urandom(12)  # 96-bit nonce for ChaCha20-Poly1305
    encrypted_message = aead.encrypt(nonce, message.encode(), None)
    return encrypted_message, nonce

def decrypt_message(encrypted_message, nonce, sender_public_key, receiver_private_key):
    """ Decrypt the message using X25519 and ChaCha20-Poly1305 """
    # Generate a shared secret
    shared_secret = receiver_private_key.exchange(sender_public_key)
    
    # Derive a key from the shared secret using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_secret)
    
    # Decrypt the message using ChaCha20-Poly1305
    aead = ChaCha20Poly1305(derived_key)
    decrypted_message = aead.decrypt(nonce, encrypted_message, None)
    return decrypted_message.decode()

def public_key_to_bytes(public_key):
    """ Convert a public key to bytes """
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)

def public_key_to_base64(public_key):
    """ Convert a public key to a base64 string """
    public_key_bytes = public_key_to_bytes(public_key)
    return base64.b64encode(public_key_bytes).decode('utf-8')


def validate_key(base64_key):
    try:
        print(base64_key)
        key_bytes = base64.b64decode(base64_key)
        print(len(key_bytes))
        if len(key_bytes) == 32:  # Expected length for an X25519 key
            print("This appears to be a valid X25519 key.")
        else:
            print("Invalid key length: Expected 32 bytes.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


# Example usage
def main():

    # Generate key pairs
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()
    
    # Alice sends a message to Bob
    message = "check check"
    encrypted_message, nonce = encrypt_message(message, bob_public, alice_private)
    print(f"Encrypted: {encrypted_message}")
    
    # Bob decrypts the message
    try:
        decrypted_message = decrypt_message(encrypted_message, nonce, alice_public, bob_private)
        print(f"Decrypted: {decrypted_message}")
    except Exception as e:
        print(f"Decryption failed: {e}")

if __name__ == "__main__":
    main()
