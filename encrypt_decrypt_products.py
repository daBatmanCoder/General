from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from eth_keys import keys
from eth_hash.auto import keccak
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
import hashlib
import os

def hash_function(input_string, salt=b""):
    # Hash the input string using SHA256
    prefix = "\x19Ethereum Signed Message:\n";
    length = len(input_string)
    hash = keccak(prefix.encode() + str(length).encode() + input_string.encode()+ salt) 

    # Convert the hash to an Ethereum private key
    private_key = keys.PrivateKey(hash)
    
    return private_key

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a cryptographic key from a password using Scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data: bytes, password: str) -> tuple:
    """Encrypt data using a derived key from a password."""
    salt = os.urandom(16)
    key = derive_key(password, salt)

    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    return (encrypted_data, salt, encryptor.tag, nonce)  # Include the nonce in the returned tuple

def decrypt_data(encrypted_data: bytes, salt: bytes, tag: bytes, nonce: bytes, password: str) -> bytes:
    """Decrypt data using a derived key from a password."""
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()


def encrypt(plaintext, password):
    # Derive a key from the password using SHA-256
    key = sha256(password.encode()).digest()[:16]

    # Create the AES cipher object
    cipher = AES.new(key, AES.MODE_ECB)

    # Pad the plaintext to be a multiple of 16 bytes
    padded_plaintext = pad(plaintext, AES.block_size)

    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)

    return ciphertext

def decrypt(ciphertext, password):
    # Derive the key from the password using SHA-256
    key = sha256(password.encode()).digest()[:16]

    # Create the AES cipher object
    cipher = AES.new(key, AES.MODE_ECB)

    # Decrypt the ciphertext
    padded_plaintext = cipher.decrypt(ciphertext)

    # Remove the padding from the plaintext
    plaintext = unpad(padded_plaintext, AES.block_size)

    return plaintext


def hash_string(input_string):

    # Encode the input string to bytes
    encoded_string = input_string.encode()
    # Create a sha256 hash object
    sha256_hash = hashlib.sha256()
    # Update the hash object with the bytes
    sha256_hash.update(encoded_string)
    # Get the hexadecimal digest of the hash
    hex_digest = sha256_hash.hexdigest()
    return hex_digest


    

user_choosen_name = "amir6@gmail.com"
hashed_output = hash_string(user_choosen_name)
hashed_output = "0x" + hashed_output
# That's going to be the user's ENS
print("Hashed username-", hashed_output)

salt = os.urandom(16)
private_key = hash_function(user_choosen_name, salt)

print("Ethereum Private Key:", private_key)
print("Ethereum Address:", private_key.public_key.to_checksum_address())


data_to_encrypt = private_key.to_bytes()
password = "secure123"

# Encrypt the plaintext
ciphertext = encrypt(data_to_encrypt, password)
ciphertextString = ciphertext.hex()
print(f"Ciphertext string: {ciphertextString}")






# # now we can send this encryption data to- IPFS get the CID and put the link in a mail
# link = "https://orange-acceptable-mouse-528.mypinata.cloud/ipfs/QmY7B7Zv88aRG5Ez4jSW6v4ZqRqYfvFcSMjJ3P56FQBcvZ"

# response = requests.get(link)
# data = response.text
data = "e2c81927ce14adfd4d222a6f5ff5dcab30745e0aaaabaaefa0c3e3274c4751b898ef6736721a5cff6c83d7d9e0cc054c"

byte_data = bytes.fromhex(data)
print(byte_data)


# # Decrypt the encrypted private key using the password
decrypted_text = decrypt(byte_data , password)
print(f"Decrypted text: {decrypted_text.hex()}")


