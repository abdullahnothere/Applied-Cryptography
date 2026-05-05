# crypto_utils.py
# Core crypto primitives — AES encryption, RSA key ops, and signatures.
# No business logic in here, just the raw operations.

from base64 import b64encode, b64decode

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from config import RSA_KEY_BITS
from logger import debug


def aes_encrypt(data, key):
    # Fresh IV on every call — reusing one with the same key breaks CBC security.
    iv = get_random_bytes(16)
    debug("crypto_utils", "aes_encrypt", f"key_len={len(key)} plaintext_len={len(data)}")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))

    # UPGRADE: swap MODE_CBC for MODE_GCM to get an auth tag for free.
    # GCM means you can drop the pad/unpad and detect tampering at decrypt time.

    return b64encode(iv).decode(), b64encode(ciphertext).decode()


def aes_decrypt(iv_b64, ciphertext_b64, key):
    iv = b64decode(iv_b64)
    ciphertext = b64decode(ciphertext_b64)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    debug("crypto_utils", "aes_decrypt", f"plaintext_len={len(plaintext)}")
    return plaintext


def generate_rsa_keypair():
    # 2048-bit is the NIST minimum right now. Worth bumping to 3072 post-2030.
    debug("crypto_utils", "generate_rsa_keypair", f"generating RSA-{RSA_KEY_BITS}")
    key = RSA.generate(RSA_KEY_BITS)
    return key.export_key(), key.publickey().export_key()


def export_private_key_encrypted(private_key_bytes, passphrase):
    # PBKDF2 derives an encryption key from the passphrase before wrapping the
    # private key bytes. Someone with only DB access still needs the password.
    key = RSA.import_key(private_key_bytes)
    protected = key.export_key(
        format="PEM",
        passphrase=passphrase,
        protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
    )
    return protected.decode()


def load_private_key(private_key_pem, passphrase):
    return RSA.import_key(private_key_pem.encode(), passphrase=passphrase)


def load_public_key(public_key_pem):
    return RSA.import_key(public_key_pem.encode())


def rsa_wrap_key(raw_key, public_key_pem):
    # OAEP with SHA-256 — same pattern as Lab 3a.
    # Never use PKCS1v15 here; it's vulnerable to padding oracle attacks.
    public_key = load_public_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    wrapped = cipher.encrypt(raw_key)
    debug("crypto_utils", "rsa_wrap_key", f"wrapped {len(raw_key)}-byte key")
    return b64encode(wrapped).decode()


def rsa_unwrap_key(wrapped_key_b64, private_key_obj):
    wrapped = b64decode(wrapped_key_b64)
    cipher = PKCS1_OAEP.new(private_key_obj, hashAlgo=SHA256)
    return cipher.decrypt(wrapped)


def sign_content(content, private_key_obj):
    # Hash first, then sign the digest — RSA-PSS doesn't sign raw strings.
    h = SHA256.new(content.encode("utf-8"))
    signer = pss.new(private_key_obj)
    signature = signer.sign(h)
    return b64encode(signature).decode()


def verify_content_signature(content, signature_b64, public_key_pem):
    # Returns False on any failure rather than raising — stops internal error
    # details leaking to the caller.
    try:
        public_key = load_public_key(public_key_pem)
        h = SHA256.new(content.encode("utf-8"))
        pss.new(public_key).verify(h, b64decode(signature_b64))
        return True
    except (ValueError, TypeError):
        return False