# =============================================================
# crypto_utils.py -- Core Cryptographic Primitives
# =============================================================
# Pure crypto functions with no database or business logic.
# Every function does exactly one thing and is independently testable.
#
# Cryptographic stack (matches Labs 3a and 3b):
#   AES-256-CBC  : Symmetric encryption (pad/unpad via PKCS7)
#   RSA-OAEP     : Asymmetric key wrapping (PKCS1_OAEP + SHA-256)
#   RSA-PSS      : Digital signatures (pss + SHA-256)
# =============================================================

from base64 import b64encode, b64decode

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from config import RSA_KEY_BITS
from logger import debug


# -------------------------------------------------------------
# AES -- Symmetric Encryption
# -------------------------------------------------------------

def aes_encrypt(data, key):
    # Encrypt bytes with AES-256-CBC.
    # A fresh random IV is generated on every call.
    # Never reuse an IV with the same key -- fundamental AES-CBC rule.
    iv = get_random_bytes(16)
    ## 128-bit IV = one AES block, required by CBC mode

    debug("crypto_utils", "aes_encrypt", "Generating AES-CBC cipher", f"key_len={len(key)} iv={iv.hex()[:16]}...")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ## CBC XORs each plaintext block with the previous ciphertext block.
    ## The IV acts as the "previous block" for the first block.
    ## This ensures identical plaintext blocks produce different ciphertext.

    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    ## pad() adds PKCS7 bytes so len(data) becomes a multiple of 16 bytes

    debug("crypto_utils", "aes_encrypt", "Encryption complete",
          f"plaintext_len={len(data)} ciphertext_len={len(ciphertext)}")

    # UPGRADE to AES-GCM:
    #   cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    #   ciphertext, tag = cipher.encrypt_and_digest(data)
    #   GCM produces an authentication tag -- drop pad/unpad entirely.
    #   Store tag alongside iv and ciphertext. Integrity checking included for free.

    return b64encode(iv).decode(), b64encode(ciphertext).decode()
    ## Caller stores iv and ciphertext separately in the DB


def aes_decrypt(iv_b64, ciphertext_b64, key):
    # Exact mirror of aes_encrypt -- same key and IV must be provided.
    iv         = b64decode(iv_b64)
    ciphertext = b64decode(ciphertext_b64)

    debug("crypto_utils", "aes_decrypt", "Decrypting AES-CBC",
          f"ciphertext_len={len(ciphertext)}")

    cipher    = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    ## unpad() strips the PKCS7 padding bytes added during encryption

    debug("crypto_utils", "aes_decrypt", "Decryption complete",
          f"plaintext_len={len(plaintext)}")
    return plaintext


# -------------------------------------------------------------
# RSA -- Key Generation and Serialisation
# -------------------------------------------------------------

def generate_rsa_keypair():
    # Generate a fresh RSA key pair.
    # 2048-bit meets NIST SP 800-131A current minimum.
    # UPGRADE: Move to 3072-bit for post-2030 deployments.
    # Trade-off: larger keys are more secure but slower for key operations.
    debug("crypto_utils", "generate_rsa_keypair",
          f"Generating RSA-{RSA_KEY_BITS} key pair (this takes a moment)")

    key         = RSA.generate(RSA_KEY_BITS)
    private_key = key.export_key()
    ## export_key() serialises the full private key as PEM bytes
    public_key  = key.publickey().export_key()
    ## .publickey() strips the private components -- safe to distribute

    debug("crypto_utils", "generate_rsa_keypair", "Key pair generated")
    return private_key, public_key


def export_private_key_encrypted(private_key_bytes, passphrase):
    # Re-export the private key with passphrase protection before DB storage.
    # PBKDF2 derives an encryption key from the passphrase (with a random salt),
    # then AES-128-CBC encrypts the private key bytes.
    # An attacker with DB read access still needs the user's password.
    # Same protection pattern as Lab 3b DSA key export.
    debug("crypto_utils", "export_private_key_encrypted",
          "Encrypting private key with passphrase (PBKDF2+AES128-CBC)")

    key       = RSA.import_key(private_key_bytes)
    protected = key.export_key(
        format="PEM",
        passphrase=passphrase,
        protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"
    )
    return protected.decode()


def load_private_key(private_key_pem, passphrase):
    # Load a passphrase-protected private key back into a usable RSA object.
    # Raises ValueError if the passphrase is wrong.
    debug("crypto_utils", "load_private_key", "Loading encrypted private key")
    return RSA.import_key(private_key_pem.encode(), passphrase=passphrase)


def load_public_key(public_key_pem):
    # Load a public key -- no passphrase required.
    debug("crypto_utils", "load_public_key", "Loading public key")
    return RSA.import_key(public_key_pem.encode())


# -------------------------------------------------------------
# RSA-OAEP -- Key Wrapping (asymmetric encryption of AES keys)
# -------------------------------------------------------------

def rsa_wrap_key(raw_key, public_key_pem):
    # Encrypt (wrap) a raw key using an RSA public key -- RSA-OAEP.
    # OAEP is the secure modern padding for RSA encryption.
    # Never use PKCS1v15 for encryption -- vulnerable to padding oracle attacks
    # (Bleichenbacher 1998).
    debug("crypto_utils", "rsa_wrap_key",
          f"Wrapping {len(raw_key)}-byte key with RSA-OAEP+SHA256")

    public_key = load_public_key(public_key_pem)
    cipher     = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    ## Same PKCS1_OAEP pattern as Lab 3a Task 2
    wrapped    = cipher.encrypt(raw_key)

    debug("crypto_utils", "rsa_wrap_key", "Key wrapped successfully")
    return b64encode(wrapped).decode()


def rsa_unwrap_key(wrapped_key_b64, private_key_obj):
    # Decrypt (unwrap) a key using an RSA private key.
    # Only the holder of the matching private key can do this.
    debug("crypto_utils", "rsa_unwrap_key", "Unwrapping key with RSA-OAEP+SHA256")

    wrapped    = b64decode(wrapped_key_b64)
    cipher     = PKCS1_OAEP.new(private_key_obj, hashAlgo=SHA256)
    raw_key    = cipher.decrypt(wrapped)

    debug("crypto_utils", "rsa_unwrap_key",
          f"Key unwrapped successfully, len={len(raw_key)}")
    return raw_key


# -------------------------------------------------------------
# RSA-PSS -- Digital Signatures
# -------------------------------------------------------------

def sign_content(content, private_key_obj):
    # Sign content with RSA-PSS + SHA-256.
    # PSS is the modern, more secure choice over PKCS1v15 for signing.
    # The signature proves:
    #   1. The signer holds the matching private key (authenticity)
    #   2. The content has not been modified since signing (integrity)
    debug("crypto_utils", "sign_content",
          f"Signing {len(content)} bytes with RSA-PSS+SHA256")

    h         = SHA256.new(content.encode("utf-8"))
    ## Hash the content first -- RSA operates on the digest, not raw text
    signer    = pss.new(private_key_obj)
    signature = signer.sign(h)

    debug("crypto_utils", "sign_content",
          f"Signature produced, len={len(signature)}")
    return b64encode(signature).decode()


def verify_content_signature(content, signature_b64, public_key_pem):
    # Verify an RSA-PSS signature using the signer's public key.
    # Returns True if valid, False for any failure.
    # All exceptions are caught and return False -- prevents leaking
    # internal error details to the caller (secure error handling pattern).
    debug("crypto_utils", "verify_content_signature",
          "Verifying RSA-PSS signature")
    try:
        public_key = load_public_key(public_key_pem)
        h          = SHA256.new(content.encode("utf-8"))
        verifier   = pss.new(public_key)
        verifier.verify(h, b64decode(signature_b64))
        debug("crypto_utils", "verify_content_signature", "Signature VALID")
        return True
    except (ValueError, TypeError) as e:
        debug("crypto_utils", "verify_content_signature",
              "Signature INVALID", str(e))
        return False