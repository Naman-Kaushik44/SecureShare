"""Cryptographic primitives for SecureShare: AES-256 (GCM/CBC), SHA-256, RSA-2048 (OAEP key wrap, PSS signatures)."""
import os, hashlib
from cryptography.hazmat.primitives import hashes, serialization, padding as sympad
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


class DecryptionError(Exception):
    pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---- RSA keys -------------------------------------------------------------
def gen_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def priv_to_pem(key, password: str) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.BestAvailableEncryption(password.encode()))


def pub_to_pem(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def load_priv(pem: bytes, password: str):
    return serialization.load_pem_private_key(pem, password.encode())


def load_pub(pem: bytes):
    return serialization.load_pem_public_key(pem)


# ---- AES-256 --------------------------------------------------------------
def aes_encrypt(plaintext: bytes, mode: str = "GCM"):
    """Returns (key, iv, ciphertext). GCM ciphertext carries the 16-byte tag at the end."""
    key = os.urandom(32)                                   # AES-256
    if mode == "GCM":
        iv = os.urandom(12)
        return key, iv, AESGCM(key).encrypt(iv, plaintext, None)
    if mode == "CBC":
        iv = os.urandom(16)
        padder = sympad.PKCS7(128).padder()
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return key, iv, enc.update(padder.update(plaintext) + padder.finalize()) + enc.finalize()
    raise ValueError("mode must be GCM or CBC")


def aes_decrypt(key: bytes, iv: bytes, ct: bytes, mode: str) -> bytes:
    try:
        if mode == "GCM":
            return AESGCM(key).decrypt(iv, ct, None)
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        unpad = sympad.PKCS7(128).unpadder()
        return unpad.update(dec.update(ct) + dec.finalize()) + unpad.finalize()
    except Exception as e:                                  # InvalidTag / bad padding / bad length
        raise DecryptionError(type(e).__name__) from e


# ---- RSA wrap / sign ------------------------------------------------------
_OAEP = lambda: padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def wrap_key(pub, key: bytes) -> bytes:
    return pub.encrypt(key, _OAEP())


def unwrap_key(priv, wrapped: bytes) -> bytes:
    return priv.decrypt(wrapped, _OAEP())


def sign(priv, data: bytes) -> bytes:
    return priv.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())


def verify(pub, signature: bytes, data: bytes) -> bool:
    try:
        pub.verify(signature, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO),
                   hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False
