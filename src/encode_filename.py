from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from hashlib import sha256
from functools import wraps
import os, base64


def error_validation(debug=False):
    def decorator(func):
        wraps(func)
        def wrapper(*args, **kwargs):
            try:
                f_result = func(*args, **kwargs)
                if not f_result:
                    raise Exception('Could not encrypt or decrypt files. May the password is incorrect.')
                return f_result
            except Exception as e:
                if debug:
                    print(str(e))
                    exit(127)
                else:
                    print('An error ocurred.')
                    exit(127)
        return wrapper
    return decorator


def generate_key(password: str) -> str:
    # generating key
    return sha256(password.encode()).digest()
    

@error_validation(debug=True)
def encrypt_filename(filename: str, key: bytes) -> str:
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(key),
                    modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padding_length = 16 - len(filename) % 16
    padded_filename = filename + chr(padding_length) * padding_length
    
    encrypted = encryptor.update(padded_filename.encode()) + encryptor.finalize()
    
    return base64.urlsafe_b64encode(iv + encrypted).decode()


@error_validation(debug=True)
def decrypt_filename(encrypted_filename: str, key: bytes) -> str:
    encrypted_data = base64.urlsafe_b64decode(encrypted_filename)
    
    iv, encrypted = encrypted_data[:16], encrypted_data[16:]
    
    cipher = Cipher(algorithms.AES(key),
                    modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    
    padding_length = decrypted[-1]
    filename = decrypted[:-padding_length].decode()
    
    return filename
