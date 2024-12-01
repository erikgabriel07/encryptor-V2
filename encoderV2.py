import os, warnings, getpass
from src.encode_filename import (
    generate_key, encrypt_filename, decrypt_filename
)
from cryptography.fernet import Fernet, InvalidToken
from argparse import ArgumentParser
from dotenv import load_dotenv, set_key


if not load_dotenv():
    print('File \'.env\' not found! Please create a file ' \
           'named \'.env\' and write SECRET_KEY="Your secret key"')
    raise SystemExit(1)
    
    
def generate_token():
    new_key = Fernet.generate_key()
    set_key('.env', 'SECRET_KEY', new_key.decode())
    print('Token generated and stored with success!')


class Crypt(Fernet):
    def __init__(self, password):
        self.__pswd = generate_key(password)
        key = os.getenv('SECRET_KEY').encode()
        try:
            super().__init__(key)
        except Exception as e:
            print(f'InvalidToken {repr(key.decode())}!', str(e),\
                    '\nUse --token parameter to generate a new valid token.')
            raise SystemExit(1)
        
    def encrypt_dir(self, dirname):
        mode = 0o777
        flags = os.O_RDWR | os.O_BINARY
        for root, dirs, files in os.walk(dirname, topdown=False):
            for file in files:
                # reading file data
                path = os.path.join(root, file)
                fd = os.open(path, flags, mode)
                content = os.read(fd, os.path.getsize(path))
                ciphered = self.encrypt(content)
                
                # encrypting
                new_name = encrypt_filename(file, self.__pswd)
                new_path = os.path.join(root, new_name)
                os.ftruncate(fd, 0)
                os.lseek(fd, 0, 0)
                os.write(fd, ciphered)
                os.close(fd)
                os.rename(path, new_path)
            for dir in dirs:
                path = os.path.join(root, dir)
                new_name = encrypt_filename(dir, self.__pswd)
                new_path = os.path.join(root, new_name)
                os.rename(path, new_path)
    
    def decrypt_dir(self, dirname):
        mode = 0o777
        flags = os.O_RDWR | os.O_BINARY
        for root, dirs, files in os.walk(dirname, topdown=False):
            for file in files:
                # reading file data
                path = os.path.join(root, file)
                fd = os.open(path, flags, mode)
                content = os.read(fd, os.path.getsize(path))
                try:
                    plaintext = self.decrypt(content)
                except InvalidToken as e:
                    print('Texto não criptografado ou a chave não é válida.')
                    raise SystemExit(0)
                
                # decrypting
                old_name = decrypt_filename(file, self.__pswd)
                new_path = os.path.join(root, old_name)
                os.ftruncate(fd, 0)
                os.lseek(fd, 0, 0)
                os.write(fd, plaintext)
                os.close(fd)
                os.rename(path, new_path)
            for dir in dirs:
                path = os.path.join(root, dir)
                new_name = decrypt_filename(dir, self.__pswd)
                new_path = os.path.join(root, new_name)
                os.rename(path, new_path)


def main():
    parser = ArgumentParser(prog='encoder')
    parser.add_argument('directory_name', help='directory to encrypt')
    parser.add_argument('-e', '--encode', action='store_true')
    parser.add_argument('-d', '--decode', action='store_true')
    parser.add_argument('--token', action='store_true', help='generate a token')
    
    args = parser.parse_args()
    
    print('Your password will be used to encrypt the name of the files.')
    password = getpass.getpass('Password: ').strip()
    if not password.strip():
        warnings.warn('You haven\'t typed the password. The filenames will be encrypted without passkey.')
        try:
            input('\nPress ENTER to continue or CRTL+C to cancel...')
        except KeyboardInterrupt:
            raise SystemExit(0)
    
    if args.token:
        generate_token()
        raise SystemExit(0)
    
    if args.encode == args.decode:
        print('You must choose one \'--encode\' or \'--decode\' method.')
        raise SystemExit(1)
    
    if args.encode:
        Crypt(password).encrypt_dir(args.directory_name)
    if args.decode:
        Crypt(password).decrypt_dir(args.directory_name)

if __name__ == '__main__':
    main()