import argparse
import os
import platform
import zlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# listkun = [1, 1, 2, 3, 45, 65, 7][:-1]
# print("/".join(map(str, listkun)))


def create_parser():
    parser = argparse.ArgumentParser(description="Compress your data with encryption")
    parser.add_argument("-d", "--directory", help="Perform szip on the file path")
    parser.add_argument("-p", "--password", help="Password")
    return parser


def save_salt(salt, data_path):
    sep = "/"
    if platform.system() == "Windows":
        sep = "\\"
    data_dir = data_path.split(sep)[:-1]
    data_dir = sep.join(data_dir)
    salt_path = data_dir+sep+"/salt"
    file = open(salt_path,"w")
    file.write(salt)
    file.close()
    # TODO save salt to file


def encrypt(compressed_data, password, data_path):
    salt = os.urandom(16)
    save_salt(salt, data_path)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )


def handle_args(args=None):
    if args is None:
        parser = create_parser()
        args = parser.parse_args()
    if args.directory and args.password:
        with open(args.directory, 'r') as file:
            data = file.read()
        compressed_data = zlib.compress(bytes(data), 9)
        encrypted_data = encrypt(compressed_data, args.password, args.directory)
    else:
        raise SystemExit


if __name__ == '__main__':
    handle_args()
