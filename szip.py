#!/usr/bin/env python3
import argparse
import os
import platform
import gzip
import sys
from termcolor import colored

from cryptography.fernet import Fernet


# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# listkun = [1, 1, 2, 3, 45, 65, 7][:-1]
# print("/".join(map(str, listkun)))


def create_parser():
    parser = argparse.ArgumentParser(description="Compress your data with encryption")
    parser.add_argument("-s", "--szip", help="Perform szip on the file path")
    parser.add_argument("-r", "--read", help="Read file")
    parser.add_argument("-u", "--unsubscribe", help="If you don't like SecuredZip")
    return parser


# def save_salt(salt, data_path):
#     sep = "/"
#     if platform.system() == "Windows":
#         sep = "\\"
#     data_dir = data_path.split(sep)[:-1]
#     data_dir = sep.join(data_dir)
#     salt_path = data_dir+sep+"/salt"
#     file = open(salt_path,"w")
#     file.write(salt)
#     file.close()
#     # TODO save salt to file


# def encrypt(compressed_data, password, data_path):
#     salt = os.urandom(16)
#     save_salt(salt, data_path)
#     kdf = PBKDF2HMAC(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=salt,
#         iterations=100000,
#         backend=default_backend()
#     )
class AlreadyEncrypted(Exception):
    pass


def write_key(filename):
    key = Fernet.generate_key()
    with open("{}.key".format(filename), "wb") as key_file:
        key_file.write(key)


def load_key(filename):
    return open("{}.key".format(filename), "rb").read()


def initializer(path):
    if not os.path.isfile(path):
        print("The file does not exist\nExit...")
        sys.exit()
    filename = str(path).split("/")[-1]
    with open(path, 'rb') as file:
        data = file.read()
    return data, filename


def compress_encrypt(data, filename):
    compressed_data = gzip.compress(data)
    write_key(filename)
    f = Fernet(load_key(filename))
    encrypted_data = f.encrypt(compressed_data)
    return encrypted_data


def decrypt_decompress(data, filename):
    f = Fernet(load_key(filename))
    decrypted_data = f.decrypt(data)
    decompressed_data = gzip.decompress(decrypted_data)
    print("File content: "+decompressed_data.decode('utf-8'))
    return decompressed_data


def write(writable, path):
    with open(path, 'wb') as file:
        data = file.write(writable)


def message(correct, path):
    if correct:
        print(colored("{}".format(path), 'green')
              + " is safe with "
              + colored("SecuredZip"
                        + "\u2122", 'green')
              + " latest technology")
    else:
        print(colored("{}".format(path), 'red')
              + " is unsafe without "
              + colored("SecuredZip" + "\u2122", 'green')
              + " latest technology")


def handle_args(args=None):
    if args is None:
        parser = create_parser()
        args = parser.parse_args()
    if args.szip:  # and args.password
        path = args.szip
        if os.path.isfile(path + ".key"):
            print("The file is already encrypted\nExit...")
            sys.exit()
        data, filename = initializer(args.szip)
        writable = compress_encrypt(data, filename)
        write(writable, path)

        message(True, path)
    if args.read:
        path = args.read
        if not os.path.isfile(path + ".key"):
            with open(path, 'r') as file:
                print("File content: "+file.read())
            print("The file is not encrypted\nExit...")
            sys.exit()
        data, filename = initializer(path)
        decrypt_decompress(data, filename)
    if args.unsubscribe:
        path = args.unsubscribe
        data, filename = initializer(path)
        decompressed_data = decrypt_decompress(data, filename)
        write(decompressed_data, path)
        os.remove(path+".key")
        message(False, path)
    else:
        raise SystemExit


if __name__ == '__main__':
    handle_args()
