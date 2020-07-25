# This is a file encryptor. It encrypts the contents
# of a file using a sha256 hash to verify the password. 

import base64
from base64 import b64encode
import os, sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

print("Current Directory: " + os.getcwd())

fd = input("Single File or Directory: ")
# 1 = File
# 0 = Directory

for x in ["d", "directory", "dir"]:
    if x in fd.lower():
        fd = 0
        break
if not fd == 0:
    fd = 1
    input_file = input("Input File: ")
    dirs = [input_file]

if fd == 0:
    input_dir = input("Directory (FULL PATH): ")
    dirs = []
    
    for (dirpath, dirnames, filenames) in os.walk(input_dir):
        dirs.extend(filenames)
        break

    dirs_temp = dirs
    dirs = []
    for x in dirs_temp:
        if input_dir[-1] == "/":
            dirs.append(input_dir + x)
        else:
            dirs.append(input_dir + "/" + x)

ed = input("Encrypt or Decrypt: ")

password_provided = str(input("Password\n> ")) # This is input in the form of a string
password = password_provided.encode() # Convert to type bytes

dirs = [ x for x in dirs if "_salt." not in x ]

for selfile in dirs: 
    if 'e' in ed.lower() or ed == "1" or not ed:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once

        outfile_ = selfile.split(".")
        output_file = outfile_[0] + "_enc." + outfile_[1]

        print("Output file: " + output_file)
        with open(selfile, 'rb') as decrypteddata:
            data = decrypteddata.read()

        fernet = Fernet(key)
        encrypteddata = fernet.encrypt(data)

        with open(output_file, 'wb') as f:
            f.write(encrypteddata)
            
        outfile = output_file.split(".")
        with open(outfile[0] + "_salt." + outfile[-1], 'wb') as f:
            f.write(salt)
            
    elif 'd' in ed.lower() or ed == "2":
        outfile_ = selfile.replace("_enc", "")
        output_file = outfile_

        ofile = selfile.split(".")
        try:
            print("opening " + ofile[0] + "_salt." + ofile[-1])
            with open(ofile[0] + "_salt." + ofile[-1], 'rb') as f:
                salt = f.read()
            os.remove(ofile[0] + "_salt." + ofile[-1])
        except FileNotFoundError:
            salt = input("Salt: ").encode("utf-8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once

        with open(selfile, 'rb') as encrypteddata:
            data = encrypteddata.read()

        fernet = Fernet(key)
        decrypteddata = fernet.decrypt(data)

        with open(output_file, 'wb') as f:
            f.write(decrypteddata)
    os.remove(selfile)
