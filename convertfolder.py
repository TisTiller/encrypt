# This is a file encryptor. It encrypts the contents
# of a file using a sha256 hash to verify the password. 

import base64
from base64 import b64encode
import os, sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

dirs = []

for (dirpath, dirnames, filenames) in os.walk("."):
    dirs.extend(filenames)
    break

ed = input("Encrypt or Decrypt: ")

password_provided = str(input("Password\n> "))
password = password_provided.encode() 

dirs = [ x for x in dirs if "_salt." not in x ]
dirs = [ x for x in dirs if ".py" not in x ]

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
