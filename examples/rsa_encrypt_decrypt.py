import argparse
import binascii
import random
import string
import sys
import time
from sneks.crypto.sesh import Sesh, random_key_id

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", help="Username.",dest="username",required=True)
    parser.add_argument("--password", help="Password.",dest="password",required=True)
    parser.add_argument("--key-label", help="Key label.",dest="key_label",default=None)
    parser.add_argument("--lib-path", help="Full location of the PKCS11 .so library on disk.",dest="lib_path",default=None)
    parser.add_argument("--token", help="Create a long-lived token key instead of a session key, and restart the session in the middle.", default=False, action="store_true")
    return parser.parse_args()

hexlify = lambda x: binascii.hexlify(bytearray(x.encode("utf-8") if isinstance(x,str) else x))

def main():
    args = get_args()
    username = args.username
    password = args.password
    lib_path = args.lib_path
    token = args.token
    key_label = args.key_label if args.key_label else "example-".format("".join([random.choice(string.ascii_lowercase+string.ascii_uppercase) for i in range(8)]))

    sesh = Sesh(username=username, password=password, lib_path=lib_path)

    sesh.start()

    key_id = random_key_id()

    message = "Hello, world!  I is snek, reporting for duty."
    print("Message: {}".format(message))

    pubKey, privKey = sesh.create_rsa_keypair(key_label=key_label, key_id=key_id, token=token)

    ciphertext = sesh.rsa_encrypt(message, key_id=key_id)

    print("Ciphertext (in hex): {}".format(hexlify(ciphertext)))
    if token:
        print("Ending session, sleeping 5 seconds, then starting again...")
        sesh.end()
        time.sleep(5)
        sesh.start()

    plaintext = sesh.rsa_decrypt(ciphertext, key_id=key_id)

    print("Plaintext: {}".format(plaintext.decode("utf-8")))

    if token:
        sesh.delete_keys(key_id=key_id)

    sesh.end()

if __name__ == "__main__":
    main()
