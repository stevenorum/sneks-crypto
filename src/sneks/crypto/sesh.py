from __future__ import print_function
from PyKCS11 import *
import binascii
import random
import time

# https://pkcs11wrap.sourceforge.io/api/samples.html

RSA_KEYGEN_MECHANISM = Mechanism(CKM_RSA_X9_31_KEY_PAIR_GEN, None)

OBJECT_CLASSES = {
    "CKO_DATA":CKO_DATA,
    "CKO_CERTIFICATE":CKO_CERTIFICATE,
    "CKO_PUBLIC_KEY":CKO_PUBLIC_KEY,
    "CKO_PRIVATE_KEY":CKO_PRIVATE_KEY,
    "CKO_SECRET_KEY":CKO_SECRET_KEY,
    "CKO_DOMAIN_PARAMETERS":CKO_DOMAIN_PARAMETERS,
    "CKO_OTP_KEY":CKO_OTP_KEY,
    "CKO_HW_FEATURE":CKO_HW_FEATURE,
    "CKO_MECHANISM":CKO_MECHANISM,
    "CKO_VENDOR_DEFINED":CKO_VENDOR_DEFINED
}

def OBJECT_CLASS_NAME(obj_class):
    for item in OBJECT_CLASSES.items():
        if item[1] == obj_class:
            return item[0]
    return None

def random_key_id(length=16):
    return [random.randint(0,255) for i in range(length)]

class Sesh(object):
    def __init__(self, username, password, lib_path=None):
        self._lib_path = lib_path
        self._pkcs11 = PyKCS11Lib()
        self._slot = None
        self._session = None
        self._pin = "{}:{}".format(username, password)

    def start(self):
        if self._lib_path:
            self._pkcs11.load(self._lib_path)
        else:
            self._pkcs11.load()
        self._slot = self._pkcs11.getSlotList(tokenPresent=True)[0]
        self._session = self._pkcs11.openSession(self._slot, CKF_RW_SESSION | CKF_SERIAL_SESSION)
        self._session.login(self._pin)

    def end(self):
        self._session.logout()
        self._session.closeSession()

    def create_rsa_keypair(self, key_label=None, key_id=None, token=False):
        token = CK_TRUE if token else CK_FALSE
        pubTemplate = [
            (CKA_CLASS, CKO_PUBLIC_KEY),
            (CKA_TOKEN, token),
            (CKA_PRIVATE, CK_FALSE),
            (CKA_MODULUS_BITS, 0x0800),
            (CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
            (CKA_ENCRYPT, CK_TRUE),
            (CKA_VERIFY, CK_TRUE),
            (CKA_VERIFY_RECOVER, CK_TRUE),
            (CKA_WRAP, CK_TRUE),
        ]
        privTemplate = [
            (CKA_CLASS, CKO_PRIVATE_KEY),
            (CKA_TOKEN, token),
            (CKA_PRIVATE, CK_TRUE),
            (CKA_DECRYPT, CK_TRUE),
            (CKA_SIGN, CK_TRUE),
            (CKA_SIGN_RECOVER, CK_TRUE),
            (CKA_UNWRAP, CK_TRUE),
        ]
        if key_label:
            pubTemplate.append((CKA_LABEL, key_label))
        if key_id != None:
            if not isinstance(key_id, (tuple,list)):
                key_id = (key_id,)
            pubTemplate.append((CKA_ID, key_id))
            privTemplate.append((CKA_ID, key_id))
        return self._session.generateKeyPair(pubTemplate, privTemplate, mecha=RSA_KEYGEN_MECHANISM)

    def rsa_encrypt(self, plaintext, key_id=None, key=None):
        if isinstance(plaintext, (str)):
            plaintext = plaintext.encode("utf-8")
        if not key and not key_id:
            raise RuntimeError("Must specify either key or key_id!")
        if not key:
            key = self._session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_ID, (key_id,))])[0]
        ciphertext = self._session.encrypt(key, plaintext, mecha=MechanismRSAPKCS1)
        return bytearray(ciphertext)

    def rsa_decrypt(self, ciphertext, key_id=None, key=None):
        if isinstance(ciphertext, bytearray):
            ciphertext = bytes(ciphertext)
        if not key and not key_id:
            raise RuntimeError("Must specify either key or key_id!")
        if not key:
            key = self._session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, (key_id,))])[0]
        plaintext = self._session.decrypt(key, ciphertext, mecha=MechanismRSAPKCS1)
        return bytearray(plaintext)

    def list_keys(self, key_id=None):
        obj_list = []
        search_attrs = []
        if key_id:
            if not isinstance(key_id, (tuple,list)):
                key_id = (key_id,)
            search_attrs.append((CKA_ID, key_id))
        if key_label:
            search_attrs.append((CKA_LABEL, key_label))
        objs = self._session.findObjects(search_attrs)
        for obj in objs:
            obj_data = {}
            attrs = self._session.getAttributeValue(obj, [CKA_CLASS, CKA_ID, CKA_LABEL, CKA_TOKEN])
            obj_data["OBJECT_HANDLE"] = obj
            obj_data["CKA_CLASS"] = attrs[0]
            obj_data["CKA_CLASS_NAME"] = OBJECT_CLASS_NAME(attrs[0])
            obj_data["CKA_ID"] = attrs[1]
            obj_data["CKA_LABEL"] = attrs[2]
            obj_data["CKA_TOKEN"] = attrs[3]
            obj_list.append(obj_data)
        return obj_list

    def delete_keys(self, keys=None, key_id=None, key_label=None):
        if not keys and not key_id and not key_label:
            raise RuntimeError("Must specify keys, key_id, or key_label!")
        if not keys:
            key_info = self.list_keys(key_id=key_id, key_label=key_label)
            keys = [k["OBJECT_HANDLE"] for k in key_info]
        if not isinstance(keys, (list,tuple)):
            keys = [keys]
        for key in keys:
            self._session.destroyObject(key)
