import argparse
import base64
import hashlib
import json
import os
import time
from multiprocessing.pool import Pool

from ecdsa import SigningKey
import ecdsa.util

import utils


class Generator:
    user_code = ""
    doc_code = ""
    certificate_file = ""
    private_key = None

    sequence_to_find = ""

    start = 0

    chunk_size = 100000000

    def __init__(self, user_code: str, doc_code: str, certificate_file: str, private_key=None):
        """
        Initialise the generator for generating the keys
        :param user_code: Unique user identifier
        :param doc_code: SHA1-hash of the document
        :param certificate_file: Path to the certificate file
        :param private_key: Path to the private key or None if not signing
        """
        self.user_code = user_code.lower().strip()
        self.doc_code = doc_code.lower().strip()
        self.certificate_file = certificate_file
        self.private_key = private_key

        self.sequence_to_find = utils.generate_crc32(self.user_code)

    def generate(self, i: int):
        """
        Calculate the hash of this key, and check whether it contains the sequence_to_find
        :param i: The key of the hash
        :return: The key if it does contain the sequence, or none if it does not
        """
        d = utils.calculate_key(self.user_code, self.doc_code, i)

        if self.sequence_to_find in d:
            print("Key found:")
            print(d)
            print(i)
            print(time.time() - self.start)

            # Save the new certificate
            document = json.load(open(self.certificate_file))
            if i not in document["certificates"][self.user_code]["keys"]:
                document["certificates"][self.user_code]["keys"].append(i)
                document["certificates"][self.user_code]["keys"] = \
                    sorted(document["certificates"][self.user_code]["keys"])
                sign = None
                if self.private_key:
                    sign = self.generate_signature(document["certificates"][self.user_code]["keys"])
                document["certificates"][self.user_code]["signature"] = sign
                json.dump(document, open(self.certificate_file, "w"))
        return None

    def generate_signature(self, keys: list):
        """
        Generate a signature for this document and key set
        :param keys: The keys to verify
        :return: A Base64-encoded signature
        """
        sk = SigningKey.from_pem(open(self.private_key).read())
        sign = sk.sign(utils.get_key_signature(self.user_code, self.doc_code, keys),
                       hashfunc=hashlib.sha1, sigencode=ecdsa.util.sigencode_der)
        return base64.b64encode(sign).decode()

    def generate_all(self, offset=0):
        self.start = time.time()
        i = 0
        while True:
            with Pool(8) as p:
                p.map(self.generate, range((i * self.chunk_size) + offset, ((i + 1) * self.chunk_size) + offset))
                i += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate a certificate document')
    parser.add_argument("user_code",
                        type=str,
                        help="The unique user identifier")
    parser.add_argument("doc_path",
                        type=str,
                        help="The path to the document to sign")
    parser.add_argument("certificate_file",
                        type=str,
                        help="The signature document")
    parser.add_argument("--sign",
                        type=str,
                        help="Path to the private key to sign with")
    parser.add_argument("--offset",
                        type=int,
                        help="Offset of keys to start calculating from (default: 0)")

    args = parser.parse_args()

    doc_code = utils.get_sha1_file_hash(args.doc_path)
    g = Generator(args.user_code, doc_code, args.certificate_file, args.sign)

    print("user_code: " + g.user_code)
    print("doc_code: " + g.doc_code)
    print("sequence_to_find: " + g.sequence_to_find)

    if os.path.exists(args.certificate_file):
        document = json.load(open(args.certificate_file))
        if not doc_code == document["doc_code"]:
            print("The doc_code does not match")
            exit()
    else:
        document = {
            "doc_code": g.doc_code,
            "certificates": {}
        }

    if g.user_code in document["certificates"]:
        print("The user_code already exists")
    else:
        document["certificates"][g.user_code] = {
            "keys": [],
            "signature": None
        }

    json.dump(document, open(args.certificate_file, "w"))
    offset = args.offset or 0
    g.generate_all(offset)
