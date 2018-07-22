import argparse
import base64
import json
import os
import time
from multiprocessing.pool import Pool

from ecdsa import SigningKey

import utils


class Generator:
    user_code = ""
    doc_code = ""

    sequence_to_find = ""

    start = 0

    def __init__(self, user_code: str, doc_code: str):
        """
        Initialise the generator for generating the keys
        :param user_code: Unique user identifier
        :param doc_code: SHA1-hash of the document
        """
        self.user_code = user_code.lower().strip()
        self.doc_code = doc_code.lower().strip()

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
            return i

        return None

    def generate_signature(self, keys: list, key_file):
        """
        Generate a signature for this document and key set
        :param keys: The keys to verify
        :param key_file: The path to the private key file
        :return: A Base64-encoded signature
        """
        sk = SigningKey.from_pem(open(key_file).read())
        sign = sk.sign(utils.get_key_signature(self.user_code, self.doc_code, keys))
        return base64.b64encode(sign).decode()

    def generate_all(self):
        self.start = time.time()
        with Pool(8) as p:
            result = p.map(self.generate, range(100000000))

        # Make sure result is sorted and contains no None, otherwise it might go wrong verifying
        result = sorted([x for x in result if x is not None])
        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate a certificate document')
    parser.add_argument("user_code", type=str, help="The unique user identifier")
    parser.add_argument("doc_path", type=str, help="The path to the document to sign")
    parser.add_argument("--sign", type=str, help="Path to the private key to sign with")

    args = parser.parse_args()

    doc_code = utils.get_sha1_file_hash(args.doc_path)
    g = Generator(args.user_code, doc_code)

    print("user_code: " + g.user_code)
    print("doc_code: " + g.doc_code)
    print("sequence_to_find: " + g.sequence_to_find)

    if os.path.exists(args.doc_path + ".powcert"):
        document = json.load(open(args.doc_path + ".powcert"))
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
        exit()

    r = g.generate_all()
    sign = None
    if args.sign:
        sign = g.generate_signature(r, args.sign)

    document["certificates"][g.user_code] = {}
    document["certificates"][g.user_code]["keys"] = r
    document["certificates"][g.user_code]["signature"] = sign

    json.dump(document, open(args.doc_path + ".powcert", "w"))
