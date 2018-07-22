import argparse
import base64
import json
from multiprocessing.pool import Pool

import requests
from ecdsa import VerifyingKey, BadSignatureError

import utils


class Verifier:
    user_code = ""
    doc_code = ""
    keys = []

    sequence_to_find = ""

    def __init__(self, user_code: str, doc_code: str, keys: list):
        """
        Initialise the verifier for verifying the codes supplied by a user
        :param user_code: Unique user identifier
        :param doc_code: SHA1-hash of the document
        :param keys: List of codes from the user
        """
        self.user_code = user_code.lower().strip()
        self.doc_code = doc_code.lower().strip()
        self.keys = keys

        self.sequence_to_find = utils.generate_crc32(self.user_code)

    def verify(self, i: int):
        """
        Verify that this key is actually in the hash by recalculating the hash and checking whether it exists
        :param i:
        :return: Whether it contains this string
        """
        d = utils.calculate_key(self.user_code, self.doc_code, i)
        return self.sequence_to_find in d

    def verify_signature(self, sign: str, key: str):
        """
        Verify the supplied signature
        :param sign: Signature as Base64-encoded string
        :param key: The public key
        :return: Whether this signature is correct given the doc_code, user_code and keys.
        """
        try:
            vk = VerifyingKey.from_pem(key)
            sign = base64.b64decode(sign.encode())
            vk.verify(sign, utils.get_key_signature(self.user_code, self.doc_code, self.keys))
            return True
        except BadSignatureError:
            return False

    def verify_all(self):
        """
        Verify all codes by this user_code
        :return: A list of bools which keys could be verified
        """
        with Pool(min(len(self.keys), 8)) as p:
            result = p.map(self.verify, self.keys)
        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Verify a certificate document')
    parser.add_argument("doc_path", type=str, help="The path to the document to verify")
    parser.add_argument("--verify", action="store_true", help="Verify the signatures")

    args = parser.parse_args()

    document = json.load(open(args.doc_path + ".powcert", "rb"))

    doc_code = utils.get_sha1_file_hash(args.doc_path)
    if not doc_code == document["doc_code"]:
        print("The doc_code does not match")
        exit()

    # The first user code
    for user_code in list(document["certificates"].keys()):
        v = Verifier(user_code, document["doc_code"], document["certificates"][user_code]["keys"])
        print("user_code: " + v.user_code)
        print("doc_code: " + v.doc_code)
        print("sequence_to_find: " + v.sequence_to_find)
        output = v.verify_all()

        if False not in output:
            print("All keys verified")
            if args.verify:
                if not v.verify_signature(document["certificates"][user_code]["signature"],
                                          requests.get(utils.get_powcert_url(user_code)).text):
                    print("Signature verification failed")
                else:
                    print("Signature OK!")
        else:
            print("Not all codes could be verified")
