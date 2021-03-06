import argparse
import base64
import hashlib
import json

import ecdsa.util
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
            vk.verify(sign, utils.get_key_signature(self.user_code, self.doc_code, self.keys),
                      hashfunc=hashlib.sha1, sigdecode=ecdsa.util.sigdecode_der)
            return True
        except BadSignatureError:
            return False

    def verify_all(self):
        """
        Verify all codes by this user_code
        :return: A boolean whether all keys were verified
        """
        for key in self.keys:
            if not self.verify(key):
                return False

        return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Verify a certificate document')
    parser.add_argument("doc_path", type=str, help="The path to the document to verify")
    parser.add_argument("certificate_file", type=str, help="The signature document")
    parser.add_argument("--verify", action="store_true", help="Verify the signatures")
    parser.add_argument("--write-report", type=str, help="Path to write the verification report to")

    args = parser.parse_args()

    # Certificate file
    document = json.load(open(args.certificate_file, "r"))

    doc_code = utils.get_sha1_file_hash(args.doc_path)
    if not doc_code == document["doc_code"]:
        print("The doc_code does not match")
        exit()

    # Report generated for --write-report
    report = {
        "doc_code": doc_code,
        "verify_signatures": args.verify,
        "certificates": {}
    }

    print("doc_code: " + document["doc_code"])
    for user_code in list(document["certificates"].keys()):
        v = Verifier(user_code, document["doc_code"], document["certificates"][user_code]["keys"])
        print("-------------")
        print("user_code: " + v.user_code)
        print("sequence_to_find: " + v.sequence_to_find)
        keys_valid = v.verify_all()

        signature_provided = False
        signature_valid = False

        if keys_valid:
            print("All " + str(len(v.keys)) + " keys verified")
            if args.verify:
                if document["certificates"][user_code]["signature"] is None:
                    print("No signature provided")
                else:
                    signature_provided = True
                    certificate_url = utils.get_powcert_url(user_code)
                    if certificate_url is None:
                        print("Certificate URL could not be found")
                    elif not v.verify_signature(document["certificates"][user_code]["signature"],
                                                requests.get(certificate_url).text):
                        print("Signature verification failed")
                    else:
                        signature_valid = True
                        print("Signature OK!")
        else:
            print("Not all keys could be verified")

        report["certificates"][v.user_code] = {
            "sequence_to_find": v.sequence_to_find,
            "keys_valid": keys_valid,
            "signature_provided": signature_provided,
            "signature_valid": signature_valid
        }

    if args.write_report:
        json.dump(report, open(args.write_report, "w"))
