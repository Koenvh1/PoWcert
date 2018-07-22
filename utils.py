import hashlib
import zlib

import dns.resolver


def generate_crc32(user_code: str):
    """
    Generate a CRC32 hexadecimal string based on a user_code
    :param user_code: The user_code
    :return: An eight character hexadecimal string (zero-padded)
    """
    # Unique 32-bit key to find, based on the user_code
    sequence_to_find = zlib.crc32(user_code.encode())
    # Take the hex encoding of the unsigned code to find,
    # remove the 0x prefix, and pad with 0 if less than 8 characters
    return hex(sequence_to_find)[2:].zfill(8).lower()


def calculate_key(user_code: str, doc_code: str, i: int):
    """
    Calculate the key for the hash function
    :param user_code: The user_code
    :param doc_code: The doc_code
    :param i: The key
    :return: A 512-bit hexadecimal string
    """
    m = hashlib.sha512()
    # Generate a key based on the doc_code, user_code and key
    key = str(doc_code + user_code + str(i))
    m.update(key.encode())
    return m.hexdigest().lower()


def get_key_signature(user_code: str, doc_code: str, keys: list):
    """
    Get signature that will be signed and verified
    :param user_code: The user_code
    :param doc_code: The doc_code
    :param keys: The list of keys
    :return:
    """
    return (doc_code + "\n" + user_code + "\n" + "\n".join([str(x) for x in keys])).encode()


def get_sha1_file_hash(path: str):
    """
    Get the SHA1-hash for a file
    :param path: Path to the file
    :return: The SHA1-hash as hex string
    """
    m = hashlib.sha1()

    with open(path, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            m.update(data)

    return m.hexdigest().lower()


def get_powcert_url(user_code: str):
    """
    Do a DNS lookup for the domain specified in the user_code
    Check whether it contains a PoWcert= TXT attribute, and if so, return its value
    :param user_code: The user_code
    :return: The URL for this user's public key, or None if not found
    """
    username, domain = user_code.split("@", 1)
    answers = dns.resolver.query(domain, "TXT")

    prefix = "powcert="

    for answer in answers:
        answer = answer.to_text().strip("\"")
        if answer.lower().startswith(prefix):
            answer = answer[len(prefix):]
            answer = answer.replace("{user_code}", user_code)
            return answer

    return None
