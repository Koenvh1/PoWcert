from ecdsa import SigningKey

# Script to generate a public and private key
sk = SigningKey.generate()
vk = sk.get_verifying_key()
open("private.pem", "wb").write(sk.to_pem())
open("public.pem", "wb").write(vk.to_pem())
