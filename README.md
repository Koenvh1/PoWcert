# PoWcert

**Author:** Koen van Hove

PoWcert is a decentralised proof of work document signing tool. 
Current document signing methods depend on a central certificate authority 
(or pre-established trust) and authority of one signer. PoWcert requires neither.
It alleviates the problem of trust in a single authority by employing a decentralised herd protection system, 
allowing a single document to be verified by many.

## Inner working
### Generating:  
The user gives the SHA-1 hash of a document 
(the *doc_code*, for example `b55bfb61790e8d4b66660501e9945ed9b33be1d5`), 
his own user identifier (the *user_code*, for example `koen@koenvh.nl`) and his private key (ECDSA NIST192p SHA1). 
The user code and doc code are case insensitive.

The CRC32 of the *user_code* will be calculated, which will be converted to hexadecimal 
(for example `abcd1234`). It will then generate a set of potential keys (where key is a number), by taking the 
SHA-512 hash of the *doc_code* + *user_code* + *key* 
(for example `b55bfb61790e8d4b66660501e9945ed9b33be1d5koen@koenvh.nl512522`).
In this example, this would result in 
`214ec9f614522174b56f0202c66ae7f775b81cffbe8a715f5b2773505b8d53bbcdfd0c64f6465a6657640d418db9c39c3a119402ba106602cf40a928731bd8e7`.
If this sequence of characters contains the CRC32 calculated earlier (in this example `abcd1234`), it is a valid key,
and it will be added to a list of valid keys. 

After the set of potential keys is depleted, a signature will be generated using the private key, 
based on the *doc_code*, *user_code* and *keys*.

### Verifying: 
In order to verify the keys from a user, the user's public key needs to be retrieved. This can be done by making 
a DNS query to the domain from the *user_code*. A TXT record with a value `PoWcert=<server>` will point to the server 
where the public key for this user can be retrieved (for example `PoWcert=https://example.org/certs/{user_code}.pem`). 
The client will then replace the `{user_code}` placeholder with the user_code, and request the public key.

The *doc_code*, *user_code* and *keys* will then be verified using the retrieved public key and the signature provided.

For the _keys_ provided by the user, the SHA-512 and CRC32 hash are calculated in the same way as described above, 
and it is checked that hashes of the keys do indeed contain the CRC32 of the *user_code*.

## Proof of concept

A Python implementation of the specification described above has been implemented.
It requires Python >3.5 to run, along with the following packages:
`pip install dnspython requests ecdsa`