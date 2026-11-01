# CIP-0206 vector check

verify-cip0206.py checks every vector in the CIP-0206 test-vectors.json against a stock OpenSSL that ships ML-DSA and SLH-DSA, so it confirms the whole set independently of our own code.

It reads test-vectors.json from a path you pass, from the current directory, or it fetches the copy in the CIP branch. Run it with

python3 verify-cip0206.py path/to/test-vectors.json

It confirms that every genuine signature verifies, every tampered or mismatched case fails, every encoding has the right layout, and every malformed object is refused, and it exits nonzero if any case is wrong. A clean run reports thirty two passed and zero failed. OpenSSL 3.5 or newer is needed for the post quantum algorithms.
