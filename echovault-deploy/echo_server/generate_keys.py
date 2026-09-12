"""
generate_keys.py — mint the server's X25519 + Ed25519 keypairs.

Prints the two .env lines and the browser pin. Run once, paste into server/.env
(and echovault-deploy/echo_server/.env); never at server startup.
"""

from hpke_server import b64url_encode, generate_server_keys

g = generate_server_keys()
print(f"SERVER_X25519_PRIVATE_KEY_HEX={g['SERVER_X25519_PRIVATE_KEY_HEX']}")
print(f"SERVER_ED25519_PRIVATE_KEY_HEX={g['SERVER_ED25519_PRIVATE_KEY_HEX']}")
print()
print("# Browser pin (paste into the page's Server key box, protocol §4.1.1):")
print(f"# {b64url_encode(bytes.fromhex(g['ed25519_pub_hex']))}")
