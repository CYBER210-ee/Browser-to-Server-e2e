"""
generate_keys.py — mint the server's Ed25519 identity.

Prints the .env line and the browser pin. Run once, paste into server/.env
(and echovault-deploy/echo_server/.env); never at server startup. There is no
static X25519 key any more (D026/D028): each connection mints its own.
"""

from hpke_server import b64url_encode, generate_server_keys

g = generate_server_keys()
print(f"SERVER_ED25519_PRIVATE_KEY_HEX={g['SERVER_ED25519_PRIVATE_KEY_HEX']}")
print()
print("# Browser pin (paste into the page's Server key box, protocol §4.1.1):")
print(f"# {b64url_encode(bytes.fromhex(g['ed25519_pub_hex']))}")
