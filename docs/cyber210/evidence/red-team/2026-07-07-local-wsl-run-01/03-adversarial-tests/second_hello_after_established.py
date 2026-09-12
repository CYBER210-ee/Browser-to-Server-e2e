import asyncio
import json
import os
import ssl
import urllib.request

import websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from server.hpke_server import (
    HPKE_INFO,
    SUITE,
    b64url_decode,
    b64url_encode,
    build_t_hello,
)


URI = "wss://echo.server.test/ws"
PUBKEY_URL = "https://echo.server.test/pubkey"


def get_server_keys():
    ssl_context = ssl._create_unverified_context()
    with urllib.request.urlopen(PUBKEY_URL, context=ssl_context) as response:
        data = json.loads(response.read().decode())

    return (
        b64url_decode(data["server_x25519"]),
        b64url_decode(data["server_ed25519"]),
    )


async def main():
    server_x25519, server_ed25519 = get_server_keys()

    browser_x25519_kp = SUITE.kem.derive_key_pair(os.urandom(32))
    browser_x25519 = browser_x25519_kp.public_key.to_public_bytes()

    browser_ed25519_priv = Ed25519PrivateKey.generate()
    browser_ed25519 = browser_ed25519_priv.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )

    server_pk = SUITE.kem.deserialize_public_key(server_x25519)
    enc, sender_ctx = SUITE.create_sender_context(
        pkr=server_pk,
        info=HPKE_INFO,
    )

    t_hello = build_t_hello(
        browser_x25519,
        browser_ed25519,
        enc,
        server_x25519,
        server_ed25519,
    )
    sig = browser_ed25519_priv.sign(t_hello)

    hello = {
        "type": "hello",
        "browser_x25519": b64url_encode(browser_x25519),
        "browser_ed25519": b64url_encode(browser_ed25519),
        "enc": b64url_encode(enc),
        "sig": b64url_encode(sig),
    }

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    try:
        async with websockets.connect(URI, ssl=ssl_context) as ws:
            print("sending first hello")
            await ws.send(json.dumps(hello))

            first_reply = await ws.recv()
            print("received:", first_reply)

            print("sending second hello")
            await ws.send(json.dumps(hello))

            await ws.recv()

    except websockets.exceptions.ConnectionClosed as e:
        print("closed code:", e.code)
        print("closed reason:", e.reason)


asyncio.run(main())
