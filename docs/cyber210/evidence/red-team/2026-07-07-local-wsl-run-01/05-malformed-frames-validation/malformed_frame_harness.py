import argparse
import asyncio
import json
import os
import ssl
import urllib.request

import websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hpke_server import (
    HPKE_INFO,
    SUITE,
    b64url_decode,
    b64url_encode,
    build_t_hello,
)


URI = "wss://echo.server.test/ws"
PUBKEY_URL = "https://echo.server.test/pubkey"


TEST_CASES = {
    "missing_ct": {
        "type": "msg",
        "seq": "0000000000000000",
    },
    "missing_seq": {
        "type": "msg",
        "ct": "AAAA",
    },
    "seq_numeric": {
        "type": "msg",
        "seq": 0,
        "ct": "AAAA",
    },
    "seq_empty": {
        "type": "msg",
        "seq": "",
        "ct": "AAAA",
    },
    "seq_invalid_hex": {
        "type": "msg",
        "seq": "zzzzzzzzzzzzzzzz",
        "ct": "AAAA",
    },
    "seq_wrong_length": {
        "type": "msg",
        "seq": "0000",
        "ct": "AAAA",
    },
    "missing_type": {
        "seq": "0000000000000000",
        "ct": "AAAA",
    },
    "unknown_type": {
        "type": "not_a_real_type",
    },
    "ct_empty": {
        "type": "msg",
        "seq": "0000000000000000",
        "ct": "",
    },
    "ct_truncated": {
        "type": "msg",
        "seq": "0000000000000000",
        "ct": "A",
    },
    "ct_invalid_base64url": {
        "type": "msg",
        "seq": "0000000000000000",
        "ct": "%%%%",
    },
}


RAW_TEST_CASES = {
    "non_json": "this is not json",
    "malformed_json": '{"type":"msg","seq":',
}


BATCHES = {
    "missing_fields": [
        "missing_ct",
        "missing_seq",
    ],
    "malformed_seq": [
        "seq_numeric",
        "seq_empty",
        "seq_invalid_hex",
        "seq_wrong_length",
    ],
    "frame_type": [
        "missing_type",
        "unknown_type",
    ],
    "ciphertext_encoding": [
        "ct_empty",
        "ct_truncated",
        "ct_invalid_base64url",
    ],
    "malformed_input": [
        "non_json",
        "malformed_json",
    ],
}


def get_server_keys():
    ssl_context = ssl._create_unverified_context()

    with urllib.request.urlopen(
        PUBKEY_URL,
        context=ssl_context,
    ) as response:
        data = json.loads(response.read().decode())

    return (
        b64url_decode(data["server_x25519"]),
        b64url_decode(data["server_ed25519"]),
    )


def build_hello():
    server_x25519, server_ed25519 = get_server_keys()

    browser_x25519_kp = SUITE.kem.derive_key_pair(os.urandom(32))
    browser_x25519 = browser_x25519_kp.public_key.to_public_bytes()

    browser_ed25519_priv = Ed25519PrivateKey.generate()
    browser_ed25519 = browser_ed25519_priv.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )

    server_pk = SUITE.kem.deserialize_public_key(server_x25519)

    enc, _ = SUITE.create_sender_context(
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

    return {
        "type": "hello",
        "browser_x25519": b64url_encode(browser_x25519),
        "browser_ed25519": b64url_encode(browser_ed25519),
        "enc": b64url_encode(enc),
        "sig": b64url_encode(sig),
    }


def get_ssl_context():
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


async def establish_connection(ws):
    hello = build_hello()

    await ws.send(json.dumps(hello))
    reply = await ws.recv()

    parsed = json.loads(reply)

    if parsed.get("type") != "server_hello":
        raise RuntimeError(
            f"expected server_hello, got: {reply}"
        )

    print("handshake: established")


async def send_test(name):
    print()
    print("=" * 70)
    print(f"TEST: {name}")

    if name in RAW_TEST_CASES:
        payload = RAW_TEST_CASES[name]
        print(f"sent raw: {payload!r}")
    else:
        payload = json.dumps(
            TEST_CASES[name],
            separators=(",", ":"),
        )
        print(f"sent: {payload}")

    try:
        async with websockets.connect(
            URI,
            ssl=get_ssl_context(),
        ) as ws:
            await establish_connection(ws)

            await ws.send(payload)

            try:
                response = await asyncio.wait_for(
                    ws.recv(),
                    timeout=3,
                )

                print(f"received: {response}")
                print("RESULT: connection remained open")

            except asyncio.TimeoutError:
                print("RESULT: no response before timeout")

            except websockets.exceptions.ConnectionClosed as exc:
                print(f"closed code: {exc.code}")
                print(f"closed reason: {exc.reason}")
                print("RESULT: rejected")

    except websockets.exceptions.ConnectionClosed as exc:
        print(f"closed code: {exc.code}")
        print(f"closed reason: {exc.reason}")
        print("RESULT: rejected")

    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}")


async def run_tests(names):
    for name in names:
        await send_test(name)


def main():
    all_tests = list(TEST_CASES) + list(RAW_TEST_CASES)
    choices = all_tests + list(BATCHES) + ["all"]

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--test",
        choices=choices,
        required=True,
    )

    args = parser.parse_args()

    if args.test == "all":
        asyncio.run(run_tests(all_tests))

    elif args.test in BATCHES:
        asyncio.run(run_tests(BATCHES[args.test]))

    else:
        asyncio.run(send_test(args.test))


if __name__ == "__main__":
    main()
