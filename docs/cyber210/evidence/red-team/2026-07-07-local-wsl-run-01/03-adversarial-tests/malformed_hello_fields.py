import asyncio
import json
import ssl

import websockets


URI = "wss://echo.server.test/ws"

CASES = [
    ("missing enc", {
        "type": "hello",
        "browser_x25519": "AAAA",
        "browser_ed25519": "AAAA",
        "sig": "AAAA",
    }),
    ("missing sig", {
        "type": "hello",
        "browser_x25519": "AAAA",
        "browser_ed25519": "AAAA",
        "enc": "AAAA",
    }),
    ("missing browser_x25519", {
        "type": "hello",
        "browser_ed25519": "AAAA",
        "enc": "AAAA",
        "sig": "AAAA",
    }),
    ("missing browser_ed25519", {
        "type": "hello",
        "browser_x25519": "AAAA",
        "enc": "AAAA",
        "sig": "AAAA",
    }),
    ("invalid hello values", {
        "type": "hello",
        "browser_x25519": "AAAA",
        "browser_ed25519": "AAAA",
        "enc": "AAAA",
        "sig": "AAAA",
    }),
]


async def run_case(name, frame, ssl_context):
    try:
        async with websockets.connect(URI, ssl=ssl_context) as ws:
            print(f"\ncase: {name}")
            print("sending:", json.dumps(frame))
            await ws.send(json.dumps(frame))
            await ws.recv()
    except websockets.exceptions.ConnectionClosed as e:
        print("closed code:", e.code)
        print("closed reason:", e.reason)


async def main():
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    for name, frame in CASES:
        await run_case(name, frame, ssl_context)


asyncio.run(main())
