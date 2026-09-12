import asyncio
import json
import ssl

import websockets


async def main():
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    uri = "wss://echo.server.test/ws"

    try:
        async with websockets.connect(uri, ssl=ssl_context) as ws:
            frame = {
                "type": "msg",
                "seq": 0,
                "ct": "AAAA"
            }

            print("sending:", json.dumps(frame))
            await ws.send(json.dumps(frame))
            await ws.recv()

    except websockets.exceptions.ConnectionClosed as e:
        print("closed code:", e.code)
        print("closed reason:", e.reason)


asyncio.run(main())
