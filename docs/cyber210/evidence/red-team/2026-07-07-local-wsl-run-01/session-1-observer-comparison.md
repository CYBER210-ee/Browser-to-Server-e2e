# Session 1 Observer Comparison

This comparison summarizes what different observers could see across plaintext, TLS-only, and TLS + HPKE testing.

| Test Model | Observation Point | Result |
|---|---|---|
| Plaintext / no TLS | Internal non-TLS hop between mitmproxy and echo server | The exact test token was readable in cleartext in the tcpdump capture on port 8000. |
| TLS only | Passive observer using Wireshark | TLS traffic and metadata were visible, but the exact plaintext test token was not found in captured packet bytes. |
| TLS only | TLS-terminating proxy using mitmproxy | The full plaintext request and echo response were readable after TLS termination. |
| TLS + HPKE | Passive observer using Wireshark | TLS traffic and metadata were visible, but the exact plaintext test token was not found in captured packet bytes. |
| TLS + HPKE | TLS-terminating proxy using mitmproxy | WebSocket traffic and encrypted ciphertext fields were visible, but the plaintext prompt was not readable. |
| TLS + HPKE | Intended browser | The browser successfully received and displayed the readable echoed message. |

## Summary

Plaintext traffic was readable on the non-TLS internal hop. TLS protected message contents from a passive observer, but the TLS-terminating proxy could still read application plaintext. With browser-to-server HPKE enabled, the TLS-terminating proxy could observe the traffic but could not read the prompt, while the intended browser still received the readable echo.
