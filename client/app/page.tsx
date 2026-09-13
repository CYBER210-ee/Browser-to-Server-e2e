/* ============================================================================
 * BOREALIS ASSISTANT — chat front end, now with EchoVault E2E encryption
 * ============================================================================
 *
 * WHAT CHANGED vs the plain chat version?
 *   1) The mnemonic is loaded from the Identity page (localStorage "mnemonic")
 *      and turned into the browser's two key pairs (protocol.md §2).
 *   2) A "Server key" text box + Verify button. On load the box is filled
 *      from the server's own /pubkey (D032) so a rebuilt server with a new
 *      identity needs no copy-paste — trust on first use, and the page says
 *      so. Paste the PIN printed in the server console over it to get the
 *      real out-of-band check back. Verify fetches /pubkey again and runs
 *      the §4.1.1 pin gate; a green stoplight means the served key matched
 *      the pin AND its signature checked out.
 *   3) After a green light, the page opens the WebSocket and waits for the
 *      server's signed `server_key` — a fresh X25519 key minted for THIS
 *      connection (§4.0, ADR 2). It checks it against the pin, mints its own
 *      ephemeral, and only then runs hello / server_hello (§4.2–§4.3). Both
 *      directions seal to keys that die with the connection: a recording of
 *      the wire cannot be opened with anything that survives it.
 *   4) Every message you send is sealed in the browser (HPKE,
 *      ChaCha20-Poly1305) and every echo is opened in the browser — a
 *      TLS-terminating proxy sees only { type, seq, ct }. There is no
 *      plaintext mode (D029).
 *   5) Stored history (ADR 212, protocol.md §9). Each prompt is ALSO sealed to
 *      a random per-epoch key before it leaves the page and rides inside the
 *      sealed msg; the epoch key itself is sealed to your identity key and
 *      uploaded once. The server files blobs it cannot open and pushes them
 *      back right after the handshake — same 24 words, same history, on any
 *      browser. Expiry is the server erasing the epoch key after the window.
 *
 * Extra npm packages this page needs (on top of the original):
 *   npm i @scure/bip39 @noble/hashes @noble/curves \
 *         @hpke/core @hpke/dhkem-x25519 @hpke/chacha20poly1305
 * ========================================================================== */

"use client";
import React, { useState, useEffect, useRef } from 'react';
import Link from "next/link";
import { validateMnemonic, mnemonicToSeed } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
// Crypto building blocks for EchoVault (same libraries the spec was tested with):
import { sha256 } from "@noble/hashes/sha2.js";              // hashing
import { extract, expand } from "@noble/hashes/hkdf.js";     // key derivation
import { ed25519, x25519 } from "@noble/curves/ed25519.js";  // signatures + DH keys
import { CipherSuite, HkdfSha256 } from "@hpke/core";        // HPKE seal/open
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";


/* ----------------------------------------------------------------------------
 * ECHOVAULT PROTOCOL CONSTANTS — frozen values from protocol.md §0 (D011/D013).
 * These byte strings MUST match the server character-for-character, or nothing
 * will decrypt. Think of them as the "dialect" both sides agreed to speak.
 * -------------------------------------------------------------------------- */
const te = new TextEncoder();
const HKDF_SALT = hexToBytes(
  "65b9295c885b667d3ce7d06afaee50edabb816af6f3b64a763d6b75201e6ed95",
);
const INFO_X25519 = te.encode("echovault-x25519-encryption");
const INFO_ED25519 = te.encode("echovault-ed25519-signing");
const HPKE_INFO = te.encode("echovault/hpke/v1");
const LABEL_PUBKEY = te.encode("echovault/pubkey/v2");           // D028
const LABEL_SERVER_KEY = te.encode("echovault/server_key/v1");   // D027
const LABEL_HELLO = te.encode("echovault/hello/v2");             // D027
const LABEL_SERVER_HELLO = te.encode("echovault/server_hello/v2");
const AAD_STATE = te.encode("echovault");
const DIR_C2S = te.encode("c2s"); // browser → server
const DIR_S2C = te.encode("s2c"); // server → browser
const TYPE_MSG = new Uint8Array([0x01]);
const TYPE_EPOCH_KEY = new Uint8Array([0x04]);   // c2s only (§3.0.1, D023)
const TYPE_HISTORY = new Uint8Array([0x05]);     // s2c only
// Storage seals (§9): distinct info strings keep a stored blob from ever being
// confused with a channel frame. Neither is derived from the mnemonic tree.
const INFO_EPOCH_KEY = te.encode("echovault/epoch-key/v1");
const INFO_RECORD = te.encode("echovault/record/v1");
const EPOCH_ID_LEN = 16;

// The HPKE cipher suite: X25519 key agreement + SHA-256 KDF + ChaCha20-Poly1305.
const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
});

/* ----------------------------------------------------------------------------
 * SMALL BYTE HELPERS — encoding rules from protocol.md §6.
 * All binary goes on the wire as base64url WITHOUT padding; seq is 16-char hex.
 * -------------------------------------------------------------------------- */
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function b64u(raw: Uint8Array): string {
  let bin = "";
  raw.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Strict decoder: refuses standard base64 (+ / =) and wrong-length values.
function unb64u(s: string, expectedLen: number): Uint8Array {
  if (typeof s !== "string" || /[+/=]/.test(s)) throw new Error("bad encoding");
  const bin = atob(
    s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4),
  );
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (expectedLen >= 0 && out.length !== expectedLen)
    throw new Error("bad length");
  if (b64u(out) !== s) throw new Error("bad encoding");  //Base64URL non-canonical encoding
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// hpke-js wants standalone ArrayBuffers, not views into shared memory.
function ab(u8: Uint8Array): ArrayBuffer {
  return u8.slice().buffer as ArrayBuffer;
}

function seqToBytes8(seq: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(seq), false);
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// The 37-byte authentication label sealed into every message (protocol §3.1):
// app name ‖ session fingerprint ‖ direction ‖ frame type ‖ counter.
function buildAad(
  sessionId: Uint8Array, dir: Uint8Array, seq: number, type: Uint8Array = TYPE_MSG,
): Uint8Array {
  return concatBytes(AAD_STATE, sessionId, dir, type, seqToBytes8(seq));
}

/* ----------------------------------------------------------------------------
 * STORAGE SEALS — protocol.md §9. Every stored blob is an HPKE single-shot
 * seal (one context, one message) so HPKE keeps owning the nonce (D014).
 * -------------------------------------------------------------------------- */
interface SealedBlob { enc: Uint8Array; ct: Uint8Array }

// The storage AAD binds owner ‖ epoch (§9.4): a blob copied to another owner or
// re-filed under another epoch fails open().
function storageAad(ownerEd: Uint8Array, epochId: Uint8Array): Uint8Array {
  return concatBytes(ownerEd, epochId);
}

async function sealTo(
  recipientPub: Uint8Array, plaintext: Uint8Array, info: Uint8Array, aad: Uint8Array,
): Promise<SealedBlob> {
  const pk = await suite.kem.importKey("raw", ab(recipientPub), true);
  const ctx = await suite.createSenderContext({ recipientPublicKey: pk, info: ab(info) });
  const ct = new Uint8Array(await ctx.seal(ab(plaintext), ab(aad)));
  return { enc: new Uint8Array(ctx.enc), ct };
}

async function openFrom(
  recipientScalar: Uint8Array, blob: SealedBlob, info: Uint8Array, aad: Uint8Array,
): Promise<Uint8Array> {
  const sk = await suite.kem.importKey("raw", ab(recipientScalar), false);
  const ctx = await suite.createRecipientContext({
    recipientKey: sk, enc: ab(blob.enc), info: ab(info),
  });
  return new Uint8Array(await ctx.open(ab(blob.ct), ab(aad)));
}

// An epoch (§9.1): a RANDOM X25519 keypair + random id. Random on purpose —
// anything derived from the mnemonic could be re-derived forever and so could
// never expire. The scalar lives in memory for the session and, sealed to the
// identity key, on the server host until the server erases it.
interface Epoch {
  id: Uint8Array;        // 16 bytes
  scalar: Uint8Array;    // X25519 private key (opens records of this epoch)
  pub: Uint8Array;       // X25519 public key (records are sealed TO this)
  createdAt: number;     // UNIX seconds — server clock once uploaded
}

interface HistoryPolicy { epochLengthS: number; windowS: number }

/* ----------------------------------------------------------------------------
 * IDENTITY — protocol.md §2: one mnemonic → two unrelated key pairs.
 * The mnemonic comes from the Identity page ("Key Vault"), which saved it in
 * localStorage under "mnemonic". Same words in = same keys out, every time.
 * -------------------------------------------------------------------------- */
interface Identity {
  xScalar: Uint8Array;  // X25519 private key — STORAGE identity: opens epoch keys (§9.2)
  xPub: Uint8Array;     // X25519 public key — epoch keys are sealed TO this; never on the channel (D026)
  edSeed: Uint8Array;   // Ed25519 private key (signs our half of the handshake)
  edPub: Uint8Array;    // Ed25519 public key (server checks our signature with this)
}

// The per-connection recipient keypair (D026). Minted after `server_key`
// verifies, used for the server→browser context, zeroed at teardown.
interface Ephemeral { scalar: Uint8Array; pub: Uint8Array }

async function deriveIdentity(mnemonic: string): Promise<Identity> {
  // Standard BIP-39 words → 64-byte seed, then HKDF splits it into the two
  // independent keys using the frozen salt/labels above.
  const seed = await mnemonicToSeed(mnemonic, "");
  const prk = extract(sha256, seed, HKDF_SALT);
  const xScalar = expand(sha256, prk, INFO_X25519, 32);
  const edSeed = expand(sha256, prk, INFO_ED25519, 32);
  return {
    xScalar,
    xPub: x25519.getPublicKey(xScalar),
    edSeed,
    edPub: ed25519.getPublicKey(edSeed),
  };
}

/* ----------------------------------------------------------------------------
 * THE SHAPE OF DATA (unchanged from the original page)
 * -------------------------------------------------------------------------- */
type Sender = 'user' | 'assistant';

interface ChatMessage {
  id: number;         // render identity — unique for the page's lifetime.
                      // seq is NOT usable as a React key: it resets to 0 on
                      // every new session (re-handshakes).
  seq: number;        // a counter/ID number for ordering messages (0, 1, 2, ...)
  text: string;       // the actual words of the message
  type: string;       // a label for the kind of message (e.g. 'msg')
  sender: Sender;     // who sent it: 'user' or 'assistant'
  timestamp: string;  // a human-readable time, e.g. "3:42:10 PM"
  restored?: boolean; // came back in the history push (§5.4.2), not typed now;
                      // echoes are rebuilt from the stored prompt (D025)
}

// Traffic-light states for the server-key check.
type PinStatus = 'unchecked' | 'valid' | 'invalid';

// Where the pin in the box came from (D032). 'server' is trust on first use:
// the key was learned from the same server it is about to authenticate.
type PinSource = 'server' | 'pasted';

/* ----------------------------------------------------------------------------
 * THE COMPONENT
 * -------------------------------------------------------------------------- */
export default function ChatApp() {

  /* ---------------------------- chat state ------------------------------ */
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [isConnected, setIsConnected] = useState(false);
  const [isTyping, setIsTyping] = useState(false);

  // ---- Sequence state ----
  // c2sSeq : next client→server seq to send (must track the HPKE context's
  //          internal counter one-for-one, so ONLY advance it after a seal).
  // lastS2C: highest server→client seq already accepted. Starts at -1 so the
  //          first server frame (seq 0) is accepted. In encrypted mode the
  //          check is STRICT (must be exactly lastS2C+1): a gap or repeat is
  //          a protocol fault and tears the channel down (protocol §7.3).
  const c2sSeq = useRef<number>(0);
  const lastS2C = useRef<number>(-1);

  // Monotonic id for React keys — never resets, unlike the per-session seq.
  const nextMsgId = useRef<number>(0);

  const socketRef = useRef<WebSocket | null>(null);
  const endRef = useRef<HTMLDivElement | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const typingTimeout = useRef<ReturnType<typeof setTimeout> | null>(null);

  /* ------------------------- EchoVault state ---------------------------- */
  // The server public key (Ed25519, base64url) — the PIN. The real trust root
  // is a pin that comes to you OUTSIDE the connection (the server prints it in
  // its own console at startup). For the demo the box is pre-filled from
  // /pubkey on load instead (D032) — see pinSource.
  const [serverPinInput, setServerPinInput] = useState('');
  const [pinSource, setPinSource] = useState<PinSource>('pasted');
  // Set once the user types in the box, so a slow /pubkey never overwrites it.
  const pinEdited = useRef(false);
  // Traffic light: did the served /pubkey match the pasted pin + valid signature?
  const [pinStatus, setPinStatus] = useState<PinStatus>('unchecked');
  const [hasSavedMnemonic, setHasSavedMnemonic] = useState(false);
  const [channelEstablished, setEncChannel] = useState(false);
  const [statusNote, setStatusNote] = useState('');

  // The mnemonic itself, loaded from the Identity page's saved variable.
  const mnemonicRef = useRef<string>('');

  // Everything crypto about the CURRENT link lives in this one box. It's a
  // ref (not state) because none of it should redraw the screen, and it must
  // never be half-updated: teardown wipes it all at once.
  const link = useRef<{
    identity: Identity | null;                                            // our keys
    pinnedEd: Uint8Array | null;                                          // trusted server signing key
    serverEph: Uint8Array | null;                                         // this connection's server recipient key (§4.0.1)
    browserEph: Ephemeral | null;                                         // this connection's own recipient key (D026)
    awaitingServerKey: boolean;                                           // AWAIT_SERVER_KEY phase (§5.6)
    sender: Awaited<ReturnType<CipherSuite["createSenderContext"]>> | null;   // seals c2s
    recipient: Awaited<ReturnType<CipherSuite["createRecipientContext"]>> | null; // opens s2c
    sessionId: Uint8Array | null;                                         // this handshake's fingerprint
    tServerKey: Uint8Array | null;                                        // the server_key transcript we accepted
    tHello: Uint8Array | null;                                            // our signed hello bytes
    awaitingHistory: boolean;                                             // AWAIT_HISTORY phase (§5.6)
    policy: HistoryPolicy | null;                                         // from the history push
    epochs: Map<string, Epoch>;                                           // b64u(id) → epoch, live ones only
  }>({
    identity: null, pinnedEd: null, serverEph: null, browserEph: null, awaitingServerKey: false,
    sender: null, recipient: null, sessionId: null, tServerKey: null, tHello: null,
    awaitingHistory: false, policy: null, epochs: new Map(),
  });

  /* ---------------------------- auto-scroll ----------------------------- */
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [messages, isTyping]);

  /* --------------- load the mnemonic from the Identity page ------------- */
  // The Identity page ("Key Vault") stores the mnemonic in localStorage under
  // the key "mnemonic". We load it once, validate the words, and derive the
  // browser's key pairs from it. No mnemonic → no identity → the Verify /
  // handshake path below refuses to run (fail closed).
  useEffect(() => {
    const savedMnemonic = localStorage.getItem("mnemonic") ?? "";
    if (savedMnemonic.trim() && validateMnemonic(savedMnemonic.trim(), wordlist)) {
      mnemonicRef.current = savedMnemonic.trim();
      setHasSavedMnemonic(true);
      deriveIdentity(mnemonicRef.current)
        .then((id) => { link.current.identity = id; })
        .catch(() => setHasSavedMnemonic(false));
    } else {
      setHasSavedMnemonic(false);
    }
  }, []);

  // Hang up the phone line if the user leaves the page.
  useEffect(() => {
    return () => {
      if (typingTimeout.current) clearTimeout(typingTimeout.current);
      socketRef.current?.close();
    };
  }, []);

  /* ------------------------------ teardown ------------------------------ */
  // EchoVault is fail-closed (protocol §7.3/§7.4): on ANY fault — bad
  // signature, wrong counter, tampered ciphertext, unexpected frame — we
  // abandon the whole encrypted channel and require a fresh Verify+handshake.
  // We never try to "keep going" on a connection we no longer trust.
  const teardown = (note: string) => {
    socketRef.current?.close();
    socketRef.current = null;
    link.current.sender = null;
    link.current.recipient = null;
    link.current.sessionId = null;
    link.current.tServerKey = null;
    link.current.tHello = null;
    // Per-connection recipient keys die with the connection (D026): zero ours,
    // forget theirs. This is what makes a recording of the wire unrecoverable.
    link.current.browserEph?.scalar.fill(0);
    link.current.browserEph = null;
    link.current.serverEph = null;
    link.current.awaitingServerKey = false;
    // Nothing about history is persisted in the browser (§9.6): zero the epoch
    // scalars and forget them. The next handshake gets them back from the server.
    for (const e of link.current.epochs.values()) e.scalar.fill(0);
    link.current.epochs.clear();
    link.current.policy = null;
    link.current.awaitingHistory = false;
    c2sSeq.current = 0;
    lastS2C.current = -1;
    setEncChannel(false);
    setIsConnected(false);
    setIsTyping(false);
    setStatusNote(note);
  };

  /* -------------------- server base URLs (HTTP + WS) -------------------- */
// One env var, HTTP-flavored. The echo server always speaks TLS itself
// (D030), so the default is the local server's https port; in the cloud it is
// the reverse proxy's public name for the server you picked.
//   NEXT_PUBLIC_API_URL=https://localhost:8443
const httpBase =
  process.env.NEXT_PUBLIC_API_URL ?? 'https://localhost:8443';

// The WS base is DERIVED: https→wss, http→ws. Same host, same TLS decision.
const wsBase =
  process.env.NEXT_PUBLIC_WS_URL ?? httpBase.replace(/^http/, 'ws');

  /* ---------- pre-fill the pin from the server itself (D032, TOFU) -------- */
  // The self-licking ice cream, on purpose: we ask the server which key to
  // trust and then check the server against that answer. Whoever answers this
  // first fetch — the server, or anything that terminates TLS in front of it —
  // chooses the pin, and every gate below then passes against THEIR key. It
  // saves re-pasting after every rebuild; pasting the console pin over it is
  // what restores the out-of-band guarantee of §4.1.1.
  useEffect(() => {
    fetch(`${httpBase}/pubkey`)
      .then((res) => res.json())
      .then((pk) => {
        unb64u(pk.server_ed25519, 32);             // well-formed or nothing
        if (pinEdited.current) return;
        setServerPinInput(pk.server_ed25519);
        setPinSource('server');
      })
      .catch(() => {
        if (!pinEdited.current)
          setStatusNote('Could not fetch /pubkey — is the server up and its CA trusted? Paste the pin from the server console.');
      });
  }, [httpBase]);

  /* ------------------- VERIFY BUTTON: the §4.1.1 pin gate ---------------- */
  // What happens when you click Verify, in plain English:
  //   1. Take the key in the box (the pin) — that is the only thing we trust.
  //      If it was pre-filled from /pubkey (D032), steps 3–4 confirm only
  //      that the server agrees with itself.
  //   2. Fetch /pubkey from the server. Whatever comes back is UNTRUSTED
  //      input; it exists only so we can compare it against the pin.
  //   3. Compare the served signing key to the pin, byte for byte. Mismatch
  //      → red light, stop. (A middleman swapping keys is caught right here.)
  //   4. Check the signature over the served key using the pinned key.
  //   5. Only then light up GREEN. There is no encryption key here any more
  //      (D028): the server's recipient key arrives per connection, signed, as
  //      the first WebSocket frame (see establishChannel below).
  const handleVerify = async () => {
    try {
      setStatusNote('');
      if (!link.current.identity) {
        setPinStatus('unchecked');
        setStatusNote('No valid mnemonic — create one on the Key Vault page first.');
        return;
      }
      const pinText = serverPinInput.trim();
      if (!pinText) {
        // No pin provisioned → refuse to handshake at all (fail closed, §4.1.1).
        setPinStatus('unchecked');
        setStatusNote('No server key — reload to fetch it, or paste the one printed in the server console.');
        return;
      }
      const pinnedEd = unb64u(pinText, 32);

      const res = await fetch(`${httpBase}/pubkey`);
      const pk = await res.json();
      const wireEd = unb64u(pk.server_ed25519, 32);
      const sig = unb64u(pk.sig, 64);

      // Step 3 — pin comparison FIRST. The wire never teaches us a new key.
      if (!bytesEqual(wireEd, pinnedEd)) throw new Error('pin mismatch');

      // Step 4 — signature over label ‖ signing key (§4.1, v2).
      const tPubkey = concatBytes(LABEL_PUBKEY, wireEd);
      if (!ed25519.verify(sig, tPubkey, pinnedEd)) throw new Error('bad sig');

      // Step 5 — the pin is confirmed live. Everything else arrives on the socket.
      link.current.pinnedEd = pinnedEd;
      setPinStatus('valid');
      setStatusNote(pinSource === 'server'
        ? 'Server key matches the key this server served on load (trust on first use, not out-of-band) — establishing encrypted channel…'
        : 'Server key verified against pin — establishing encrypted channel…');

      await establishChannel();
    } catch {
      // One uniform failure path: red light, no channel, no detail an
      // attacker could learn from.
      link.current.pinnedEd = null;
      setPinStatus('invalid');
      teardown('Server key verification failed — channel not established.');
    }
  };

  /* --------- THE HANDSHAKE: server_key / hello / server_hello ----------- */
  // Runs only after the green light. In plain English:
  //   0. Open the socket and WAIT. The server speaks first: a fresh X25519
  //      key for this connection, signed by its identity ("server_key").
  //      Check the signature with the PIN, never with a key off the wire.
  //   1. Mint our own fresh X25519 key for this connection, then create our
  //      outgoing encryption "pipe" aimed at the server's fresh key; this
  //      mints a one-time key share ("enc") to send along.
  //   2. Sign a transcript of everything that matters (our fresh key, our
  //      identity, our enc, the server's fresh key, the PIN) and send it as
  //      "hello".
  //   3. Wait for "server_hello". Rebuild the transcript the server should
  //      have signed — from OUR OWN values, the key we accepted in step 0 and
  //      the PIN, never from the wire — and check the signature with the
  //      pinned key. If a middleman swapped anything (even just our own key
  //      on its way to the server!), this check fails and we abort BEFORE any
  //      message is ever sealed (§4.3.1).
  //   4. Derive the session fingerprint and open our incoming pipe on our
  //      fresh key. Then wait for the history push; then the Encrypt toggle
  //      comes alive.
  // Both fresh keys are zeroed at teardown, so nothing that survives the
  // connection can open a recording of it (D026).
  const establishChannel = async () => {
    // Fresh counters for a fresh handshake (a new session restarts at 0).
    c2sSeq.current = 0;
    lastS2C.current = -1;

    const ws = new WebSocket(`${wsBase}/ws`);
    socketRef.current = ws;
    link.current.awaitingServerKey = true;

    ws.onopen = () => {
      setIsConnected(true);
      setStatusNote('Connected — waiting for the server\u2019s connection key…');
    };
    ws.onerror = () => teardown('Connection error.');
    ws.onclose = () => {
      if (socketRef.current !== ws) return;
      setIsConnected(false);
      setEncChannel(false);
    };
    ws.onmessage = (event) => {
      // Any fault — bad signature, wrong counter, tampered ciphertext,
      // unexpected frame — abandons the whole channel (§7.3/§7.4).
      handleFrame(event.data as string).catch(() => {
        teardown('Encrypted channel fault — torn down. Verify again to reconnect.');
      });
    };
  };

  /* --------------- INCOMING FRAMES (handshake + sealed msgs) ------------- */
  const handleFrame = async (raw: string) => {
    const L = link.current;
    const data = JSON.parse(raw);
    if (typeof data !== 'object' || data === null) throw new Error('bad frame');

    // The server's uniform rejection — it already tore the link down.
    if (data.type === 'error') throw new Error('server rejected');

    // ---------- AWAIT_SERVER_KEY: the server's fresh key (§4.0.1) ----------
    if (L.awaitingServerKey) {
      if (data.type !== 'server_key') throw new Error('wrong frame for phase');
      const id = L.identity!;
      const pinnedEd = L.pinnedEd!;
      const serverEph = unb64u(data.server_x25519, 32);
      const sig = unb64u(data.sig, 64);

      // Step 0 — the transcript is rebuilt from the PIN, so a proxy that
      // re-signs a key of its own fails here, before we mint anything.
      const tServerKey = concatBytes(LABEL_SERVER_KEY, serverEph, pinnedEd);
      if (!ed25519.verify(sig, tServerKey, pinnedEd)) throw new Error('server_key rejected');
      L.serverEph = serverEph;
      L.tServerKey = tServerKey;
      L.awaitingServerKey = false;

      // Step 1 — our fresh key for this connection + outgoing pipe to theirs.
      const scalar = x25519.utils.randomSecretKey();
      L.browserEph = { scalar, pub: x25519.getPublicKey(scalar) };
      const serverPk = await suite.kem.importKey("raw", ab(serverEph), true);
      const sender = await suite.createSenderContext({
        recipientPublicKey: serverPk,
        info: ab(HPKE_INFO),
      });
      const enc = new Uint8Array(sender.enc);

      // Step 2 — signed hello transcript (§4.2, v2).
      const tHello = concatBytes(LABEL_HELLO, L.browserEph.pub, id.edPub, enc, serverEph, pinnedEd);
      const helloSig = ed25519.sign(tHello, id.edSeed);
      L.sender = sender;
      L.tHello = tHello;
      socketRef.current!.send(JSON.stringify({
        type: "hello",
        browser_x25519: b64u(L.browserEph.pub),
        browser_ed25519: b64u(id.edPub),
        enc: b64u(enc),
        sig: b64u(helloSig),
      }));
      return;
    }

    // -------- waiting for server_hello (strict state machine, §5.6) --------
    if (L.recipient === null) {
      if (data.type !== 'server_hello') throw new Error('wrong frame for phase');
      const encS2c = unb64u(data.enc, 32);
      const sig = unb64u(data.sig, 64);

      // Step 3 of the handshake (see establishChannel comment): rebuild the
      // transcript from our own fresh key, the server key we accepted, and
      // the pin — then verify with the pin (§4.3.1).
      const tServerHello = concatBytes(
        LABEL_SERVER_HELLO, encS2c, L.browserEph!.pub, L.identity!.edPub,
        L.serverEph!, L.pinnedEd!,
      );
      if (!ed25519.verify(sig, tServerHello, L.pinnedEd!))
        throw new Error('server_hello rejected');

      // Step 4 — session fingerprint over all three transcripts (§3.0) +
      // incoming pipe on OUR FRESH KEY. Not live yet: the server's very next
      // frame is the history push (§5.4.2), and we need our epoch keys from
      // it before we can seal a prompt.
      L.sessionId = sha256(concatBytes(L.tServerKey!, L.tHello!, tServerHello)).slice(0, 16);
      const myPriv = await suite.kem.importKey("raw", ab(L.browserEph!.scalar), false);
      L.recipient = await suite.createRecipientContext({
        recipientKey: myPriv,
        enc: ab(encS2c),
        info: ab(HPKE_INFO),
      });
      L.awaitingHistory = true;
      setStatusNote('Handshake done — waiting for history…');
      return;
    }

    // ------------------- AWAIT_HISTORY: the one-time push -------------------
    // Strict: it must be a `history` frame at s2c seq 0, opened with TYPE 0x05.
    // Anything else here is a fault (§5.6).
    if (L.awaitingHistory) {
      if (data.type !== 'history') throw new Error('wrong frame for phase');
      if (data.seq !== '0000000000000000') throw new Error('seq gate');
      const ct = unb64u(data.ct, -1);
      if (ct.length < 16) throw new Error('bad ct');
      const aad = buildAad(L.sessionId!, DIR_S2C, 0, TYPE_HISTORY);
      const pt = await L.recipient.open(ab(ct), ab(aad));
      lastS2C.current = 0;
      await restoreHistory(JSON.parse(new TextDecoder().decode(pt)));
      L.awaitingHistory = false;
      setEncChannel(true);
      setStatusNote('Encrypted channel established.');
      return;
    }

    // ----------------------- established: sealed msg -----------------------
    // Only a sealed {type, seq, ct} block is legal here. Anything else — a
    // 'text' field, a missing ct — is a fault: there is no plaintext mode.
    if (data.type !== 'msg' || typeof data.ct !== 'string' || 'text' in data)
      throw new Error('wrong frame for phase');

    setIsTyping(false);

    // The counter must be EXACTLY the next one (16-char lowercase hex).
    // Anything else — repeat, gap, garbage — is a fault.
    if (typeof data.seq !== 'string' || !/^[0-9a-f]{16}$/.test(data.seq))
      throw new Error('malformed seq');
    const seq = parseInt(data.seq, 16);
    if (seq !== lastS2C.current + 1) throw new Error('seq gate');

    // Rebuild the authentication label from what WE know and open the
    // ciphertext. Wrong session, direction, type, counter, or a single
    // flipped bit → open() throws → teardown (caught by the caller).
    const ct = unb64u(data.ct, -1);
    if (ct.length < 16) throw new Error('bad ct');
    const aad = buildAad(L.sessionId!, DIR_S2C, seq);
    const pt = await L.recipient.open(ab(ct), ab(aad));
    lastS2C.current = seq;

    const incoming: ChatMessage = {
      id: nextMsgId.current++,
      seq,
      text: new TextDecoder().decode(pt),
      type: 'msg',
      sender: 'assistant',
      timestamp: new Date().toLocaleTimeString(),
    };
    setMessages((prev) => [...prev, incoming]);
  };

  /* --------------------------- STORED HISTORY ---------------------------- */
  // The history push (§5.4.2), in plain English:
  //   1. Every live epoch key comes back sealed to OUR identity key — open it
  //      with the X25519 scalar the mnemonic gave us (§9.2). Any browser with
  //      the same 24 words can; the server never could.
  //   2. Every record is sealed to one of those epoch keys — open it (§9.3).
  //   3. Rebuild the transcript: the prompt, then the echo the server would
  //      have sent (it is deterministic, D025), both marked "restored".
  // A blob that fails to open is skipped, never rendered. The transcript is
  // REPLACED, not appended to: what the server holds is the conversation.
  const restoreHistory = async (h: {
    policy: { epoch_length_s: number; window_s: number };
    epochs: { epoch: string; created_at: number; enc: string; ct: string }[];
    records: { epoch: string; created_at: number; enc: string; ct: string }[];
  }) => {
    const L = link.current;
    const id = L.identity!;
    if (typeof h?.policy?.epoch_length_s !== 'number' || typeof h?.policy?.window_s !== 'number')
      throw new Error('bad history');
    L.policy = { epochLengthS: h.policy.epoch_length_s, windowS: h.policy.window_s };

    for (const e of h.epochs ?? []) {
      const epochId = unb64u(e.epoch, EPOCH_ID_LEN);
      const scalar = await openFrom(
        id.xScalar, { enc: unb64u(e.enc, 32), ct: unb64u(e.ct, 48) },
        INFO_EPOCH_KEY, storageAad(id.edPub, epochId),
      );
      L.epochs.set(e.epoch, {
        id: epochId, scalar, pub: x25519.getPublicKey(scalar), createdAt: e.created_at,
      });
    }

    const restored: ChatMessage[] = [];
    for (const r of h.records ?? []) {
      const epoch = L.epochs.get(r.epoch);
      if (!epoch) continue;                       // its key was erased: unrecoverable by design
      let text: string;
      let ts: number;
      try {
        const pt = await openFrom(
          epoch.scalar, { enc: unb64u(r.enc, 32), ct: unb64u(r.ct, -1) },
          INFO_RECORD, storageAad(id.edPub, epoch.id),
        );
        const rec = JSON.parse(new TextDecoder().decode(pt));
        if (typeof rec?.text !== 'string') continue;
        text = rec.text;
        ts = typeof rec.ts === 'number' ? rec.ts : r.created_at * 1000;
      } catch {
        continue;                                  // wrong owner/epoch or corrupt: not shown
      }
      const when = new Date(ts).toLocaleString();
      restored.push({
        id: nextMsgId.current++, seq: -1, text, type: 'msg', sender: 'user',
        timestamp: when, restored: true,
      });
      restored.push({
        id: nextMsgId.current++, seq: -1, text: `ECHO: ${text}`, type: 'msg', sender: 'assistant',
        timestamp: when, restored: true,
      });
    }
    setMessages(restored);
  };

  // The epoch to seal the next record to (§9.5): reuse the newest live epoch
  // while it is younger than EPOCH_LENGTH, otherwise mint a fresh random one,
  // seal its scalar to our identity key, and upload it in an `epoch_key` frame
  // BEFORE the msg that will reference it. Both frames share the c2s counter.
  const ensureEpoch = async (ws: WebSocket): Promise<Epoch> => {
    const L = link.current;
    const id = L.identity!;
    const nowS = Math.floor(Date.now() / 1000);
    let newest: Epoch | null = null;
    for (const e of L.epochs.values())
      if (!newest || e.createdAt > newest.createdAt) newest = e;
    if (newest && nowS - newest.createdAt < L.policy!.epochLengthS) return newest;

    const scalar = x25519.utils.randomSecretKey();
    const epoch: Epoch = {
      id: crypto.getRandomValues(new Uint8Array(EPOCH_ID_LEN)),
      scalar, pub: x25519.getPublicKey(scalar), createdAt: nowS,
    };
    const sealed = await sealTo(id.xPub, scalar, INFO_EPOCH_KEY, storageAad(id.edPub, epoch.id));
    const pt = te.encode(JSON.stringify({
      epoch: b64u(epoch.id), enc: b64u(sealed.enc), ct: b64u(sealed.ct),
    }));
    const seq = c2sSeq.current;
    const aad = buildAad(L.sessionId!, DIR_C2S, seq, TYPE_EPOCH_KEY);
    const ct = new Uint8Array(await L.sender!.seal(ab(pt), ab(aad)));
    ws.send(JSON.stringify({
      type: 'epoch_key', seq: seq.toString(16).padStart(16, '0'), ct: b64u(ct),
    }));
    c2sSeq.current += 1;                           // one seal, one counter tick
    L.epochs.set(b64u(epoch.id), epoch);
    return epoch;
  };

  /* ------------------------------ SENDING -------------------------------- */
  const handleSend = async (e?: React.FormEvent) => {
    e?.preventDefault();

    const text = inputValue.trim();
    if (!text) return;

    const ws = socketRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      setStatusNote('Not connected — verify the server key first.');
      return;
    }

    const ready =
      channelEstablished && !!link.current.sender && !!link.current.sessionId &&
      !!link.current.policy;
    if (!ready) {
      // Fail closed: there is no plaintext path to fall back to (D029).
      setStatusNote('Channel not ready — press Verify to reconnect.');
      return;
    }

    // What we show in OUR OWN transcript (always the readable words — it's our
    // message; encryption only changes what goes over the wire).
    const localEcho: ChatMessage = {
      id: nextMsgId.current++,
      seq: c2sSeq.current,
      text,
      type: 'msg',
      sender: 'user',
      timestamp: new Date().toLocaleTimeString(),
    };

    try {
      {
        // First make sure an epoch key is live (this may send
        // an `epoch_key` frame and tick the counter). Then seal the prompt to
        // the epoch key for storage (§9.3), wrap words + record into the §7.5
        // plaintext, build the authentication label for "browser→server, msg,
        // counter N", seal, and put ONLY {type, seq, ct} on the wire. A proxy
        // that terminates TLS sees ciphertext, not words — and so does the
        // server for the stored copy.
        const epoch = await ensureEpoch(ws);
        const id = link.current.identity!;
        const rec = await sealTo(
          epoch.pub, te.encode(JSON.stringify({ text, ts: Date.now() })),
          INFO_RECORD, storageAad(id.edPub, epoch.id),
        );
        const plaintext = te.encode(JSON.stringify({
          text, rec: { epoch: b64u(epoch.id), enc: b64u(rec.enc), ct: b64u(rec.ct) },
        }));
        const currentSeq = c2sSeq.current;
        localEcho.seq = currentSeq;
        const aad = buildAad(link.current.sessionId!, DIR_C2S, currentSeq, TYPE_MSG);
        const ct = new Uint8Array(await link.current.sender!.seal(ab(plaintext), ab(aad)));
        ws.send(JSON.stringify({
          type: 'msg',
          seq: currentSeq.toString(16).padStart(16, '0'),
          ct: b64u(ct),
        }));
      }
    } catch {
      teardown('Failed to seal message — channel torn down.');
      return;
    }

    // Optimistically render our own message immediately.
    setMessages((prev) => [...prev, localEcho]);
    setInputValue('');

    // Advance the counter only AFTER a successful seal+send, so it stays in
    // lock-step with the encryption pipe's internal counter.
    c2sSeq.current += 1;

    setIsTyping(true);
    if (typingTimeout.current) clearTimeout(typingTimeout.current);
    typingTimeout.current = setTimeout(() => setIsTyping(false), 12000);

    if (textareaRef.current) textareaRef.current.style.height = 'auto';
  };

  /* --------------------- keyboard + auto-grow (unchanged) ---------------- */
  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleInput = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInputValue(e.target.value);
    const el = e.target;
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 160) + 'px';
  };

  /* ========================================================================
   * THE VISIBLE LAYOUT (HTML / JSX)
   * ====================================================================== */
  return (
    <div className="cg-app">
      <div className="cg-window">

        {/* ---------- Header ---------- */}
        <header className="cg-header">
          <div className="cg-brand">
            <div className="cg-logo">
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none">
                <path
                  d="M12 2l1.9 4.7L19 8l-4.1 1.3L13 14l-1.4-4.5L7 8l4.6-1.3L12 2z"
                  fill="#fff"
                />
                <circle cx="18.5" cy="17.5" r="1.6" fill="#fff" />
                <circle cx="6" cy="16" r="1.1" fill="#fff" />
              </svg>
            </div>

            <div className="cg-titles">
              <h1 className="cg-title">Borealis Assistant</h1>
              <span className={`cg-status ${isConnected ? 'on' : 'off'}`}>
                <span className="cg-dot" />
                {isConnected ? 'Online' : 'Connecting…'}
              </span>
            </div>
          </div>
          <div className="cg-header-actions">
            <a className="cg-mnemonic-btn" href="/identity">Key Vault</a>
          </div>
        </header>

        {/* ---------- Key bar: identity + server-key verification ---------- */}
        <div className="cg-keybar">
          {/* Light 1: does the Identity page have a valid saved mnemonic? */}
          <span className="cg-keychip">
            <span className={`cg-light ${hasSavedMnemonic ? "green" : "red"}`} />
            Mnemonic Saved
          </span>

          {/* Light 2: the /pubkey stoplight. Green ONLY after the served key
              matched the pin byte-for-byte AND its signature verified. A pin
              pre-filled from /pubkey is labelled TOFU (D032). */}
          <span className="cg-keychip">
            <span
              className={`cg-light ${
                pinStatus === 'valid' ? 'green' : pinStatus === 'invalid' ? 'red' : ''
              }`}
              style={pinStatus === 'unchecked' ? { background: '#999' } : undefined}
            />
            Server Key {pinStatus === 'valid' ? 'Verified' : pinStatus === 'invalid' ? 'REJECTED' : 'Unverified'}
            {pinSource === 'server' && ' · TOFU'}
          </span>

          {/* Light 3: is the end-to-end channel actually up? */}
          <span className="cg-keychip">
            <span className={`cg-light ${channelEstablished ? "green" : "red"}`} />
            E2E Channel
          </span>
        </div>

        {/* The pin box + Verify button. Pre-filled from /pubkey on load
            (D032) — a key the network handed you, and the TOFU chip says so.
            Paste the base64url Ed25519 key the server printed at startup to
            make it OUT-OF-BAND again (read it off the server console yourself). */}
        <div
          className="cg-pinbar"
          style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '8px 16px' }}
        >
          <input
            value={serverPinInput}  className="cg-input"
            onChange={(e) => {
              pinEdited.current = true;
              setServerPinInput(e.target.value);
              setPinSource('pasted');
              setPinStatus('unchecked');
            }}
            placeholder="Paste server public key (Ed25519, base64url) from server console"
            style={{ flex: 1, fontFamily: 'monospace', fontSize: 12, padding: '6px 10px' }}
            spellCheck={false}
          />
          <button className="cg-mnemonic-btn"
            type="button"
            onClick={handleVerify}
            disabled={!hasSavedMnemonic}
            title={hasSavedMnemonic ? 'Verify against /pubkey and connect' : 'Save a mnemonic on the Key Vault page first'}
          >
            Verify
          </button>
        </div>
        {statusNote && (
          <p style={{ margin: '0 16px 8px', fontSize: 12, opacity: 0.8 }}>{statusNote}</p>
        )}

        {/* ---------- Transcript ---------- */}
        <div className="cg-transcript">

          {messages.length === 0 && !isTyping && (
            <div className="cg-empty">
              <div className="cg-empty-orb">
                <svg viewBox="0 0 24 24" width="34" height="34" fill="none">
                  <path
                    d="M12 2l1.9 4.7L19 8l-4.1 1.3L13 14l-1.4-4.5L7 8l4.6-1.3L12 2z"
                    fill="#fff"
                  />
                </svg>
              </div>
              <h2 className="cg-empty-title">How can I help you today?</h2>
              <p className="cg-empty-sub">
                Ask me anything — your conversation starts here.
              </p>
            </div>
          )}

          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`cg-row ${msg.sender}`}
            >
              <div className={`cg-avatar ${msg.sender}`}>
                {msg.sender === 'assistant' ? (
                  <svg viewBox="0 0 24 24" width="16" height="16" fill="none">
                    <path
                      d="M12 2l1.9 4.7L19 8l-4.1 1.3L13 14l-1.4-4.5L7 8l4.6-1.3L12 2z"
                      fill="#fff"
                    />
                  </svg>
                ) : (
                  <svg viewBox="0 0 24 24" width="16" height="16" fill="none">
                    <circle cx="12" cy="8" r="3.4" fill="#fff" />
                    <path
                      d="M4.5 19c.8-3.4 3.7-5 7.5-5s6.7 1.6 7.5 5"
                      stroke="#fff"
                      strokeWidth="2"
                      strokeLinecap="round"
                      fill="none"
                    />
                  </svg>
                )}
              </div>

              <div className="cg-bubble">
                {msg.restored && (
                  <div className="cg-restored-badge">restored from history</div>
                )}
                <div className="cg-text">{msg.text}</div>
                <div className="cg-time">{msg.timestamp}</div>
              </div>
            </div>
          ))}

          {isTyping && (
            <div className="cg-row assistant">
              <div className="cg-avatar assistant">
                <svg viewBox="0 0 24 24" width="16" height="16" fill="none">
                  <path
                    d="M12 2l1.9 4.7L19 8l-4.1 1.3L13 14l-1.4-4.5L7 8l4.6-1.3L12 2z"
                    fill="#fff"
                  />
                </svg>
              </div>
              <div className="cg-bubble cg-typing">
                <span className="cg-typing-dot" />
                <span className="cg-typing-dot" />
                <span className="cg-typing-dot" />
              </div>
            </div>
          )}

          <div ref={endRef} />
        </div>

        {/* ---------- Composer ---------- */}
        <form className="cg-composer" onSubmit={handleSend}>
          <div className="cg-inputwrap">
            <textarea
              ref={textareaRef}
              rows={1}
              value={inputValue}
              onChange={handleInput}
              onKeyDown={handleKeyDown}
              placeholder="Message Borealis…"
              className="cg-input"
            />

            <button
              type="submit"
              className="cg-send"
              disabled={!inputValue.trim()}
              aria-label="Send message"
            >
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none">
                <path
                  d="M12 19V5M12 5l-6 6M12 5l6 6"
                  stroke="currentColor"
                  strokeWidth="2.2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </button>
          </div>

          <p className="cg-footnote">
            Borealis can make mistakes. Press <kbd>Enter</kbd> to send ·{' '}
            <kbd>Shift</kbd>+<kbd>Enter</kbd> for a new line.
          </p>
        </form>
      </div>
    </div>
  );
}
