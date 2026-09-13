# CYBER 210 FINAL PROJECT Decision Log

> **Format (team convention):** every protocol decision gets a short entry —
> **Chose / Rejected / Why** — so the final paper can reconstruct *why* the channel
> looks the way it does. Keep each entry tight. Add a one-line meta header per entry.
>
> Project: *Protecting LLM Prompt Traffic Beyond TLS* (CYBER 210, Summer 2026).
> Channel: **BIP-39 identity → HPKE seal (RFC 9180) → echo server, inside TLS 1.3.**
> Legend: ✅ decided · 🔁 revisit later · 🧪 stretch/optional.

## Core Project Design 

### D001 - HPKE vs hand-rolled crypto (ECDH→HKDF→GCM) ✅
- **Chose:** HPKE (RFC 9180)
- **Rejected:** ECDH→HKDF→GCM
- **Why:** ECDH→HKDF→GCM is essentially HPKE base mode composed by hand. Hand-rolling crypto is dangerous and not industry-tested, which can lead to implementation errors. The library owns the dangerous details — nonce management, suite binding, and the key schedule — so there are fewer subtle ways to be quietly wrong. Since this is a network security project rather than a cryptography implementation project, using a standard HPKE library is the safer and more defensible choice.

### D002 - BIP-39-derived browser identity vs per-session ephemeral browser key ✅
- **Chose:** BIP-39-derived browser identity/key material for the demo.
- **Rejected:** Pure per-session ephemeral browser identity.
- **Why:** BIP-39 gives the browser a repeatable identity source across demo sessions without needing a full login, database, or external identity provider. A purely ephemeral per-session key is simpler, but it makes identity continuity, key pinning, and repeatable testing harder. Ephemeral per-message HPKE keys can still be used for sealing messages.

### D003 - AES-256-GCM vs ChaCha20-Poly1305 (forward-ratchet mechanisms; practical implementation safety) ✅
- **Chose:** ChaCha20-Poly1305
- **Rejected:** AES-256-GCM (slower without hardware acceleration)
- **Why:** ChaCha20-Poly1305 is a strong AEAD choice with good software performance and broad support in modern protocols/libraries. It avoids relying on AES hardware acceleration, which makes it a practical choice across different test environments. HPKE/library support also helps keep nonce and key-schedule handling out of our custom code. We should still treat nonce reuse as dangerous and rely on the HPKE library to manage this correctly.

### D004 - Handshake authentication: implemented vs hand-waved ✅ *(updated)*
- **Chose:** Authenticated handshake with signed key material / transcript verification.
- **Rejected:** Unauthenticated public-key exchange.
- **Why:** Without handshake authentication, a TLS-terminating proxy could try a key-substitution attack by replacing Bob’s public key with its own. Authentication gives the browser a way to verify that it is sealing the prompt to the intended server key. (Note: this authenticates the *server to the browser* via the pinned Ed25519 key; the browser's own `hello` signature is trust-on-first-use — see protocol.md §4.1 note.)

### D005 — Threat model & trust boundary ✅
- **Chose:** HPKE-protected application payloads inside TLS 1.3. The browser seals the prompt before it enters the socket, and the intended echo server opens it.
- **Rejected:** TLS-only protection as the final security model. Also rejected hiding plaintext from the intended server itself, which would require TEEs/confidential computing and is out of scope.
- **Why:** TLS already protects against a passive network sniffer, but it does not protect plaintext after TLS terminates at a trusted inspection proxy such as mitmproxy. HPKE changes what that TLS-terminating middlebox can see: with E2E on, it sees sealed payload fields instead of prompt plaintext. The intended server remains trusted and still sees plaintext after decryption. Known gaps include served-JS/code delivery, server-side logging after decryption, and traffic analysis such as timing and size.

### D006 — Threat-model audit vs current protocol ✅
- **Chose:** Update `threat-model.md` to match the current protocol and diagrams.
- **Rejected:** Leaving the threat model with outdated AES-GCM references and missing active attacker cases.
- **Why:** The protocol now uses ChaCha20-Poly1305 through HPKE, and the diagrams include an authenticated handshake, key pinning, sealed payloads, replay/order checks, and mitmproxy as an active TLS-terminating intermediary. The threat model should include key substitution, tampering, replay/reorder, reflection, traffic analysis, served-JS/code delivery, and server-side plaintext logging as either threats or limitations.

### D007 — Wire envelope format ✅  *(updated)*
- **Chose:** A structured JSON message envelope with a `type` discriminator and per-message-type fields, frozen in `protocol.md` §5. The steady-state message frame is `{ "type": "msg", "seq", "ct" }` (E2E mode); handshake frames (`hello`, `server_hello`, `GET /pubkey` response) carry key material (`enc`, public keys) and a `sig` only. In plaintext (E2E-OFF) mode the payload may instead be a `text` field.
- **Rejected:** An unstructured raw text message and a single global sequence counter. Also **dropped** the earlier `sender` and `timestamp` envelope fields — `protocol.md` §5.4 (the single source of truth per D013) does not carry them; direction is known per link and freshness is handled via `seq` + session binding, not a wire timestamp.
- **Why:** A stable envelope makes the demo easier to extend. The same message structure can support plaintext mode, E2E mode, replay detection, and ordering checks. Separate client-to-server and server-to-client sequence tracking is clearer than one global counter. HPKE owns nonce handling, so the envelope should not add a custom IV field. **This entry is descriptive; if it ever conflicts with `protocol.md` §5, `protocol.md` wins (D013).**

### D008 — Served-JS / code-delivery integrity ✅ (limitation) · 🧪 (demo aid)
- **Chose:** Document browser code-delivery integrity as an explicit, unsolved limitation of
  this project. Optionally add a demo-only integrity aid — a shown bundle hash or a locally
  packaged client — as stretch work, not a core requirement.
- **Rejected:** Treating delivered browser JavaScript as automatically trustworthy.
- **Why:** Browser-side encryption only protects the prompt if the code performing it is itself
  trustworthy. If the same server or delivery path can modify the JavaScript, malicious code
  could exfiltrate plaintext before HPKE seal or alter key-pinning/verification behavior. We
  scope this out as residual risk, we do not solve it. Note: a hash-on-slide proves nothing if
  the same origin serves both the bundle and the hash — only an out-of-band-verified hash or a
  locally packaged/pinned client (SRI, packaged app, extension) actually removes the server
  from the code-integrity trust path.


### D009 — Identity = BIP-39 24-word mnemonic, deterministic keys via HKDF tree ✅ *(updated; tradeoff superseded by D026)*
- **Chose:** Derive a static identity from a 24-word BIP-39 mnemonic via the standard BIP-39
  seed process and an HKDF-SHA256 key tree, yielding an X25519 HPKE-recipient key and an
  Ed25519 signing key.
- **Rejected:** Random per-session identity keys, raw localStorage key blobs, or any scheme
  that cannot be recovered from the mnemonic.
- **Why:** The mnemonic gives a recoverable, escrow-free, human-transferable demo identity with
  no server-side private-key storage. 
- **Tradeoff (corrected Step-1 F1):** a static identity key is weaker than a fresh per-session
  key. EchoVault uses HPKE **base mode**, which seals every message to a **static** recipient
  key in **both** directions (server X25519 for c2s, browser X25519 for s2c). Base mode is
  therefore **not** forward-secret against recipient long-term-key compromise in **either**
  direction: a stolen server key exposes all captured prompts (harvest-now-decrypt-later). This
  is consistent with `threat-model.md`, which already scopes "stolen server private key" out.
  Real forward secrecy would require per-epoch **ephemeral recipient** keys (not merely rotating
  the static identity) — future work / stretch goal. Private keys never go on the wire and are
  imported non-extractable where the platform allows. **→ Done in D026:** both channel
  directions now seal to per-connection ephemeral recipient keys; the static X25519 key is the
  storage identity only (§9.2). The derivation in this entry is unchanged.


### D010 — Seed derivation = standard BIP-39 mnemonicToSeed parameters ✅
- **Chose:** Standard BIP-39 mnemonic-to-seed derivation: PBKDF2-HMAC-SHA512, 2048 iterations,
  salt = "mnemonic" + passphrase, empty passphrase for the demo.
- **Rejected:** Custom salts, custom iteration counts, custom hash functions, or requiring a
  passphrase in the demo flow.
- **Why:** The goal is deterministic, cross-implementation recovery. The *reason* to use the
  standard process is that BIP-39 already defines exactly how a mnemonic becomes a seed, so the
  same 24 words reproduce deterministic cross-implementation interoperable with any implemenation
  (python, node.js etc). The low 2048-iteration   count is acceptable only because the security 
  lives in the ~256-bit mnemonic entropy, not in a low-entropy password. The empty passphrase 
  drops BIP-39's optional 25th-word second factor — fine for demo simplicity, but documented 
  as a demo limitation, not a production recommendation.

### D011 — Key tree = HKDF-SHA256 with domain-separated outputs ✅
- **Chose:** Derive separate encryption and signing key material from the 64-byte BIP-39 seed
  with HKDF-SHA256, using a frozen salt and distinct `info` strings per key purpose (e.g.
  `echovault-x25519-encryption`, `echovault-ed25519-signing`), 32 bytes each.
- **Rejected:** Splitting the seed by hand, reusing one derived key for multiple purposes, or a
  wallet-style hierarchical scheme (BIP-32 / SLIP-0010).
- **Why:** This is fundamentally a key-purpose separation decision: never use one key for two
  jobs. Two flat keys (one HPKE encryption identity, one signing) with per-purpose `info` domain
  separation is the RFC 5869 idiom — simple, curve-agnostic, easy to reproduce across JS/Python.
  The salt and `info` strings are frozen: changing either silently changes the derived identity.

### D012 — Keypair derivation = deterministic X25519 (HPKE recipient) + Ed25519 (signing) ✅
- **Chose:** Derive deterministic keypairs from the mnemonic-backed key tree — X25519 for HPKE
  recipient encryption, Ed25519 for signing — stating each key's role and the requirement to
  verify them byte-for-byte across both implementations.
- **Rejected:** Randomly generated identity keypairs, persisting private keys as raw blobs, or
  trusting cross-library key handling that has not been interop-tested.
- **Why:** The identity must be reproducible from the mnemonic and byte-identical between the
  browser (hpke-js) and Python/server (pyhpke) sides. The decision log states the roles and the
  interop obligation; it need not reproduce the scalar math. The specific footgun is deterministic 
  X25519 derivation from HKDF bytes, where raw-scalar vs. clamped handling can diverge between 
  libraries and produce mismatched public keys or shared secrets. Move the exact byte-level 
  contract (scalar clamping, encoding) into PROTOCOL.md **Also add `SESSION_ID` (protocol §3.0)
  to the interop test — both sides must compute `SHA-256(T_hello ‖ T_server_hello)[:16]`
  byte-identically.**

### D013 — Freeze the full wire contract in PROTOCOL.md before live handshake ✅
- **Chose:** Freeze the HPKE suite, key-derivation values (salt/info/iterations), public-key
  formats, AAD encoding, transcript byte-layout, frame shapes, and base64 conventions in
  PROTOCOL.md, with Cam's sign-off, before either side implements the live handshake.
- **Rejected:** Writing the handshake first and reconciling encoding/framing differences later
  during interop.
- **Why:** The client and server are built in different languages by different people working
  remotely. Even with correct crypto choices, mismatched encodings or frame formats silently
  break interop. Catching those in document review is far cheaper than debugging them live.

### D014 — Let HPKE ctx.seal / ctx.open own the nonce and message counter ✅
- **Chose:** Let the HPKE context manage nonce derivation and the internal message counter
  through `seal` / `open`.
- **Rejected:** Manually generating, transmitting, or tracking nonces outside the HPKE context.
- **Why:**  Manual nonce handling risks nonce reuse, a catastrophic AEAD failure: under 
ChaCha20-Poly1305 (and GCM) a repeated nonce leaks the XOR of plaintexts and, for GCM, enables 
forgery. RFC 9180's `seal`/`open` derive a unique, monotonic per-message nonce inside the context 
and put nothing secret or redundant on the wire; the API is identical across hpke-js, pyhpke, 
Go, and Rust. 
- **Tradeoff:** Each HPKE context requires strict in-order delivery per direction, offers no
  random-access/stateless decryption, and has a per-context message ceiling. A long-lived link
  must rotate to a fresh context (`enc` + hello/server_hello) before that ceiling — the same
  rotation named in D009. **Note (Step-1 F1):** this rotation bounds nonce exhaustion and mints a
  fresh `SESSION_ID`, but on its own it does **not** add forward secrecy while the recipient key
  is a static BIP-39 identity; forward secrecy needs per-epoch ephemeral recipient keys 
  (delivered per connection by D026). 

### D015 — Mandatory `server_hello` acceptance gate  ✅
- **Chose:** Require the browser to **cross-check the contents** of `T_server_hello`, not
  just verify its signature, **before** opening the HPKE context or sealing any prompt.
  The browser MUST (protocol.md §4.3.1): (1) `Ed25519_Verify` with the **pinned**
  `server_ed25519`; (2) assert the transcript's `server_x25519`/`server_ed25519` equal
  the pin; (3) assert the transcript's `browser_x25519`/`browser_ed25519` byte-equal the
  values the browser itself put in `hello`; (4) abort hard on any mismatch. The server
  performs the analogous check on `hello` (client sealed to *this* server's keys).
- **Rejected:** Signature-only acceptance of `server_hello` (verify `sig`, then proceed).
- **Why:** The c2s (prompt) direction uses the browser's *ephemeral* `enc`, so it never
  depends on `browser_x25519`. The s2c (echo-reply) direction — a **declared protected
  asset**, since the echo carries the prompt back — seals to `browser_x25519`, and the
  server holds **no pin for the browser**. An active proxy can rewrite `hello` (keep the
  real `enc`, swap in its own `browser_x25519`, re-sign with its own Ed25519); the real
  pinned server then validly signs a `server_hello` containing the proxy's key, so a
  signature-only check passes and the server seals the reply **to the proxy**, which
  decrypts the prompt. The content cross-check is the only thing that detects this. The
  `hello → server_hello → msg` ordering means the gate aborts **before** any prompt is
  sealed, so the fix costs nothing but a comparison. **Tradeoff:** a proxy can still force
  an abort (denial of service) — explicitly out of scope (availability).

### D016 — `/pubkey` is confirmed against the pin, never trusted from the wire ✅ *(demo default relaxed by D032)*
- **Chose:** Treat `server_ed25519` from `/pubkey` as **untrusted input**. The browser
  MUST compare it to a pre-provisioned out-of-band pin **first**, verify the signature
  against the pin, and adopt `server_x25519` only via that pin-anchored signature
  (protocol.md §4.1.1). If no pin is provisioned, refuse to run the E2E handshake (fail
  closed).
- **Rejected:** Trust-on-first-use / pin-on-first-use — learning and caching the server
  identity from the first `/pubkey` response.
- **Why:** The entire key-substitution defense (D004, D015) rests on the server Ed25519
  identity being a genuine out-of-band pin. If the identity is learned from the wire, an
  active proxy present at first contact substitutes **both** the key and the identity, and
  every downstream check — including D015 — then validates against the attacker's key,
  silently voiding the whole guarantee. This keeps the mitigation inside the documented
  "pin is a demo trust assumption" boundary (threat-model.md) and makes that assumption
  *enforceable* rather than implicit. It does **not** claim production key management
  (provisioning/rotation/revocation remain out of scope).

### D017 — Fresh server ephemeral `enc` per connection is security-critical ✅
- **Chose:** Mandate a fresh `SetupBaseS` (new ephemeral `enc`) on the server for **every**
  connection (protocol.md §7.1), so each handshake yields a distinct `SESSION_ID` (§3.0).
- **Rejected:** Reusing an HPKE context / `enc` across connections as an optimization.
- **Why:** The whole-session-replay defense works **only** because a replayed `hello`
  forces the server to emit a fresh `enc`, changing `SESSION_ID` and causing the replayed
  `msg` frames to fail `open()`. That is currently an emergent property of per-connection
  ephemerals, not a stated guarantee — an `enc`-reuse optimization would silently reopen
  session replay, and the server has no independent anti-replay. Documenting it as a MUST
  converts an accident into a guarantee. **Defense-in-depth (🔁 optional):** mix a
  server-chosen random nonce into `T_pubkey`/`server_hello`, or reject a `hello` whose
  `enc` was seen recently.

### D018 — Uniform fail-closed decrypt/handshake error handling  ✅
- **Chose:** On any `open()` failure, malformed frame, bad encoding/length, out-of-order
  `seq`, or failed acceptance gate, return a **single uniform error**, emit no plaintext,
  reveal no distinguishing detail on the wire (no bad-tag vs bad-seq vs unknown-key
  oracle), log without prompt content, and never fall back to a plaintext path
  (protocol.md §7.4).
- **Rejected:** Distinct, descriptive error messages per failure cause; any
  plaintext/partial-plaintext on failure.
- **Why:** Satisfies the threat-model integrity requirement ("reject without leaking
  plaintext or sensitive errors") explicitly, avoids padding/oracle-style side channels,
  and gives the Step-3 tamper/malformed tests (T9/T10) a well-defined expected result.

### D019 — Enforce replay/reorder with teardown-and-rehandshake ✅
- **Chose:** Make receiver-side per-link `seq` tracking **mandatory**, with a single
  fail-closed policy — **teardown-and-rehandshake** (protocol.md §7.3). Keep
  `expected_next_seq` per direction; check it *before* `open()`. Any duplicate / rollback
  / gap in `seq`, **or** any `seq`-correct frame that fails `open()` (tamper / AAD
  mismatch), aborts the link and forces a fresh handshake (new `enc` + hello/
  server_hello, new `SESSION_ID`). The receiver never skips a `seq`, never resyncs, never
  continues on a suspect context.
- **Rejected:** (a) Leaving replay protection "partial"/optional. (b) **Drop-and-continue**
  — dropping the offending frame and keeping the link alive.
- **Why:** With a single strictly-in-order HPKE context per direction there is no safe way
  to "drop one frame and keep going": the app-level `seq` and HPKE's internal counter can
  silently diverge, and a receiver that guesses wrong ends up on a desynchronized context
  that still *looks* live. Failing the whole link closed is the honest, auditable
  behavior and makes the replay/reorder integrity claim **unconditional** (was "partial",
  D-note under §3.2/§7.3). **Tradeoff (accepted):** an active proxy can force a reconnect
  by injecting one bad/duplicate frame — a denial-of-service lever, which notifys the user 
  that there is something amiss. We prefer a clean teardown over a silently desynchronized
  stream. Step-3's pen test will exercise both the replay-reject and the tamper-teardown
  paths (T9-style).

### D020 — Bind message `TYPE` into the AAD + strict receiver state machine ✅
- **Chose:** Add a fixed **1-byte `TYPE` code** to the AAD (`msg = 0x01`; `0x02`/`0x03`
  reserved for hello/server_hello, which are signed not sealed), making the AAD
  `STATE ‖ SESSION_ID ‖ DIRECTION ‖ TYPE ‖ SEQ8` = **37 bytes** (was 36). Also enforce a
  **strict receiver state machine** (protocol.md §5.6) that accepts only the frame
  type(s) valid in the current handshake phase. The wire `type` string is untrusted
  routing metadata; `TYPE` is its authenticated form (§3.0.1).
- **Rejected:** (a) Leaving `type` unauthenticated. (b) State-machine-only (Branch B) with
  no AAD change — chose the full cryptographic binding (Branch A) instead.
- **Why:** `type` currently sits in the JSON frame, outside both the ciphertext and the
  AAD, so an active proxy can flip `"msg"→"hello"` to push a payload into the handshake
  code path (parser/state-machine confusion, cheap DoS). Binding `TYPE` into the AAD means
  a sealed frame can only `open()` under the type the sender intended, and the state
  machine refuses cross-type routing before dispatch — belt and suspenders. Branch A also
  future-proofs: if a later version seals a new frame class, the reserved codes stop it
  from being confused with `msg`.
- **Cost / ripple (paid deliberately):** this changes the **frozen AAD contract** (D013).
  The 36→37-byte layout, §3.1 table/diagram/example, and §7.2 pseudocode all move, and
  **both implementations must compute the new AAD byte-identically or every `open()`
  fails** — so the D012 interop test MUST be re-run for the `TYPE` byte alongside
  `SESSION_ID`. Batched here with S4 so the contract re-freeze happens once.
---

> **Course boundary.** D001–D020 are the **CYBER210** baseline, frozen at tag `EchoSrv`
> and preserved under `docs/cyber210/`. Everything from D021 on is **CYBER212** work on
> `main`; the plan for the cloud is in `docs/cyber212/README.md`.

## Persistent History (ADR 212)

### D021 — History ownership: the mnemonic owns the history; server and database hold opaque blobs ✅
- **Chose:** Persist chat history, but seal every stored record **in the browser** to key
  material that only the holder of the BIP-39 mnemonic can unlock. The echo server stores
  and returns blobs it cannot open; the database stores blobs the server handed it. "Come
  back with the same 24 words, get your history back" is the whole acceptance test.
- **Rejected:** (a) A server-held storage key in `.env` — the server operator (or a leaked
  `.env`) reads every conversation of every user forever, which widens exposure well past
  D005's "the server sees the live prompt". (b) Storing the channel `ct` as received — it is
  bound to one session's HPKE context, so reading it back means storing `enc`/`seq`, rebuilding
  the recipient context from the server's static key, and opening in order from `seq 0`: a
  feature built on the very non-forward-secrecy D009 calls a weakness, and useless for the
  echo direction, which is sealed to the browser.
- **Why:** This extends the project thesis one hop: browser-to-server encryption beyond
  TLS becomes browser-to-storage encryption beyond the server. Per-user isolation is free
  (every identity unlocks only its own blobs), there is no master key to rotate or lose, and a
  compromise of the server host, the database host, or a backup yields ciphertext only. The
  server's exposure stays exactly what it is today: the live prompt during a session.

### D022 — Expiry by key erasure: random per-epoch keys, sealed to the identity key, erased after a window ✅
- **Chose:** The browser mints a **random X25519 epoch keypair** every `EPOCH_LENGTH` and
  HPKE-seals each prompt record to the current epoch public key. The epoch **private** key is
  HPKE-sealed to the browser's static X25519 identity key (§2, unchanged key tree) and uploaded
  once. The server **erases** the sealed epoch key once the epoch is older than
  `HISTORY_WINDOW`; every record of that epoch is then unrecoverable wherever a copy lives.
  All storage crypto is HPKE single-shot seal/open with distinct `info` strings, so D014
  still holds: no hand-managed nonces or raw AEAD keys in the page.
- **Rejected:** (a) Epoch keys **derived** from the mnemonic (HKDF + epoch index) — anything
  derivable from the 24 words is re-derivable forever, so it can never expire. (b) A
  hash-chain "forward ratchet" over epoch keys — a leaked head exposes every later epoch and
  buys nothing that independent random keys don't. (c) Row deletion alone — deletes only the
  copies you know about; backups and replicas keep the data. (d) A third HKDF branch feeding a
  raw ChaCha20-Poly1305 key with random nonces — reintroduces manual nonce handling (D014).
- **Why:** "Impossible to recover after T" always means *someone erased a secret at T*. A
  ratchet does not make data expire; erasure does. What the epoch key buys is leverage:
  erasing one 32-byte sealed blob kills every record of that epoch in every location,
  including the remote database and any backup of it (crypto-shredding). Signal's disappearing
  messages are a deletion timer, not a ratchet property; this design is the same honest
  mechanism with a smaller thing to erase. A record is guaranteed gone by
  `created + HISTORY_WINDOW` and alive for at least `HISTORY_WINDOW − EPOCH_LENGTH`.
- **Tradeoff (accepted, documented in `threat-model.md`):** expiry rests on the **server
  erasing on schedule** — the browser cannot verify deletion. Within the window a stolen
  mnemonic reads everything (the identity key is static by D009). An epoch private key sits in
  browser memory for the length of a session. A wire recording of the channel was
  recoverable via the server's static key until D026 closed that half; the two are
  complementary halves of one claim.

### D023 — Wire contract: record rides inside the sealed `msg`; new `epoch_key` (c2s) and `history` (s2c) frames ✅
- **Chose:** The **c2s `msg` plaintext becomes structured JSON** — `{ text, rec }` — where
  `rec` is the prompt already sealed to the epoch key. One seal, one frame: the server opens
  the `msg` as today, echoes `text`, and stores `rec` under the owner (the `browser_ed25519`
  proven by the `hello` signature). Two new **sealed** frame types: `epoch_key` (c2s,
  `TYPE = 0x04`, any time in ESTABLISHED) carries a newly minted, identity-sealed epoch
  private key; `history` (s2c, `TYPE = 0x05`) is pushed **once, immediately after
  `server_hello`, at s2c `seq 0`**, carrying the retention policy, the live sealed epoch
  keys, and the records. The browser MUST receive `history` (even empty) before it is
  ESTABLISHED. Both new frames share the per-direction `seq` counters, because each HPKE
  context is a single strictly-in-order stream (D014/D019).
- **Rejected:** (a) A separate per-record upload frame — the prompt would cross the wire
  twice. (b) An authenticated REST endpoint for history — a second auth path beside the
  handshake, and history would leave the HPKE channel. (c) Browser-requested history
  (`history_req`) — one more frame type for no gain; the server always knows to push.
- **Why:** The `msg` frame is already the authenticated, sealed, in-order carrier for the
  prompt; adding the record to its plaintext costs bytes, not trust. Pushing history right
  after `server_hello` means the browser has its epoch keys before it can seal its first
  prompt, so "reuse the live epoch or mint a new one" is decided with full information.
- **Cost / ripple (paid deliberately):** this amends the **frozen contract** (D013): §0 gains
  storage constants, §3.0.1 gains two TYPE codes, §5 gains two frame shapes, §5.6 gains
  `AWAIT_HISTORY`, and §7 gains the structured c2s plaintext. Both implementations must build
  the new AADs byte-identically or every `open()` fails.

### D024 — Split stores: sealed epoch keys on the server host, records in a remote Postgres over TLS ✅
- **Chose:** Two stores behind one small interface. **Sealed epoch keys** live on the server
  host in a SQLite file on a volume (stdlib, no dependency); **records** live in a
  **Postgres container that may run anywhere**, reached with `sslmode=verify-full` against a
  self-signed CA generated the same way as the existing demo certs. The expiry sweeper runs
  on the server, on every connection and on a timer.
- **Rejected:** (a) Keys and records in the same Postgres — a backup of that database carries
  both halves, so "erase the key" no longer beats "delete the rows". (b) Plain TCP to Postgres,
  relying on the blobs being opaque — owner keys, epoch ids and timestamps would cross the link
  in the clear. (c) SQLite behind a bespoke HTTP service — more code for less capability.
- **Why:** The remote location, and every backup of it, holds ciphertext that nothing *in that
  location* can decrypt. The erasure authority sits on the box the operator controls. The
  interface boundary is what makes the database swappable without touching the protocol.
- **Update (ADR 5):** erasure means the bytes, not the row. The SQLite store runs with
  `secure_delete=ON` and truncates its WAL after each erase, so a copy of the file taken
  afterwards holds no expired key. Volume snapshots of the host are the same problem as
  database backups and are settled by placement (ADR 4).

### D025 — Echoes are not stored; the browser reconstructs them on replay ✅
- **Chose:** Persist prompts only. On replay the browser renders `ECHO: <text>` for each
  restored prompt, labelled as restored.
- **Rejected:** (a) The browser sealing the echo after receipt and uploading it — a second
  upload per message, the exact cost D023 avoids. (b) The server storing echoes under a key of
  its own — reintroduces the server-held key D021 rejects, for one direction only.
- **Why:** The echo server is deterministic, so the stored prompt *is* the echo. When a real
  reply-producing backend replaces the echo, this entry is the one to revisit.

## Channel Forward Secrecy (ADR 2)

### D026 — Per-connection ephemeral recipient keys in both directions ✅
- **Chose:** Each side mints a **fresh X25519 keypair for every connection**, signs its
  public half with its Ed25519 identity, uses it as the HPKE recipient key for the incoming
  direction, and **wipes the private half at teardown**. The browser→server context seals to
  the server ephemeral (`server_key`, §4.0); the server→browser context seals to the browser
  ephemeral (`hello`, §4.2). The static X25519 identity key leaves the channel entirely and
  keeps one job: sealing epoch keys for stored history (§9.2).
- **Rejected:** (a) Keeping static recipient keys (the D009 posture) — a recording of the wire
  plus a later theft of the server's static key decrypts every prompt ever sent
  (harvest-now-decrypt-later), and ADR 212's key erasure would leave that copy untouched.
  (b) Rotating the *static* identity on a schedule — the D014 note already says this adds no
  forward secrecy. (c) Mid-session rekeying only — more machinery (rekey frames, counter
  resets on a live socket) for a weaker guarantee than "nothing survives the connection";
  it remains available as a later refinement on top of this.
- **Why:** Forward secrecy is the erase-a-key mechanism applied to the channel: once the
  recipient private keys are gone, no key that survives the session can open its ciphertext.
  It is the second half of the ADR 212 claim — after the history window, neither the stored
  copy nor a captured copy of a prompt is recoverable. The cost is one extra handshake frame
  and one keypair generation per side per connection.
- **Tradeoff (accepted):** identity theft still allows **impersonation going forward** (any
  signature-based identity has this limit); compromise of an ephemeral *during* a live
  session exposes that session; a long-lived connection shares one pair of contexts.

### D027 — Server-first `server_key` frame, `v2` transcript labels, `SESSION_ID` over three transcripts ✅
- **Chose:** On WebSocket accept the server sends `server_key` = `{server_x25519 (ephemeral),
  sig over T_server_key}` **before** the browser speaks; the browser gates it against the pin
  (§4.0.1), mints its own ephemeral, then sends `hello`. `hello` and `server_hello` keep their
  byte layouts but carry ephemerals, so their labels bump to **`v2`** and `pubkey`'s to `v2`
  (its layout shrank). `SESSION_ID = SHA-256(T_server_key ‖ T_hello ‖ T_server_hello)[:16]`.
- **Rejected:** (a) Minting the ephemeral in `/pubkey` per request — binds HTTP state to a
  later WebSocket (a nonce, a TTL, a cache of unspent ephemerals), and a proxy can request
  them freely. (b) A browser-first three-frame flow (`hello` → `server_hello` →
  `client_finish`) — one more round trip for the same result. (c) Keeping the `v1` labels —
  a signature over a v1 transcript would verify inside a v2 handshake with the same bytes.
- **Why:** The browser cannot seal to a key it has not seen, so *someone* must send a second
  time; letting the server speak first costs no extra round trip because the browser was
  waiting on the socket anyway. Fresh labels are the D013 discipline: change the meaning,
  change the domain separator. **Cost / ripple:** the frozen contract moves again (§0, §3.0,
  §4, §5, §5.6, §7.1) — both implementations must build the three transcripts and the
  `SESSION_ID` byte-identically or every `open()` fails.

### D028 — `/pubkey` carries only the Ed25519 pin confirmation; no backward compatibility ✅
- **Chose:** `/pubkey` = `{server_ed25519, sig over T_pubkey = label ‖ server_ed25519}`. The
  X25519 field is removed. The pin gate (§4.1.1) is unchanged in spirit: compare to the pin
  first, verify, then open the socket.
- **Rejected:** Keeping `server_x25519` in `/pubkey` "for compatibility" — it would be a
  key that must never be sealed to, sitting on the wire as an invitation to do exactly that.
- **Why:** One root of trust (the pinned Ed25519 identity), one place where a recipient key
  arrives (`server_key`), and the static X25519 key is once again a single-purpose key
  (D011): storage identity for the browser, nothing at all for the server. The old deployed
  demo is not a compatibility target (the proxy stack is retired in ADR 3).

## CYBER212 Cleanup (ADR 3)

### D029 — Plaintext mode removed entirely ✅
- **Chose:** Delete `/ws/plain`, the Encrypt toggle, the plaintext wire mode and its
  red-rendering path, and every E2E-OFF column in the docs. The secure link is the only
  link.
- **Rejected:** Keeping plaintext mode "for comparison". Its only purpose was the mitmproxy
  exhibit (D005), and the proxy stack is gone (this ADR). A downgrade path with no exhibit
  behind it is just a downgrade path.
- **Why:** Less code in the receiver state machine, no `text`-vs-`ct` discriminator to get
  wrong, and the threat model no longer has to describe a mode the system does not have.
  The CYBER210 comparison survives at tag `EchoSrv`.

### D030 — Every echo server terminates its own TLS ✅
- **Chose:** uvicorn serves HTTPS/WSS on 8443 with a per-server certificate issued by a
  project CA (`server/certs/gen-server-certs.sh`, SAN from `SERVER_NAME`). Plain HTTP is
  removed, not made optional. In the cloud, the reverse proxy + WAF terminate public TLS and
  **re-encrypt** to each echo server, verifying against this CA; locally the browser trusts
  the CA directly.
- **Rejected:** (a) Plain HTTP behind the proxy — the proxy-to-server hop would carry the
  handshake and sealed frames in the clear inside the VPC, and the HPKE layer would be the
  only thing between an internal observer and the metadata. (b) A sidecar TLS terminator per
  server — one more container per server for something uvicorn already does.
- **Why:** HPKE protects prompt content; TLS on every hop protects everything else (frame
  metadata, pins on the wire, `/pubkey`) and is what a WAF needs to trust the upstream. A
  cert per server also gives each echo server a second, transport-level identity that the
  proxy can route on.

### D031 — History is per echo server ✅
- **Chose:** A browser that chatted with server A gets nothing back from server B. Sealed
  epoch keys stay on each server's own host (D024, unchanged); records in the shared
  database carry `server_name` and are filtered by it on read. Later (cloud ADR): bind the
  server's Ed25519 identity into the storage AAD so a record from A cannot be opened in a
  session with B even by a browser holding both keys.
- **Rejected:** Shared history across servers — it would force the sealed epoch keys into a
  shared store, which either loses the "the database cannot decrypt itself, backups
  included" property of D024 or needs a second store with its own backup policy.
- **Why:** The threat model wants each echo server to be a separate trust domain. Per-server
  history falls out of the existing key placement for free: B never holds A's epoch keys, so
  B cannot decrypt A's records even if it could read them. The `server_name` column exists
  so B does not *serve* A's blobs either (counts and sizes are metadata). With one server it
  is inert.

## CYBER212 Client fixes (ADR 5)

### D032 — The page pre-fills the pin from `/pubkey` (trust on first use, labelled) ✅
- **Chose:** On load the browser fetches `/pubkey` and fills the *Server key* box with the
  served `server_ed25519`, unless the user has already typed there. The §4.1.1 gate, the
  `server_key` check and §4.3.1 run unchanged against whatever is in the box. The page tracks
  where the pin came from and labels a server-supplied one *TOFU*; pasting the console pin
  switches back to the out-of-band path. The hardcoded default pin is removed.
- **Rejected:** (a) Keeping the paste-only flow — every rebuild with a new identity broke the
  demo until someone copied a key by hand, and a stale hardcoded pin failed red for no
  reason worth demonstrating. (b) Baking the pin into the client bundle at build time — it
  couples the client image to one server identity, and the bundle comes from a server too
  (D008), so it moves the trust question without answering it. (c) Silently caching the
  first key in `localStorage` — pin-on-first-use that hides itself is the case D016 was
  written against.
- **Why:** This is a deliberate, visible exception to D016 for the demo. It makes the
  boundary a talking point instead of a hidden assumption: with a pre-filled pin the
  handshake proves only that the server agrees with itself, so the key's authenticity
  collapses to the TLS hop that delivered `/pubkey`. Locally that hop ends at the server;
  behind the cloud proxy + WAF it ends at the intermediary D005 is about, which could
  substitute key and signature together. The conformant path (a pasted out-of-band pin) is
  one paste away and is what the red-team claims in `threat-model.md` still rest on.
