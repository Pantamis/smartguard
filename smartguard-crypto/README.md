# smartguard-crypto

Smartcard-backed `DhOracle` for rustyguard. `CardHandle` implements `DhOracle`
directly — no wrapper type, no sentinel keys, no thread-locals.

`CardHandle` holds a persistent `Card<Open>` (PC/SC `SCARD_SHARE_SHARED`
connection) for the lifetime of the tunnel, and runs one short transaction
per handshake (`SCardBeginTransaction` → VERIFY+DECIPHER →
`SCardEndTransaction(LeaveCard)`). Transactions release with `LeaveCard`, not
`ResetCard`, so the card session stays intact for other consumers between
our operations.

## Coexisting with other smartcard consumers

A few one-time host-side config tweaks make this work cleanly with GPG and
SSH (i.e. with `gpg-agent` / `scdaemon`). None of them are smartguard-
specific — they're best-practice for any setup where multiple processes
share a smartcard via PC/SC.

### 1. Route scdaemon through pcscd and tell it to share (required for GPG + smartguard)

Two scdaemon options are needed, **in this order**:

```sh
cat >> ~/.gnupg/scdaemon.conf <<EOF
disable-ccid
pcsc-shared
EOF
gpgconf --kill scdaemon   # so the next gpg call picks up the flags
```

What each one does, and why the order matters:

- **`disable-ccid`** turns off scdaemon's built-in CCID driver. Without
  this, scdaemon talks to the USB reader *directly* (bypassing pcscd
  entirely), which means it doesn't see smartguard at all — and we don't
  see it. Two consumers, each thinking they own the reader, races at the
  USB layer. `disable-ccid` forces scdaemon to route through pcscd so
  PC/SC's transaction layer can serialize access between us.
- **`pcsc-shared`** then makes scdaemon's pcscd connection use
  `SCARD_SHARE_SHARED` instead of the default `SCARD_SHARE_EXCLUSIVE`.
  Without it, the very first `gpg` call after starting gpg-agent grabs
  the card exclusively for the whole session — *any* smartguard rekey
  while gpg-agent is alive then fails with `SCARD_E_SHARING_VIOLATION`,
  eventually breaking the tunnel.

The order matters in practice: with `disable-ccid` listed before
`pcsc-shared`, scdaemon already knows to use pcscd at the moment it
parses `pcsc-shared`, so the share-mode flag applies to the right code
path from the very first invocation. Reversing the order means scdaemon
may attempt one CCID-direct probe before falling back to pcscd, which
shows up as a transient first-call failure even though the configured
end state is the same.

End result: PC/SC multiplexes transactions between scdaemon and
smartguard — each holds the card only while doing actual work, and the
other waits its turn.

### 2. "First operation after starting the VPN fails" — known one-time hiccup

After starting smartguard, the **first** `ssh` connection or `gpg` operation
that hits the smartcard typically fails:

```
# SSH symptom
sign_and_send_pubkey: signing failed for ED25519 "cardno:..." from agent: agent refused operation
host: Permission denied (publickey).
```

```
# GPG symptom (in scdaemon's log)
pcsc_transmit failed: reset card (0x80100068)
operation decipher result: General error
```

What's happening: scdaemon caches a snapshot of card state and assumes it's
the only consumer. The first time it tries to use the card *after*
smartguard has touched it, pcscd surfaces a `SCARD_W_RESET_CARD` to scdaemon
mid-operation; scdaemon kicks off a full `learn-card` cycle to recover.
While that's in flight, the in-flight gpg/ssh request fails.

**It's one-time, not recurring.** Once scdaemon has noticed there's another
consumer, every subsequent operation runs a quick state-check first and
co-exists fine — including across all the smartguard handshakes that
follow (every ~2 minutes). The "fail then it works" pattern resets each
time you restart the VPN (or restart gpg-agent/scdaemon), not every
handshake.

**If you want the first call to "just work" too:** trigger scdaemon's
adapt-to-other-consumer cycle right after starting the tunnel, before
your first real gpg/ssh need:

```sh
# in your VPN-start wrapper, or run it manually once after `smartguard up`
gpg --card-status >/dev/null 2>&1 || true
```

That single call costs essentially nothing once scdaemon has cached the
card, and it absorbs the one-time failure so you never see it on a
user-facing operation.

The same trick at the SSH config level (runs before every `ssh`, but only
does meaningful work on the first one per gpg-agent lifetime):

```sshconfig
# ~/.ssh/config
Match exec "gpg --card-status >/dev/null 2>&1"

Host *
    # your usual options
```

If you don't care about the first failure (just retry once and you're set
for the rest of the session), no config change is needed.

### 3. Trim stale card identities from gpg-agent (recommended if you've had multiple YubiKeys)

If gpg-agent's keyring has Token references to YubiKeys other than the one
currently plugged in, the recovery cascade from a reset event explores
each unused serial in turn before giving up with `RESTART`. That turns a
"retry once" failure into "gpg gave up entirely."

Find which keygrip files reference cards:

```sh
grep -rln "Token:.*OPENPGP" ~/.gnupg/private-keys-v1.d/
```

For each `.key` file referencing a card you no longer have plugged in,
move it out of the directory (don't delete — keep a backup):

```sh
mkdir -p ~/.gnupg/stale-card-keys
mv ~/.gnupg/private-keys-v1.d/<keygrip>.key ~/.gnupg/stale-card-keys/
gpgconf --kill scdaemon gpg-agent
```

This keeps the on-card private keys safe (they live on the YubiKey, not
in `.key` files — the files are only the agent's pointers to them).

### 4. Optional: more aggressive scdaemon resync

If you want scdaemon to poll for card changes on every operation
(instead of trusting its in-memory cache), add to `~/.gnupg/scdaemon.conf`:

```
card-timeout 0
```

Adds milliseconds of latency to every gpg call, but eliminates the
stale-cache window entirely. Mostly redundant once the warm-up in
section 2 is in place.

## Diagnostics

If you suspect a card-sharing issue, enable scdaemon debug logging:

```sh
cat >> ~/.gnupg/scdaemon.conf <<EOF
debug 1024
log-file /tmp/scdaemon.log
EOF
gpgconf --kill scdaemon
# reproduce the failure
tail -n 200 /tmp/scdaemon.log
```

Common signatures:

| Log message | Likely meaning |
|---|---|
| `SCARD_E_SHARING_VIOLATION` (0x8010000B) | scdaemon trying to grab exclusive access — add `pcsc-shared` (section 1). |
| `pcsc_transmit failed: reset card` (0x80100068), then a full `learn-card` cascade | The one-time-per-VPN-session adaptation (section 2). If it repeats every handshake, something's wrong. |
| Multiple `SERIALNO --demand=...` requests for cards you no longer use, ending in `RESTART` | Stale Token entries in gpg-agent's keyring (section 3). |
| `card has been reset, try again` | Same root cause as the reset-card error. |

## What smartguard does internally

For the curious / for future debuggers:

- **`CardHandle::open`** runs once at startup: scan PC/SC readers, find the
  card matching the configured ident (or auto-pick the first OpenPGP card
  with an X25519 decryption key), read its public key, verify the User
  PIN to catch typos early, **and keep the `Card<Open>` connection open**
  in the handle. The cached PIN (`SecretString`), public key, ident, and
  `ss` cache live alongside it.
- **Each DH call** opens a `pcsc::Transaction` on the held connection,
  re-verifies the PIN (the card forgot it the moment another consumer's
  transaction ended), runs `DECIPHER (Cryptogram::ECDH)`, and drops the
  transaction with `LeaveCard` disposition. Transaction lock is held for
  ~50–200 ms per call; outside that window, other PC/SC consumers can
  freely transact on the same card.
- **One retry on transient errors** — typically `SCARD_E_SHARING_VIOLATION`
  from a competing daemon briefly holding the card. The retry path
  optionally re-scans the readers (in case the card was physically
  re-inserted with a different reader slot).
- **`pcsc::Card` Drop disposition is `ResetCard`** in upstream pcsc-rs.
  Because we hold the `Card<Open>` for the tunnel's lifetime, this only
  fires at shutdown — so we don't reset the card between operations,
  only when the tunnel goes down. This is what lets scdaemon's state
  cache settle and stay valid across smartguard handshakes.
- The **`ss` cache** (DH of two static keys, constant per peer) means we
  only hit the card once per peer at startup and then once per rekey
  (~every 2 min) for the fresh-ephemeral DH. Caching `ss` is safe because
  the Noise IKpsk2 chain mixes all four DH results — `ss` alone doesn't
  enable forging handshakes.

## Why we don't release the connection between handshakes

A reasonable instinct is "be polite, close the connection between
operations." That design (`Card<Open>` dropped after every DH call) was
tried briefly. It made things *worse*:

`pcsc::Card`'s Drop uses `Disposition::ResetCard`. Every smartguard
release would warm-reset the card. If another consumer (scdaemon, an
ssh-agent operation) was mid-transaction at that moment, they'd see
`SCARD_W_RESET_CARD` and their operation would fail — every time, not
just the first. The persistent-connection design produces *one* startup-
time transition and then steady-state coexistence; the close-per-use
design produced ongoing collisions.

If we ever needed to support consumers that can't be configured to use
`SCARD_SHARE_SHARED`, the path forward would be to override the pcsc-rs
Drop disposition to `LeaveCard` (upstream patch needed — `card-backend-pcsc`
doesn't surface that knob today). Not worth doing pre-emptively.
