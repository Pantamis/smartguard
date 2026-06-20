# smartguard-mobile

Android (JNI) shell for smartguard. Builds as a `cdylib`
(`libsmartguard_mobile.so`) that an Android app loads from a `VpnService`.

Everything above the card transport — the WireGuard handshake, the `ss` cache,
the async DH oracle, session management — is shared verbatim with the desktop
build via `smartguard-crypto`. The only platform-specific piece is **how APDUs
reach the card**: desktop uses PC/SC; Android uses CCID-over-USB, with the raw
USB exchange living in Kotlin and the APDU bytes crossing JNI.

```
Kotlin app (VpnService, USB, PIN UI)
        │  JNI
        ▼
smartguard-mobile  ──  JniApduLink (impl ApduLink)   ← this crate
        │                     │ transceive(byte[]) over JNI ↑
        ▼                     │
smartguard-crypto  ──  ApduBackend → openpgp-card → DECIPHER
        │
rustyguard (handshake / sessions)  ── unchanged
```

## Status

| Piece | State |
|-------|-------|
| `JniApduLink` — `ApduLink` over a JNI `transceive` callback | ✅ implemented, compiles on host |
| `nativeOpenCard` / `nativeCardPublicKey` / `nativeCloseCard` | ✅ implemented |
| CCID-over-USB framing (Kotlin side) | ⛔ TODO |
| `nativeStartTunnel` — VpnService fd → tunnel loop | ⛔ stub (throws) |
| `cargo-ndk` packaging / Gradle integration | ⛔ TODO |

The card path is the load-bearing, novel part and is done. The tunnel loop is a
port of `smartguard/src/tunnel.rs` minus OS route/DNS management (that moves to
`VpnService.Builder`); see the TODO on `nativeStartTunnel`.

## JNI surface — `am.ito.smartguard.SmartguardNative`

```kotlin
object SmartguardNative {
    init { System.loadLibrary("smartguard_mobile") }

    // transport: any object exposing `byte[] transceive(byte[] command)`.
    external fun nativeOpenCard(transport: Any, ident: String, pin: String): Long
    external fun nativeCardPublicKey(cardHandle: Long): ByteArray?
    external fun nativeCloseCard(cardHandle: Long)
    external fun nativeStartTunnel(cardHandle: Long, tunFd: Int): Long  // TODO
}
```

`ident` is the card id (e.g. `"0006:15422467"`) or `"auto"`. Handles are opaque
`Long`s (raw pointers) — every `nativeOpenCard` must be paired with exactly one
`nativeCloseCard`.

## The transport contract

The `transport` object passed to `nativeOpenCard` must implement:

```kotlin
interface UsbApduTransport {
    /** One CCID-over-USB exchange: command APDU in, response APDU out
     *  (`data || SW1 SW2`). Throws on I/O error. */
    fun transceive(command: ByteArray): ByteArray
}
```

`transceive` is called from a dedicated native card thread (attached to the JVM
per call), at startup and on every WireGuard rekey (~every 2 min). It must be
safe to call repeatedly from that thread and should re-establish the USB
connection internally if it dropped.

### CCID-over-USB sketch (Kotlin side, TODO)

1. `UsbManager.deviceList` → find the token; request permission.
2. Open `UsbDeviceConnection`; claim the CCID interface (class `0x0B`); locate
   the bulk IN/OUT endpoints.
3. `transceive(apdu)` wraps the APDU in a CCID `PC_to_RDR_XfrBlock` block,
   `bulkTransfer`s it out, reads the `RDR_to_PC_DataBlock` reply, and returns
   its APDU payload. Handle the CCID sequence number and time-extension
   (`0x80`) responses.

(CCID framing is deliberately kept on the Kotlin side so the Rust seam stays a
clean APDU boundary. It could alternatively move into Rust behind the same
`ApduLink` — the contract is unchanged.)

## Building for Android

Requires the Android NDK and [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk):

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk

# arm64 device + x86_64 emulator; -o is the app's jniLibs dir
cargo ndk -t arm64-v8a -t x86_64 -o ../android/app/src/main/jniLibs \
    build -p smartguard-mobile --release
```

The crate also builds on the host toolchain (`cargo build -p smartguard-mobile`)
since `crate-type` includes `rlib` — useful for fast iteration and unit tests
without the NDK.

## Next steps

1. Kotlin: `UsbApduTransport` (CCID framing) + USB permission flow + PIN entry.
2. Implement `nativeStartTunnel`: wrap `tunFd` as an async fd, bind a
   `protect()`ed UDP socket, drive `build_sessions` + `handle_intern/extern`.
3. Kotlin `VpnService`: `Builder.addAddress/addRoute/addDnsServer`, then hand the
   established fd to `nativeStartTunnel`.
4. `cargo-ndk` + Gradle packaging.
