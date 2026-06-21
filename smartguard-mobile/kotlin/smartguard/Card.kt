package smartguard

import java.lang.ref.Cleaner

/**
 * Low-level bridge to the native smartguard library (`libsmartguard_mobile.so`).
 *
 * These map 1:1 to the JNI entry points in `smartguard-mobile/src/lib.rs`. They
 * take/return an opaque `Long` handle (a raw Rust pointer) and throw a
 * `RuntimeException` on failure.
 *
 * File-private: nothing outside this file can reach these, so [Card] (same
 * file) is the only entry point — callers cannot bypass it and mishandle the
 * raw `Long`. JNI binds native methods by symbol name and ignores Kotlin
 * visibility, so `private` costs nothing at the FFI boundary.
 */
private object SmartguardNative {
    init {
        System.loadLibrary("smartguard_mobile")
    }

    /** @return handle (never 0; throws on failure). */
    external fun nativeOpenCard(transport: Any, ident: String, pin: String): Long

    external fun nativeCardPublicKey(handle: Long): ByteArray

    external fun nativeCloseCard(handle: Long)

    /**
     * Run the WireGuard tunnel until cancelled. **Blocks** for the tunnel's
     * whole lifetime — call on a dedicated thread, never the main thread.
     *
     * Opens its own card over [transport] (so it's independent of the handle
     * API above). Adopts and closes [tunFd] (the `VpnService` descriptor),
     * [udpFd] (a socket the app already created and `protect()`ed), and
     * [cancelFd] (the read end of a pipe). Stop the tunnel by closing/writing
     * the pipe's write end. Single peer for now.
     */
    external fun nativeRunTunnel(
        transport: Any,
        ident: String,
        pin: String,
        tunFd: Int,
        udpFd: Int,
        cancelFd: Int,
        peerPublicKey: String,
        endpoint: String,
        allowedIps: String,
        keepaliveSeconds: Int,
    )
}

/**
 * Performs one CCID-over-USB exchange with the connected OpenPGP token.
 *
 * Implemented by the app's USB layer (over `UsbDeviceConnection`). Called from a
 * dedicated native card thread, at card open and on every WireGuard rekey, so it
 * must be safe to call repeatedly and should re-establish the USB connection
 * internally if it dropped.
 */
interface UsbApduTransport {
    /**
     * @param command a complete command APDU
     * @return the response APDU (`data || SW1 SW2`)
     * @throws java.io.IOException on a transport error
     */
    fun transceive(command: ByteArray): ByteArray
}

/**
 * An open OpenPGP card, backed by a native handle.
 *
 * The handle is a raw Rust pointer behind a `Long`. Dereferencing a stale handle
 * on the native side is undefined behaviour, so this class owns the handle's
 * lifetime end to end:
 *
 *  - It is [AutoCloseable]: use it with `Card.open(...).use { ... }` for
 *    deterministic release — this is the primary mechanism.
 *  - A [Cleaner] is registered as a **backstop**: if a caller forgets to close,
 *    the handle is still freed (and the native card thread stopped) when the
 *    `Card` becomes unreachable. The backstop is insurance, not the contract —
 *    GC timing is non-deterministic, so always prefer `use { }`.
 *
 * The [Cleaner] guarantees the underlying free runs **at most once**, whether
 * triggered by [close] or by GC, so there is no double-free.
 *
 * Note: `java.lang.ref.Cleaner` requires Android API 33+. On a lower `minSdk`,
 * drop the cleaner and rely on `use { }` only (or replace it with a
 * `ReferenceQueue`/`PhantomReference` backstop).
 */
class Card private constructor(
    private val handle: Long,
    // Held only to tie the transport's lifetime to the card's: the native side
    // also keeps a JNI global ref, but keeping it here documents the link and
    // stops the app's last reference from being collected mid-tunnel.
    @Suppress("unused") private val transport: UsbApduTransport,
) : AutoCloseable {

    /**
     * The state the [Cleaner] needs to free the handle.
     *
     * CRITICAL: this must NOT capture the enclosing [Card] (directly or via a
     * lambda over a `Card` field), or the `Card` could never become unreachable
     * and the cleaner would never run. It holds only the primitive handle.
     */
    private class HandleState(private val handle: Long) : Runnable {
        override fun run() {
            if (handle != 0L) {
                SmartguardNative.nativeCloseCard(handle)
            }
        }
    }

    private val cleanable: Cleaner.Cleanable = cleaner.register(this, HandleState(handle))

    @Volatile
    private var closed = false

    /** The card's X25519 public key (32 bytes). */
    fun publicKey(): ByteArray {
        check(!closed) { "Card is closed" }
        return SmartguardNative.nativeCardPublicKey(handle)
    }

    /**
     * Free the native handle and stop the card thread. Idempotent — safe to call
     * explicitly and again via `use { }`. Subsequent [publicKey] calls throw.
     */
    override fun close() {
        if (!closed) {
            closed = true
            cleanable.clean()
        }
    }

    companion object {
        private val cleaner: Cleaner = Cleaner.create()

        /**
         * Open the OpenPGP card over [transport], verifying the User [pin].
         *
         * @param ident the card identifier (e.g. `"0006:15422467"`) or `"auto"`
         *   to pick the first X25519-capable card.
         * @throws RuntimeException if no matching card is found, the PIN is
         *   wrong, or the card has no X25519 decryption key.
         */
        fun open(transport: UsbApduTransport, ident: String, pin: String): Card {
            // nativeOpenCard throws on failure, so a returned handle is valid.
            val handle = SmartguardNative.nativeOpenCard(transport, ident, pin)
            return Card(handle, transport)
        }
    }
}
