# SmartGuard

A [WireGuard(R)](https://www.wireguard.com/) implementation in pure Rust which supports using a key in PC/SC smart card based on [RustyGuard](https://github.com/conradludgate/rustyguard).

## Project Goals

- [x] Contribute to RustyGuard to fix it for macos.
- [x] Support using key in smart card.
- [x] Stay connected if network gateway change.
- [ ] Good support of IPv4/IPv6 in TUN implementation.
- [ ] DNS config support.
- [ ] Run as manageable daemon.
- [ ] Android App.

## What is this?

WireGuard(R) is a protocol for secure tunnels, as a building block for Virtual Private Networks.

This project is based on RustyGuard, an "unmanaged" memory safe implementation of the WireGuard.

Unmanaged in this context means it is an application developer's responsibility to
process UDP packets going in and out of the RustyGuard interface - as well as manage IP routing etc.
RustyGuard will only take care of the byte processing and the cryptography.

SmartGuard provides an implementation of PC/SC smartguard as a Diffie-Hellman oracle for RustyGuard. SmartGuard aim to also provide a implementation similar to the TUN example in RustyGuard repo working with a smart card for system compatible with Tokio and support more platforms, notably Android.

---

## What the point of using a smart card ?

Quoted from [this Pro Custodibus post](https://www.procustodibus.com/blog/2023/03/openpgpcard-wireguard-guide), here are the benefits of using SmartGuard with your smart card:

> \[It\] allow you to keep a WireGuard private key stored safely on an OpenPGP card, without ever loading the key into your computer’s memory or disk. An OpenPGP card, in fact, has constraints that prevents it from ever exposing the actual private keys stored on the card — it only allows a few discrete operations to be performed using a private key through its hardware interface, without revealing the private key itself.
> 
> Therefore, if you generate a WireGuard key on an OpenPGP card (instead of importing an existing key generated elsewhere), you’re guaranteed that this key can never be stolen by an adversary remotely for use at a different time on a different computer. The key can be used only when the card is physically plugged into a computer, available to perform the periodic cryptographic operations required to initiate and maintain a WireGuard connection. Whoever controls the card physically, controls the key and its use.

TLDR: generating a X25519 key on your smart card and using it with SmartGuard GUARANTEE that it cannot be REMOTELY stolen in any way (only one exception: a quantum computer).

Be careful that:
- The PIN of the card is cached in memory, so a memory dump of smart card may leak your PIN.
- If the host is compromised and SmartGuard is on, the attacker can impersonate you and access the VPN.
- If you unplug the card, the connection will not immediately be stale, it is guarantee only after 3 minutes.
- Hardware Key management have different tradeoff: an attacker or yourself can reset your card with 3 failed PIN.
- With a key generated on card, using the card for anything else binds your WireGuard key to other usages which makes key rotation less practical.

To setup your smartcard you can read the [openpgp card requirements](https://www.procustodibus.com/blog/2023/03/openpgpcard-wireguard-guide/#openpgp-card) section of this same Pro Custodibus post. I strongly advise that you set the `disable-ccid` and `pcsc-shared` option in the `scdaemon.conf` file so that your smart card can still be used for your other usages (if you have some) while the VPN is running. This practice is common and also documented in a [guide on yubikey setup by Pro Custodibus](https://www.procustodibus.com/blog/2023/04/how-to-set-up-a-yubikey/#openpgp).

> [!NOTE]
> "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld.
