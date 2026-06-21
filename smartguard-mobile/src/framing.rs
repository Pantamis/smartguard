//! Android data-plane framing — raw-IP equivalents of
//! `smartguard_crypto::{handle_extern, handle_intern}`.
//!
//! Those desktop helpers live behind `rustyguard-tun`, whose TUN backend is
//! macOS/Linux only, so they're gated out of the Android build. The logic
//! itself is platform-independent; the only platform-specific input is the
//! kernel/AF header the OS prepends to TUN frames. Android's `VpnService`
//! descriptor carries **bare IP packets** (no header), so `KERNEL_HEADER_LEN`
//! is 0 and the framing math collapses:
//!
//! * [`IP_PACKET_START`] is just past the WireGuard `DataHeader` (room to frame
//!   an outbound packet in place); there is no kernel header before it.
//! * inbound: the decrypted IP packet at `IP_PACKET_START` is exactly what goes
//!   to the TUN — nothing is prepended.
//! * outbound: the WireGuard header is framed at offset 0
//!   (`IP_PACKET_START - size_of::<DataHeader>()`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rustyguard_core::{DataHeader, Message, SendMessage, Sessions};
use rustyguard_crypto::AsyncDhOracle;
use smartguard_crypto::PeerNet;

/// Offset of the IP packet within a working buffer. No kernel header on
/// Android (unlike macOS utun's 4-byte AF prefix), so this is just the room
/// reserved to frame the WireGuard `DataHeader` ahead of an outbound packet.
pub const IP_PACKET_START: usize = std::mem::size_of::<DataHeader>();

/// What the caller should do with a processed packet.
pub enum Write<'a> {
    /// Send these bytes back over UDP to the given endpoint.
    Outbound(&'a [u8], SocketAddr),
    /// Write this decrypted IP packet to the TUN.
    Inbound(&'a [u8]),
    /// Nothing to do (handshake, keepalive, drop).
    None,
}

fn ip_src(buf: &[u8]) -> Option<IpAddr> {
    match buf.first()? >> 4 {
        4 if buf.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            buf[12], buf[13], buf[14], buf[15],
        ))),
        6 if buf.len() >= 40 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&buf[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

fn ip_dst(buf: &[u8]) -> Option<IpAddr> {
    match buf.first()? >> 4 {
        4 if buf.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            buf[16], buf[17], buf[18], buf[19],
        ))),
        6 if buf.len() >= 40 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&buf[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// Process a UDP datagram just received from the network. `ep_buf` holds the
/// received bytes starting at offset 0 (the WireGuard packet).
pub async fn handle_extern<'a, O: AsyncDhOracle>(
    sessions: &mut Sessions<O>,
    peer_net: &PeerNet,
    addr: SocketAddr,
    ep_buf: &'a mut [u8],
) -> Write<'a> {
    match sessions.recv_message(addr, ep_buf).await {
        Err(_) | Ok(Message::Noop) | Ok(Message::HandshakeComplete(_)) => {}
        Ok(Message::Read(peer_idx, buf)) => {
            if buf.is_empty() {
                return Write::None;
            }
            let Some(src) = ip_src(buf) else {
                return Write::None;
            };
            // Cryptokey routing: the decrypted packet's source must belong to
            // the peer that just sent it, else drop.
            if peer_net.lookup(src) != peer_idx {
                return Write::None;
            }
            let len = buf.len();
            // recv_message wrote the decrypted IP packet at IP_PACKET_START.
            // No kernel header on Android, so that *is* the TUN frame.
            return Write::Inbound(&ep_buf[IP_PACKET_START..IP_PACKET_START + len]);
        }
        Ok(Message::Write(buf)) => {
            let len = buf.len();
            return Write::Outbound(&ep_buf[..len], addr);
        }
    }
    Write::None
}

/// Process an IP packet just read from the TUN. The packet must sit at
/// `IP_PACKET_START` in `reply_buf`, ending at `filled`, leaving the bytes
/// before it free for the WireGuard header.
pub async fn handle_intern<'a, O: AsyncDhOracle>(
    sessions: &mut Sessions<O>,
    peer_net: &PeerNet,
    reply_buf: &'a mut [u8],
    filled: usize,
) -> Write<'a> {
    let Some(dst) = ip_dst(&reply_buf[IP_PACKET_START..filled]) else {
        return Write::None;
    };
    let peer_idx = peer_net.lookup(dst);

    // Pad the plaintext slot to a 16-byte multiple (the cipher works on blocks).
    let n = filled - IP_PACKET_START;
    let pad_to = IP_PACKET_START + n.next_multiple_of(16);
    reply_buf[filled..pad_to].fill(0);

    let send = match sessions
        .send_message(peer_idx, &mut reply_buf[IP_PACKET_START..pad_to])
        .await
    {
        Ok(send) => send,
        Err(_) => return Write::None,
    };
    match send {
        SendMessage::Maintenance(msg) => {
            let data = msg.data();
            reply_buf[..data.len()].copy_from_slice(data);
            Write::Outbound(&reply_buf[..data.len()], msg.to())
        }
        SendMessage::Data(ep, metadata) => {
            const TAG_FOOTER_SIZE: usize = 16;
            // WG header goes immediately before the IP packet. With no kernel
            // header, IP_PACKET_START == size_of::<DataHeader>(), so this is 0.
            const WG_PACKET_START: usize = IP_PACKET_START - std::mem::size_of::<DataHeader>();
            let buf = &mut reply_buf[WG_PACKET_START..pad_to + TAG_FOOTER_SIZE];
            metadata.frame_in_place(buf);
            Write::Outbound(buf, ep)
        }
    }
}
