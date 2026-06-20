//! Dual-stack equivalents of `rustyguard_tun::handle_extern` /
//! `handle_intern`. Same control flow as the v4-only originals, but the
//! peer-lookup keys are extracted from the IP version nibble (v4 src/dst at
//! bytes 12–15 / 16–19; v6 at bytes 8–23 / 24–39) instead of going through a
//! crate-typed v4 packet parser.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rustyguard_core::{DataHeader, Message, SendMessage, Sessions};
use rustyguard_crypto::DhOracle;
use rustyguard_tun::{
    TUN_BUF_START, Write,
    tun::{Device as _, KERNEL_HEADER_LEN, platform},
};

use super::peer_net::PeerNet;

/// Starting position of the IP packet without any header
const IP_PACKET_START: usize = const_max(std::mem::size_of::<DataHeader>(), KERNEL_HEADER_LEN);

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

/// Process a UDP packet just received from the network. Either produces a
/// reply to send over UDP, an inbound IP packet to write to the TUN, or
/// nothing (handshake/keepalive/etc).
pub async fn handle_extern<'a, O: DhOracle>(
    sessions: &mut Sessions<O>,
    peer_net: &PeerNet,
    addr: SocketAddr,
    ep_buf: &'a mut [u8],
) -> Write<'a> {
    match sessions.recv_message(addr, ep_buf).await {
        Err(e) => println!("error: {e:?}"),
        Ok(Message::Noop) => println!("noop"),
        Ok(Message::HandshakeComplete(_encryptor)) => {
            // TODO(conrad): resend queued message.
            // _encryptor.encrypt_and_frame(payload_buffer)
            // endpoint.send_to(payload_buffer, addr).await.unwrap()
        }
        Ok(Message::Read(peer_idx, buf)) => {
            if buf.is_empty() {
                return Write::None;
            }

            let Some(src) = ip_src(buf) else {
                return Write::None;
            };
            // Cryptokey routing: the decrypted packet's src must belong to
            // the peer that just sent it. Otherwise drop.
            if peer_net.lookup(src) != peer_idx {
                return Write::None;
            }

            let len_data = buf.len();
            // recv_message wrote the decrypted packet for the TUN
            // of len_data bytes starting at IP_PACKET_START
            // we prepend the kernel header before it if needed
            let tun_buf = &mut ep_buf[TUN_BUF_START..IP_PACKET_START + len_data];
            let (header, packet) = tun_buf
                .split_first_chunk_mut()
                .expect("Enough len for header by definition of TUN_BUF_START");
            *header = platform::Device::get_header_for(packet);

            // and return KERNEL_HEADER || IP_PACKET for the TUN
            return Write::Inbound(tun_buf);
        }
        Ok(Message::Write(buf)) => {
            let len_data = buf.len();
            // println!("sending: {buf:?}");
            return Write::Outbound(&mut ep_buf[..len_data], addr);
        }
    };

    Write::None
}

/// Process an IP packet just read from the TUN. Looks up the destination
/// peer in `peer_net` and asks Sessions to encrypt/forward.
pub async fn handle_intern<'a, O: DhOracle>(
    sessions: &mut Sessions<O>,
    peer_net: &PeerNet,
    reply_buf: &'a mut [u8], /* TUN buffer */
    filled: usize,
) -> Write<'a> {
    let Some(dst) = ip_dst(&reply_buf[IP_PACKET_START..filled]) else {
        return Write::None;
    };
    let peer_idx = peer_net.lookup(dst);

    let n = filled - IP_PACKET_START;
    let pad_to = IP_PACKET_START + n.next_multiple_of(16);
    reply_buf[filled..pad_to].fill(0);

    match sessions
        .send_message(peer_idx, &mut reply_buf[IP_PACKET_START..pad_to])
        .await
        .unwrap()
    {
        SendMessage::Maintenance(msg) => {
            let data = msg.data();
            reply_buf[..data.len()].copy_from_slice(data);
            Write::Outbound(&reply_buf[..data.len()], msg.to())
        }
        SendMessage::Data(ep, metadata) => {
            /// Size of the WireGuard tag
            const TAG_FOOTER_SIZE: usize = 16;

            /// Starting position to write to endpoint
            const WG_PACKET_START: usize = IP_PACKET_START - std::mem::size_of::<DataHeader>();
            // send_message wrote the cypher text at [IP_PACKET_START..pad_to].
            // We frame with the WireGuard header and footer.
            // So the header must be placed at [WG_PACKET_START..IP_PACKET_START] and footer
            // at [pad_to..pad_to + TAG_FOOTER_SIZE]. So we
            // frame_in_place the payload at the buffer:
            let buf = &mut reply_buf[WG_PACKET_START..pad_to + TAG_FOOTER_SIZE];
            metadata.frame_in_place(buf);
            Write::Outbound(buf, ep)
        }
    }
}

/// TODO: replace by max once const stable
const fn const_max(a: usize, b: usize) -> usize {
    if a <= b { b } else { a }
}
