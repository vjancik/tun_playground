// https://www.kernel.org/doc/Documentation/networking/tuntap.txt
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h

use std::{ptr, io, net, os::unix::io::AsRawFd};
use nix::{unistd, errno};
use anyhow::{Result};
use mio;
use socket2;
use clap;

mod tun;

// naive ICMP request reply
#[allow(dead_code)]
fn icmp_handler(src: &mut [u8]) {
    // swap source destination
    unsafe { ptr::swap_nonoverlapping(&mut src[12], &mut src[16], 4); }

    // change request to reply
    src[20] = 0;
}

const TUN_IFF: mio::Token = mio::Token(0);
const PUBLIC_IFF: mio::Token = mio::Token(1);

fn main() -> Result<()> {
    let matches = clap::App::new("tun_playground")
        .arg(clap::Arg::with_name("server").long("server").conflicts_with("client").required_unless("client"))
        .arg(clap::Arg::with_name("client").long("client").conflicts_with("server").required_unless("server"))
        .arg(clap::Arg::with_name("tun").long("tun").value_name("NAME").required(true)
            .help("TUN interface name"))
        .arg(clap::Arg::with_name("public").long("public").value_name("ADDRESS").required(true)
            .help("public IP:port UDP socket server address"))
        .arg(clap::Arg::with_name("virtual").long("virtual").value_name("ADDRESS").required(true)
            .help("IP address on the tunnel interface"))
        .arg(clap::Arg::with_name("mask").long("mask").value_name("MASK").default_value("24")
            .help("Subnet mask of the tunnel interface"))
        .get_matches();

    let tun_name = matches.value_of("tun").unwrap();
    let tun_addr = matches.value_of("virtual").unwrap();
    let tun_mask = matches.value_of("mask").unwrap();

    let is_server = matches.is_present("server");
    let udp_addr = matches.value_of("public").unwrap().parse::<net::SocketAddr>()?;

    // let mut addr_dest_buf = [0u8; 4];
    let tun_iff = tun::Tun::new(tun_name.to_owned())?
    .set_non_blocking()?
    .set_mtu(tun::MAX_SAFE_MTU as _)?
    .set_addr(tun_addr.parse()?)?
    .set_netmask(tun_mask.parse()?)?
    .set_up()?;
    
    let mut buf = [0u8; tun::MAX_SAFE_MTU];
    // let mtu = tun_iff.get_mtu()?;
    // println!("Interface MTU is: {}", mtu);

    let mut poll = mio::Poll::new()?;
    let mut events = mio::Events::with_capacity(1024);

    poll.registry().register(
        &mut mio::unix::SourceFd(&tun_iff.fd), TUN_IFF, mio::Interest::READABLE)?;

    use socket2::{Socket, Domain, Type, Protocol};
    let udp_sock = Socket::new(Domain::ipv4(), Type::dgram().non_blocking(), Some(Protocol::udp()))?;
    udp_sock.set_reuse_address(true)?;
    udp_sock.set_reuse_port(true)?;
    if is_server {
        let port = udp_addr.port();
        udp_sock.bind(&format!{"127.0.0.1:{}", port}.parse::<net::SocketAddr>()?.into())?;
    } else {
        udp_sock.bind(&"127.0.0.1:0".parse::<net::SocketAddr>()?.into())?;
    }
    // let mut udp_sock = mio::net::UdpSocket::from_std(udp_sock.into_udp_socket());

    poll.registry().register(&mut mio::unix::SourceFd(&udp_sock.as_raw_fd()), PUBLIC_IFF, mio::Interest::READABLE)?;

    loop {
        poll.poll(&mut events, None)?;

        for event in events.iter() {
            if event.token() == TUN_IFF { 
                let read_result = unistd::read(tun_iff.fd, &mut buf);
                if read_result == Err(nix::Error::Sys(errno::EWOULDBLOCK)) {
                    println!("Read would block");
                    continue;
                }
                let nread = read_result?;

                // icmp_handler(&mut buf[..nread]);

                println!("Writing {} bytes from TUN to UDP socket", nread);
                let _nwrite = udp_sock.send_to(&mut buf[..nread], &udp_addr.into())?;
            } else {
                let (nread, _) = match udp_sock.recv_from(&mut buf) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    any => any,
                }?;

                println!("Writing {} bytes from UDP socket to TUN", nread);
                let _nwrite = unistd::write(tun_iff.fd, &mut buf[..nread])?;
            }
        }
    }
    // Ok(())
}