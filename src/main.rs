// https://www.kernel.org/doc/Documentation/networking/tuntap.txt
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h

use std::ptr;
use nix::{unistd, errno};
use anyhow::{Result};
use mio;
use clap;

mod tun;

// naive ICMP request reply
fn icmp_handler(src: &mut [u8]) {
    // swap source destination
    unsafe { ptr::swap_nonoverlapping(&mut src[12], &mut src[16], 4); }

    // change request to reply
    src[20] = 0;
}

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

    let mut buf = [0u8; tun::MAX_SAFE_MTU];
    // let mut addr_dest_buf = [0u8; 4];
    let tun_iff = tun::Tun::new(tun_name.to_owned())?
        .set_non_blocking()?
        .set_mtu(tun::MAX_SAFE_MTU as _)?
        .set_addr(tun_addr.parse().unwrap())?
        .set_netmask(tun_mask.parse().unwrap())?
        .set_up()?;
    
    // let mtu = tun_iff.get_mtu()?;
    // println!("Interface MTU is: {}", mtu);

    let mut poll = mio::Poll::new()?;
    let mut events = mio::Events::with_capacity(1024);

    poll.registry().register(
        &mut mio::unix::SourceFd(&tun_iff.fd),
        mio::Token(0),
        mio::Interest::READABLE)?;

    loop {
        poll.poll(&mut events, None)?;

        for _ in &events {
            let read_result = unistd::read(tun_iff.fd, &mut buf);
            if read_result == Err(nix::Error::Sys(errno::EWOULDBLOCK)) {
                println!("Read would block");
                continue;
            }
            let nread = read_result?;

            if nread == 0 {
                return Ok(());
            }
            // println!("Bytes read: {}", nread);

            icmp_handler(&mut buf[..nread]);

            let nwrite = unistd::write(tun_iff.fd, &mut buf[..nread])?;
            if nwrite == 0 {
                return Ok(());
            }
            // println!("Bytes written: {}", nwrite);
        }
    }
    // Ok(())
}