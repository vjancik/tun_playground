// https://www.kernel.org/doc/Documentation/networking/tuntap.txt
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h

use std::{mem, env, ptr};
use std::os::{unix, raw};
use nix::{sys::stat, fcntl, unistd};
use anyhow::{anyhow, Result};
use bytes;

type CaddrT = *const raw::c_char;

const TUNSETIFF: u64 = nix::request_code_write!(b'T', 202, mem::size_of::<libc::c_int>());
nix::ioctl_write_ptr_bad!(ioctl_tunsetiff, TUNSETIFF, Ifreq);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ifreq {
    ifr_name: [raw::c_uchar; libc::IFNAMSIZ],
    ifr_ifru: IfrIfru,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union IfrIfru {
    pub ifru_addr: libc::sockaddr,
    pub ifru_dstaddr: libc::sockaddr,
    pub ifru_broadaddr: libc::sockaddr,
    pub ifru_netmask: libc::sockaddr,
    pub ifru_hwaddr: libc::sockaddr,
    pub ifru_flags: raw::c_short,
    pub ifru_ivalue: raw::c_int,
    pub ifru_mtu: raw::c_int,
    pub ifru_map: Ifmap,
    pub ifru_slave: [raw::c_uchar; libc::IFNAMSIZ],
    pub ifru_newname: [raw::c_uchar; libc::IFNAMSIZ],
    pub ifru_data: CaddrT,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Ifmap {
    pub mem_start: raw::c_ulong,
    pub mem_end: raw::c_ulong,
    pub base_addr: raw::c_ushort,
    pub irq: raw::c_uchar,
    pub dma: raw::c_uchar,
    pub port: raw::c_uchar,
}

struct Tun {
    _name: bytes::Bytes,
    fd: unix::io::RawFd,
}

impl Drop for Tun {
    fn drop(&mut self) {
        unistd::close(self.fd).ok();
    }
}

fn tun_alloc(name: String) -> Result<Tun> {
    let iface_name = bytes::Bytes::from(name);
    if iface_name.len() >= libc::IFNAMSIZ {
        return Err(anyhow!("Tunnel name too long"));
    }

    let fd = fcntl::open("/dev/net/tun", fcntl::OFlag::O_RDWR, stat::Mode::empty())?;

    let mut ifr = Ifreq {
        ifr_name: [0; libc::IFNAMSIZ],
        ifr_ifru: IfrIfru {
            ifru_flags: (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_MULTI_QUEUE ) as _,
        }
    };
    ifr.ifr_name[..iface_name.len()].copy_from_slice(&iface_name);

    if let Err(error) = unsafe { ioctl_tunsetiff(fd, &ifr) } {
        unistd::close(fd).ok();
        return Err(error.into());
    }

    Ok(Tun { fd, _name: iface_name })
}

#[allow(dead_code)]
fn set_non_blocking(fd: unix::io::RawFd) -> Result<()> {
    let flags = unsafe { fcntl::OFlag::from_bits_unchecked(fcntl::fcntl(fd, fcntl::FcntlArg::F_GETFL)?) };

    fcntl::fcntl(fd, fcntl::FcntlArg::F_SETFL(flags | fcntl::OFlag::O_NONBLOCK))?;
    Ok(())
}

fn main() -> Result<()> {
    let mut args = env::args();
    args.next();
    let tun_name = args.next().expect("Missing tunnel name argument");

    // default 1500 MTU TODO
    let mut buf = [0u8; 1500];
    // let mut addr_dest_buf = [0u8; 4];
    let tun_iff = tun_alloc(tun_name)?;
    // set_non_blocking(tun_iff.fd)?;

    // naive ICMP request reply
    loop {
        let nread = unistd::read(tun_iff.fd, &mut buf)?;
        if nread == 0 {
            return Ok(());
        }
        // println!("Bytes read: {}", nread);

        // swap source destination
        unsafe { ptr::swap_nonoverlapping(&mut buf[12], &mut buf[16], 4); }

        // change request to reply
        buf[20] = 0;

        let nwrite = unistd::write(tun_iff.fd, &mut buf[..nread])?;
        if nwrite == 0 {
            return Ok(());
        }
        // println!("Bytes written: {}", nwrite);
    }
    // Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    fn is_nonblock(fd: unix::io::RawFd) -> Result<bool> {
        let flags = fcntl::OFlag::from_bits_truncate(fcntl::fcntl(fd, fcntl::FcntlArg::F_GETFL)?);
        Ok(flags.intersects(fcntl::OFlag::O_NONBLOCK))
    }

    #[test]
    fn test_non_blocking() -> Result<()> {
        let tun_iff = tun_alloc("tuntest1".to_owned())?;
        set_non_blocking(tun_iff.fd)?;
        assert_eq!(is_nonblock(tun_iff.fd)?, true);
        Ok(())
    }

    const TUNSETIFF: u64 = 0x4004_54ca;

    #[test]
    fn test_tunsetiff_ioctl_code() -> Result<()> {
        assert_eq!(super::TUNSETIFF, TUNSETIFF);
        Ok(())
    }
}