// https://www.kernel.org/doc/Documentation/networking/tuntap.txt
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h

use std::{mem, env, ptr, result, cell};
use std::os::{unix, raw};
use nix::{sys::socket, sys::stat, fcntl, unistd, errno};
use anyhow::{anyhow, Result};
use bytes;
use mio;

type CaddrT = *const raw::c_char;

const TUNSETIFF: u64 = nix::request_code_write!(b'T', 202, mem::size_of::<libc::c_int>());

nix::ioctl_write_ptr_bad!(ioctl_tunsetiff, TUNSETIFF, Ifreq);
nix::ioctl_read_bad!(ioctl_getmtu, libc::SIOCGIFMTU, Ifreq);
nix::ioctl_write_ptr_bad!(ioctl_setmtu, libc::SIOCSIFMTU, Ifreq);

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
    // slightly inefficient, not in the hot path, Cell::update would be prefered on nightly
    ifreq: cell::RefCell<Ifreq>,
    fd: unix::io::RawFd,
}

impl Drop for Tun {
    fn drop(&mut self) {
        unistd::close(self.fd).ok();
    }
}

impl Tun {
    fn new(name: String) -> Result<Tun> {
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
    
        Ok(Tun { fd, _name: iface_name, ifreq: cell::RefCell::new(ifr) })
    }

    fn set_non_blocking(self) -> Result<Tun> {
        set_non_blocking(self.fd)?;
        Ok(self)
    }

    fn get_mtu(&self) -> Result<libc::c_int> {
        // an apparently unitialized "placeholder" socket to facilitate the IOCTL call
        use socket::{socket, AddressFamily, SockType, SockFlag};
        let fd = socket(AddressFamily::Inet, SockType::Datagram, SockFlag::empty(), None)?;

        self.ifreq.borrow_mut().ifr_ifru.ifru_mtu = 0;
        unsafe { 
            ioctl_getmtu(fd, &mut *self.ifreq.borrow_mut())?;
            unistd::close(fd)?;
            Ok(self.ifreq.borrow().ifr_ifru.ifru_mtu)
        }
    }

    #[allow(dead_code)]
    fn set_mtu(self, mtu: libc::c_int) -> Result<Tun> {
        use socket::{socket, AddressFamily, SockType, SockFlag};
        let fd = socket(AddressFamily::Inet, SockType::Datagram, SockFlag::empty(), None)?;

        self.ifreq.borrow_mut().ifr_ifru.ifru_mtu = mtu;
        unsafe { 
            ioctl_setmtu(fd, &*self.ifreq.borrow_mut())?;
            unistd::close(fd)?;
        }

        Ok(self)
    }
}

#[allow(dead_code)]
#[inline(always)]
fn result_into<T, E: Into<anyhow::Error>>(res: result::Result<T, E>) -> result::Result<T, anyhow::Error> {
    match res {
        Err(error) => Err(error.into()),
        Ok(val) => Ok(val)
    }
}

#[inline]
fn set_non_blocking(fd: unix::io::RawFd) -> Result<()> {
    let flags = unsafe { fcntl::OFlag::from_bits_unchecked(fcntl::fcntl(fd, fcntl::FcntlArg::F_GETFL)?) };

    fcntl::fcntl(fd, fcntl::FcntlArg::F_SETFL(flags | fcntl::OFlag::O_NONBLOCK))?;
    Ok(())
}

// naive ICMP request reply
fn icmp_handler(src: &mut [u8]) {
    // swap source destination
    unsafe { ptr::swap_nonoverlapping(&mut src[12], &mut src[16], 4); }

    // change request to reply
    src[20] = 0;
}

fn main() -> Result<()> {
    let mut args = env::args();
    args.next();
    let tun_name = args.next().expect("Missing tunnel name argument");

    // default 1500 MTU TODO
    let mut buf = [0u8; 1500];
    // let mut addr_dest_buf = [0u8; 4];
    let tun_iff = Tun::new(tun_name)?.set_non_blocking()?.set_mtu(555)?;
    let mtu = tun_iff.get_mtu()?;
    println!("Interface MTU is: {}", mtu);

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


#[cfg(test)]
mod tests {
    use super::*;

    fn is_nonblock(fd: unix::io::RawFd) -> Result<bool> {
        let flags = fcntl::OFlag::from_bits_truncate(fcntl::fcntl(fd, fcntl::FcntlArg::F_GETFL)?);
        Ok(flags.intersects(fcntl::OFlag::O_NONBLOCK))
    }

    #[test]
    fn test_non_blocking() -> Result<()> {
        let tun_iff = Tun::new("tuntest1".to_owned())?;
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

    #[test]
    fn test_multi_queue() -> Result<()> {
        let mut iffs = vec!();
        for _ in &[0..8] {
            iffs.push(Tun::new("tuntest1".to_owned())?);
        }
        Ok(())
    }

    #[test]
    fn test_mtu() -> Result<()> {
        let tun_iff = Tun::new("tuntest1".to_owned())?.set_mtu(499)?;
        assert_eq!(tun_iff.get_mtu()?, 499);
        Ok(())
    }
}