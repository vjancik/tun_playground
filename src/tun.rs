use std::{mem, cell};
use std::os::{unix, raw};
use nix::{sys::socket, sys::stat, fcntl, unistd};
use anyhow::{anyhow, Result};
use bytes;

type CaddrT = *const raw::c_char;

pub const TUNSETIFF: u32 = nix::request_code_write!(b'T', 202, mem::size_of::<libc::c_int>()) as _;
// Maximum guaranteed non-drop reassembly size for IPv4, minus the IPv4 header size (without options), minus the UDP header size
pub const MAX_SAFE_MTU: usize = 576 - 20 - 8;

nix::ioctl_write_ptr_bad!(ioctl_tunsetiff, TUNSETIFF, Ifreq);

nix::ioctl_read_bad!(ioctl_getmtu, libc::SIOCGIFMTU, Ifreq);
nix::ioctl_write_ptr_bad!(ioctl_setmtu, libc::SIOCSIFMTU, Ifreq);

nix::ioctl_read_bad!(ioctl_getaddr, libc::SIOCGIFADDR, Ifreq);
nix::ioctl_write_ptr_bad!(ioctl_setaddr, libc::SIOCSIFADDR, Ifreq);

nix::ioctl_read_bad!(ioctl_getnetmask, libc::SIOCGIFNETMASK, Ifreq);
nix::ioctl_write_ptr_bad!(ioctl_setnetmask, libc::SIOCSIFNETMASK, Ifreq);

nix::ioctl_read_bad!(ioctl_getflags, libc::SIOCGIFFLAGS, Ifreq);
nix::ioctl_write_ptr_bad!(ioctl_setflags, libc::SIOCSIFFLAGS, Ifreq);

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

pub struct Tun {
    pub _name: bytes::Bytes,
    _socket: unix::io::RawFd,
    // slightly inefficient, not in the hot path, Cell::update would be prefered on nightly
    ifreq: cell::RefCell<Ifreq>,
    pub fd: unix::io::RawFd,
}

impl Drop for Tun {
    fn drop(&mut self) {
        unistd::close(self._socket).ok();
        unistd::close(self.fd).ok();
    }
}

impl Tun {
    pub fn new(name: String) -> Result<Tun> {
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

        // an apparently unitialized "placeholder" socket to facilitate the IOCTL call
        use socket::{socket, AddressFamily, SockType, SockFlag};
        let sock_fd = socket(AddressFamily::Inet, SockType::Datagram, SockFlag::empty(), None)?;
    
        Ok(Tun { fd, _name: iface_name, ifreq: cell::RefCell::new(ifr), _socket: sock_fd })
    }

    pub fn set_non_blocking(self) -> Result<Tun> {
        set_non_blocking(self.fd)?;
        Ok(self)
    }

    #[allow(dead_code)]
    pub fn get_mtu(&self) -> Result<libc::c_int> {
        self.ifreq.borrow_mut().ifr_ifru.ifru_mtu = 0;
        unsafe { 
            ioctl_getmtu(self._socket, &mut *self.ifreq.borrow_mut())?;
            Ok(self.ifreq.borrow().ifr_ifru.ifru_mtu)
        }
    }

    pub fn set_mtu(self, mtu: libc::c_int) -> Result<Tun> {
        self.ifreq.borrow_mut().ifr_ifru.ifru_mtu = mtu;
        unsafe { ioctl_setmtu(self._socket, &*self.ifreq.borrow_mut())?; }

        Ok(self)
    }

    pub fn set_addr(self, addr: std::net::Ipv4Addr) -> Result<Tun> {
        // TODO: could use a custom builder
        let addr = socket::InetAddr::new(socket::IpAddr::V4(socket::Ipv4Addr::from_std(&addr)), 0);
        let sock_addr = socket::SockAddr::new_inet(addr);
        let (c_sockaddr, _) = sock_addr.as_ffi_pair();

        self.ifreq.borrow_mut().ifr_ifru.ifru_addr = c_sockaddr.to_owned();
        unsafe { ioctl_setaddr(self._socket, &*self.ifreq.borrow_mut())?; }

        Ok(self)
    }

    pub fn set_netmask(self, netmask: u8) -> Result<Tun> {
        // TODO: somebody save this API from itself, thank you
        use bytes::BufMut;
        let mut buf = vec![];
        buf.put_i32(-1 << 32 - netmask);
        let addr = socket::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
        // println!("{} = {:b}", netmask, () as i32);
        let addr = socket::InetAddr::new(socket::IpAddr::V4(addr), 0);
        let sock_addr = socket::SockAddr::new_inet(addr);
        let (c_sockaddr, _) = sock_addr.as_ffi_pair();

        self.ifreq.borrow_mut().ifr_ifru.ifru_netmask = c_sockaddr.to_owned();
        unsafe { ioctl_setnetmask(self._socket, &*self.ifreq.borrow_mut())?; }
        Ok(self)
    }

    fn get_flags(&self) -> Result<libc::c_short> {
        unsafe { ioctl_getflags(self._socket, &mut *self.ifreq.borrow_mut())?; }

        Ok(unsafe { self.ifreq.borrow().ifr_ifru.ifru_flags })
    }

    pub fn set_up(self) -> Result<Tun> {
        let flags = self.get_flags()?;
        self.ifreq.borrow_mut().ifr_ifru.ifru_flags = flags | libc::IFF_UP as libc::c_short;
        unsafe { ioctl_setflags(self._socket, &*self.ifreq.borrow_mut())?; }

        Ok(self)
    }
}

// fn result_into<T, E: Into<anyhow::Error>>(res: result::Result<T, E>) -> result::Result<T, anyhow::Error> {
//     match res {
//         Err(error) => Err(error.into()),
//         Ok(val) => Ok(val)
//     }
// }

#[inline]
fn set_non_blocking(fd: unix::io::RawFd) -> Result<()> {
    let flags = unsafe { fcntl::OFlag::from_bits_unchecked(fcntl::fcntl(fd, fcntl::FcntlArg::F_GETFL)?) };

    fcntl::fcntl(fd, fcntl::FcntlArg::F_SETFL(flags | fcntl::OFlag::O_NONBLOCK))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix;
    use nix::fcntl;

    fn is_nonblock(fd: unix::io::RawFd) -> Result<bool> {
        let flags = fcntl::OFlag::from_bits_truncate(fcntl::fcntl(fd, fcntl::FcntlArg::F_GETFL)?);
        Ok(flags.intersects(fcntl::OFlag::O_NONBLOCK))
    }

    #[test]
    fn test_non_blocking() -> Result<()> {
        let mut tun_iff = Tun::new("tuntest1".to_owned())?;
        tun_iff = tun_iff.set_non_blocking()?;
        assert_eq!(is_nonblock(tun_iff.fd)?, true);
        Ok(())
    }

    const TUNSETIFF: u64 = 0x4004_54ca;

    #[test]
    fn test_tunsetiff_ioctl_code() -> Result<()> {
        assert_eq!(TUNSETIFF, TUNSETIFF);
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