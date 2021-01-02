// https://www.kernel.org/doc/Documentation/networking/tuntap.txt
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h

use std::{ffi, mem};
use std::os::{unix, raw};
use nix;
use anyhow::{anyhow, Result};

type CaddrT = *const raw::c_char;

const TUNSETIFF: u64 = nix::request_code_write!(b'T', 202, mem::size_of::<libc::c_int>());

#[repr(C)]
#[derive(Copy, Clone)]
struct Ifreq {
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
    _name: String,
    fd: unix::io::RawFd,
}

impl Drop for Tun {
    fn drop(&mut self) {
        close(self.fd).ok();
    }
}



fn errno_str() -> String {
    let strerr = unsafe { libc::strerror(*libc::__errno_location()) };
    let c_str = unsafe { ffi::CStr::from_ptr(strerr) };
    c_str.to_string_lossy().into_owned()
}

fn tun_alloc(name: &str) -> Result<Tun> {
    let iface_name = name.as_bytes();
    if iface_name.len() >= libc::IFNAMSIZ {
        return Err(anyhow!("Tunnel name too long"));
    }

    let fd = match unsafe { libc::open(b"/dev/net/tun\0".as_ptr() as _, libc::O_RDWR) } {
        r if r < 0 => return Err(anyhow!(errno_str())),
        fd => fd
    };

    let mut ifr = Ifreq {
        ifr_name: [0; libc::IFNAMSIZ],
        ifr_ifru: IfrIfru {
            ifru_flags: (libc::IFF_TUN /* | libc::IFF_NO_PI | libc::IFF_MULTI_QUEUE*/) as _,
        }
    };

    ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);
    if unsafe { libc::ioctl(fd, TUNSETIFF, &ifr)} == -1 {
        close(fd).ok();
        return Err(anyhow!(errno_str()));
    }

    Ok(Tun { fd, _name: name.to_owned() })
}

#[inline]
fn fnctl_getfl(fd: unix::io::RawFd) -> Result<i32> {
    match unsafe { libc::fcntl(fd, libc::F_GETFL) } {
        r if r < 0 => Err(anyhow!(errno_str())),
        flags => Ok(flags),
    }
}

fn set_non_blocking(fd: unix::io::RawFd) -> Result<()> {
    let flags = fnctl_getfl(fd)?;

    match unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } {
        r if r < 0 => Err(anyhow!(errno_str())),
        _ => Ok(()),
    }
}

fn close(fd: unix::io::RawFd) -> Result<()> {
    match unsafe { libc::close(fd) } {
        r if r < 0 => Err(anyhow!(errno_str())),
        _ => Ok(()),
    }
}

fn main() -> Result<()> {
    let tun_iff = tun_alloc(&"tuntest1")?;
    set_non_blocking(tun_iff.fd)?;

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    fn is_nonblock(fd: unix::io::RawFd) -> Result<bool> {
        let flags = fnctl_getfl(fd)?;
    
        Ok(match flags & libc::O_NONBLOCK {
            0 => false,
            _ => true,
        })
    }

    #[test]
    fn test_non_blocking() -> Result<()> {
        let tun_iff = tun_alloc(&"tuntest1")?;
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