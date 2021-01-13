// https://www.kernel.org/doc/Documentation/networking/tuntap.txt
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h

use std::{io, net, mem, sync::{self, atomic}, os::unix, collections};
use nix::{unistd, errno};
use anyhow::{Result};
use mio;
use socket2;
use clap::{self, value_t};
use num_cpus;
use signal_hook;
use tracing::{debug, info};
use tracing_subscriber::FmtSubscriber;
use byteorder::{ByteOrder};
// use parking_lot::RwLock;
use smallvec::SmallVec;

mod tun;
mod runtime;

// struct TunnelConfig {
//     tun_name: String,
//     tun_addr: net::Ipv4Addr,
//     tun_iff: Option<tun::Tun>,
//     tun_mask: u8,
//     port: u16,
//     thread_id: u8,
//     gateway: Option<net::SocketAddr>,
//     tun_to_udp: sync::Arc<RwLock<collections::HashMap<net::Ipv4Addr, net::SocketAddr>>>,
//     // channel: cell::RefCell<mio::net::UnixDatagram>,
// }

// impl fmt::Debug for TunnelConfig {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         f.debug_struct("TunnelConfig")
//          .field("tun_name", &self.tun_name)
//          .field("tun_addr", &self.tun_addr)
//          .field("tun_iff", &self.tun_iff)
//          .field("tun_mask", &self.tun_mask)
//          .field("port", &self.port)
//          .field("thread_id", &self.thread_id)
//          .field("gateway", &self.gateway)
//          // TODO: doesn't print properly?
//          .field("peer_table", &*self.tun_to_udp.read())
//          .field("channel", &"UnixDatagram channel")
//          .finish()
//     }
// }

// fn initialize_tunnel(cfg: TunnelConfig) -> Result<()> 
// {
//     let tun_iff = match cfg.thread_id {
//         0 => cfg.tun_iff.unwrap(),
//         _ => {
//             tun::Tun::new(cfg.tun_name)?
//                 .set_non_blocking()?
//         }
//     };
//     let mut tun_iff_flags: IoFlags = Default::default();
//     let mut tun_unsent_frame_size = 0;
//     let mut tun_buf = [0u8; tun::MAX_SAFE_MTU];
        
//     // let mtu = tun_iff.get_mtu()?;
//     // println!("Interface MTU is: {}", mtu);
    
//     let mut poll = mio::Poll::new()?;
//     let mut events = mio::Events::with_capacity(1000);
    
//     poll.registry().register(&mut mio::unix::SourceFd(&tun_iff.fd), TUN_IFF, 
//         mio::Interest::READABLE.add(mio::Interest::WRITABLE))?;
//     poll.registry().register(&mut udp_sock, PUBLIC_IFF, 
//         mio::Interest::READABLE.add(mio::Interest::WRITABLE))?;
//     poll.registry().register(&mut *cfg.channel.borrow_mut(), CHAN_TOKEN, mio::Interest::READABLE)?;

//     let mut chan_buf = [0u8; 1];
    
//     'event_loop: loop {
//         poll.poll(&mut events, None)?;

//         for event in events.iter() {
//             if event.token() == TUN_IFF {
//                 // TUN read / write handler
//                 loop {
//                     if tun_iff_flags.should_read {
//                         tun_unsent_frame_size = match unistd::read(tun_iff.fd, &mut tun_buf) {
//                             Err(nix::Error::Sys(errno::EWOULDBLOCK)) => break,
//                             any => any,
//                         }?;
//                     }
//                     let tun_dest_ip: net::Ipv4Addr = byteorder::BigEndian::read_u32(&tun_buf[16..20]).into();
//                     let peer_addr = match cfg.tun_to_udp.read().get(&tun_dest_ip) {
//                         Some(addr) => addr.clone(),
//                         _ => match &cfg.gateway {
//                             Some(gateway) => gateway.clone(),
//                             _ => {
//                                 debug!(msg = "unknown peer", ?tun_dest_ip);
//                                 continue
//                             }

//                         }
//                     };
                    
//                     match udp_sock.send_to(&tun_buf[..tun_unsent_frame_size], peer_addr) {
//                         Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
//                             tun_iff_flags.should_read = false;
//                             break
//                         },
//                         Err(error) if error.kind() == io::ErrorKind::Other => {
//                             if let Some(e_num) = io::Error::last_os_error().raw_os_error() {
//                                 if errno::Errno::from_i32(e_num) == errno::Errno::ENETUNREACH {
//                                     tun_iff_flags.should_read = false;
//                                     break
//                                 }
//                             }
//                             Err(error)
//                         },
//                         Err(any) => Err(any),
//                         Ok(_) => {
//                             tun_iff_flags.should_read = true; 
//                             Ok(())
//                         },
//                     }?;
//                 }
//             } 
//             else if event.token() == PUBLIC_IFF {
//                 // UDP read / write handler
//                 loop {
//                     if udp_iff_flags.should_read {
//                         let (nread, addr) = match udp_sock.recv_from(&mut udp_buf) {
//                             Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
//                             any => any,
//                         }?;
//                         udp_unsent_frame_size = nread;

//                         let tun_src_ip: net::Ipv4Addr = byteorder::BigEndian::read_u32(&udp_buf[12..16]).into();

//                         let addr_tb = cfg.tun_to_udp.read();
//                         if !addr_tb.contains_key(&tun_src_ip) {
//                             info!(msg = "unknown peer, adding", ?tun_src_ip);
//                             drop(addr_tb);
//                             cfg.tun_to_udp.write().insert(tun_src_ip, addr);
//                         } else {
//                             let old_addr = addr_tb.get(&tun_src_ip).unwrap().clone();
//                             // peer's IP address changed - unsecure
//                             if old_addr != addr { 
//                                 info!(msg = "updating peer's address", ?old_addr, ?addr, ?tun_src_ip);
//                                 drop(addr_tb);
//                                 cfg.tun_to_udp.write().insert(tun_src_ip, addr);
//                             }
//                         }
//                     }

//                     let tun_dst_ip: net::Ipv4Addr = byteorder::BigEndian::read_u32(&udp_buf[16..20]).into();
//                     match tun_dst_ip == cfg.tun_addr {
//                         true => {
//                             match unistd::write(tun_iff.fd, &udp_buf[..udp_unsent_frame_size]) {
//                                 Err(nix::Error::Sys(errno::EWOULDBLOCK)) => {
//                                     udp_iff_flags.should_read = false;
//                                     break
//                                 },
//                                 Err(any) => Err(any),
//                                 Ok(_) => {
//                                     udp_iff_flags.should_read = true;
//                                     Ok(())
//                                 },
//                             }?;
//                         }
//                         false => {
//                             if let Some(dst_ip) = cfg.tun_to_udp.read().get(&tun_dst_ip) {
//                                 // TODO: MAJOR replication occuring
//                                 match udp_sock.send_to(&udp_buf[..udp_unsent_frame_size], dst_ip.clone()) {
//                                     Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
//                                         tun_iff_flags.should_read = false;
//                                         break
//                                     },
//                                     Err(error) if error.kind() == io::ErrorKind::Other => {
//                                         if let Some(e_num) = io::Error::last_os_error().raw_os_error() {
//                                             if errno::Errno::from_i32(e_num) == errno::Errno::ENETUNREACH {
//                                                 tun_iff_flags.should_read = false;
//                                                 break
//                                             }
//                                         }
//                                         Err(error)
//                                     },
//                                     Err(any) => Err(any) ,
//                                     Ok(_) => {
//                                         tun_iff_flags.should_read = true; 
//                                         Ok(())
//                                     },
//                                 }?;
//                             // TODO: gateway forward
//                             } else { continue }
//                         }
//                     }

//                 }
//             }
//             else if event.token() == CHAN_TOKEN {
//                 loop {
//                     cfg.channel.borrow_mut().recv(&mut chan_buf)?;
//                     let signal = unsafe { mem::transmute::<u8, i8>(chan_buf[0])};
//                     if signal == -1 {
//                         break 'event_loop;
//                     }
//                 }
//             }
//         }
//     }
//     Ok(())
// }

fn udp_handler_factory() -> Box<runtime::SourceEvHandler<ThreadData>>
{ Box::new(|_runtime, thread_data, _event| {
    let mut buf = [0u8; tun::MAX_SAFE_MTU];
    let mut last_frame_size = 0usize;
    let ThreadData { udp_should_read, tun_addr, tun_iff, tun_should_read, udp_socket,
                     tun_to_udp, .. } = thread_data;

    loop {
        if *udp_should_read {
            let (nread, addr) = match udp_socket.recv_from(&mut buf) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                any => any,
            }?;
            last_frame_size = nread;

            let tun_src_ip: net::Ipv4Addr = byteorder::BigEndian::read_u32(&buf[12..16]).into();

            // let addr_tb = tun_to_udp.read();
            if !tun_to_udp.contains_key(&tun_src_ip) {
                info!(msg = "unknown peer, adding", ?tun_src_ip);
                tun_to_udp.insert(tun_src_ip, addr);
            } else {
                let old_addr = tun_to_udp.get(&tun_src_ip).unwrap().clone();
                // peer's IP address changed - unsecure
                if old_addr != addr { 
                    info!(msg = "updating peer's address", ?old_addr, ?addr, ?tun_src_ip);
                    tun_to_udp.insert(tun_src_ip, addr);
                }
            }
        }

        let tun_dst_ip: net::Ipv4Addr = byteorder::BigEndian::read_u32(&buf[16..20]).into();
        match tun_dst_ip == *tun_addr {
            true => {
                match unistd::write(*tun_iff, &buf[..last_frame_size]) {
                    Err(nix::Error::Sys(errno::EWOULDBLOCK)) => {
                        *udp_should_read = false;
                        break
                    },
                    Err(any) => Err(any),
                    Ok(_) => {
                        *udp_should_read = true;
                        Ok(())
                    },
                }?;
            }
            false => {
                if let Some(dst_ip) = tun_to_udp.get(&tun_dst_ip) {
                    // TODO: MAJOR replication occuring
                    match udp_socket.send_to(&buf[..last_frame_size], dst_ip.clone()) {
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            *tun_should_read = false;
                            break
                        },
                        Err(error) if error.kind() == io::ErrorKind::Other => {
                            if let Some(e_num) = io::Error::last_os_error().raw_os_error() {
                                if errno::Errno::from_i32(e_num) == errno::Errno::ENETUNREACH {
                                    *tun_should_read = false;
                                    break
                                }
                            }
                            Err(error)
                        },
                        Err(any) => Err(any) ,
                        Ok(_) => {
                            *tun_should_read = true; 
                            Ok(())
                        },
                    }?;
                // TODO: gateway forward
                } else { continue }
            }
        }
    }
    Ok(())
})}

fn tun_handler_factory() -> Box<runtime::SourceEvHandler<ThreadData>>
{ Box::new(|_runtime, thread_data, _event| {
    let mut buf = [0u8; tun::MAX_SAFE_MTU];
    let mut last_frame_size = 0usize;
    let ThreadData { tun_iff, gateway, tun_should_read, udp_socket, tun_to_udp, .. } = thread_data;

    loop {
        if *tun_should_read {
            last_frame_size = match unistd::read(*tun_iff, &mut buf) {
                Err(nix::Error::Sys(errno::EWOULDBLOCK)) => break,
                any => any,
            }?;
        }
        let tun_dest_ip: net::Ipv4Addr = byteorder::BigEndian::read_u32(&buf[16..20]).into();
        let peer_addr = match tun_to_udp.get(&tun_dest_ip) {
            Some(addr) => addr.clone(),
            _ => match &gateway {
                Some(gateway) => gateway.clone(),
                _ => {
                    debug!(msg = "unknown peer", ?tun_dest_ip);
                    continue
                }

            }
        };
        
        match udp_socket.send_to(&buf[..last_frame_size], peer_addr) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                *tun_should_read = false;
                break
            },
            Err(error) if error.kind() == io::ErrorKind::Other => {
                if let Some(e_num) = io::Error::last_os_error().raw_os_error() {
                    if errno::Errno::from_i32(e_num) == errno::Errno::ENETUNREACH {
                        *tun_should_read = false;
                        break
                    }
                }
                Err(error)
            },
            Err(any) => Err(any),
            Ok(_) => {
                *tun_should_read = true; 
                Ok(())
            },
        }?;
    }
    Ok(())
})}


struct ThreadData {
    tun_iff: unix::io::RawFd,
    tun_addr: net::Ipv4Addr,
    udp_socket: mio::net::UdpSocket,
    gateway: Option<net::SocketAddr>,
    tun_to_udp: collections::HashMap<net::Ipv4Addr, net::SocketAddr>,
    udp_should_read: bool,
    tun_should_read: bool,
}

fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_thread_ids(true).without_time()
        .with_writer(io::stderr).finish();

    tracing::subscriber::set_global_default(subscriber)?;

    let matches = clap::App::new("tun_playground")
        .arg(clap::Arg::with_name("tun").long("tun").value_name("NAME").required(true)
            .help("TUN interface name"))
        .arg(clap::Arg::with_name("mask").long("mask").value_name("MASK").default_value("24")
            .help("Subnet mask of the tunnel interface"))
        .arg(clap::Arg::with_name("virtual").long("virtual").value_name("ADDRESS").required(true)
            .help("IP address on the tunnel interface"))
        // TODO: not required if we can query the port assigned to first UDP socket
        .arg(clap::Arg::with_name("port").long("port").value_name("PORT").required(true))
        .arg(clap::Arg::with_name("gateway").long("gw").value_name("ADDRESS")
            .help("Public address of a peer that acts like a gateway, without a gateway a node can't \
            initiate communication first."))
        .get_matches();

    let tun_name = matches.value_of("tun").unwrap().to_owned();
    let tun_addr = clap::value_t!(matches, "virtual", net::Ipv4Addr)?;
    let tun_mask = clap::value_t!(matches, "mask", u8)?;
    let port = clap::value_t!(matches, "port", u16)?;
    // let tun_to_udp = sync::Arc::new(RwLock::new(collections::HashMap::new()));
    
    let gateway = match matches.value_of("gateway") {
        Some(_) => Some(clap::value_t!(matches, "gateway", net::SocketAddr)?),
        _ => None
    };

    let nthread = num_cpus::get();
    let mut runtime = runtime::Runtime::<ThreadData>::new(nthread)?;
    let mut tun_iffs = SmallVec::<[tun::Tun; 8]>::with_capacity(nthread);
    let mut udp_sockets = SmallVec::<[Option<mio::net::UdpSocket>; 8]>::with_capacity(nthread);

    // TODO: remove name cloning?
    tun_iffs.push(tun::Tun::new(tun_name.clone())?
        .set_non_blocking()?
        .set_mtu(tun::MAX_SAFE_MTU as _)?
        .set_addr(tun_addr)?
        .set_netmask(tun_mask)?
        .set_up()?);

    for _ in 1..nthread {
        tun_iffs.push(tun::Tun::new(tun_name.clone())?
            .set_non_blocking()?);
    }

    for _ in 0..nthread {
        use socket2::{Socket, Domain, Type, Protocol};
        let udp_sock = Socket::new(Domain::ipv6(), Type::dgram().non_blocking(), Some(Protocol::udp()))?;
        udp_sock.set_reuse_address(true)?;
        udp_sock.set_reuse_port(true)?;
        // let mut udp_iff_flags: IoFlags = Default::default();
        // let mut udp_unsent_frame_size = 0;
        // let mut udp_buf = [0u8; tun::MAX_SAFE_MTU];
        udp_sock.bind(&format!{"[::0]:{}", port}.parse::<net::SocketAddr>()?.into())?;
        udp_sockets.push(Some(mio::net::UdpSocket::from_std(udp_sock.into_udp_socket())));
    }

    for i in 0..nthread {
        let mut udp_socket = udp_sockets[i].take().unwrap();
        // TODO: consistent thread_id argument position
        let udp_event_id = runtime.register_event_source(&mut udp_socket, None, i)?;
        let tun_event_id = runtime.register_event_source(&mut mio::unix::SourceFd(&tun_iffs[i].fd), None, i)?;
        runtime.register_source_event_handler(udp_event_id, udp_handler_factory());
        runtime.register_source_event_handler(tun_event_id, tun_handler_factory());

        runtime.set_thread_data(i, ThreadData {
            udp_socket,
            tun_iff: tun_iffs[i].fd,
            tun_addr,
            gateway: gateway.clone(),
            tun_to_udp: collections::HashMap::new(),
            tun_should_read: true,
            udp_should_read: true
        });
    }

    let instance = runtime.start();
    
    use signal_hook::{
        flag, 
        consts::TERM_SIGNALS,
        iterator::{SignalsInfo, exfiltrator::WithOrigin}};
    
    let term_sig = sync::Arc::new(atomic::AtomicBool::new(false));
    let mut sig_handlers = Vec::new();
    for sig in TERM_SIGNALS {
        let handler1 = flag::register_conditional_shutdown(*sig, 1, sync::Arc::clone(&term_sig))?;
        let handler2 = flag::register(*sig, sync::Arc::clone(&term_sig))?;
        sig_handlers.push(handler1);
        sig_handlers.push(handler2);
    }
    
    let mut signals = SignalsInfo::<WithOrigin>::new(TERM_SIGNALS)?;
    for info in &mut signals {
        // eprintln!("Received a signal {:?}", info);
        if TERM_SIGNALS.contains(&info.signal) {
            eprintln!("Terminating");

            let mut chan_buf = [0u8; 1];
            chan_buf[0] = unsafe { mem::transmute::<i8, u8>(-1) };

            instance.send_stop_signal();
            break;
        }
    }

    for handler in sig_handlers.into_iter() {
        signal_hook::low_level::unregister(handler);
    }
    
    instance.block_until_finished()?;
    Ok(())
}