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

fn handle_udp_send_result(result: io::Result<usize>) -> (io::Result<()>, bool) {
    let mut send_successful = true;
    let result = match result {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            send_successful = false;
            Ok(())
        },
        Err(error) if error.kind() == io::ErrorKind::Other => {
            match io::Error::last_os_error().raw_os_error() {
                Some(e_num) if errno::Errno::from_i32(e_num) == errno::Errno::ENETUNREACH => {
                    send_successful = false;
                    Ok(())
                }
                Some(_) | None => Err(error)
            }
        },
        Err(any) => {
            send_successful = false;
            Err(any)
        },
        Ok(_) => Ok(()),
    };
    (result, send_successful)
}

fn udp_handler_factory() -> Box<runtime::SourceEvHandler<ThreadData>>
{ Box::new(|_runtime, thread_data, _event| {
    let mut buf = [0u8; tun::MAX_SAFE_MTU];
    let mut last_frame_size = 0usize;
    let ThreadData { udp_should_read, tun_addr, tun_iff, tun_should_read, udp_socket,
                     tun_to_udp, gateway } = thread_data;

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
                // TODO: may fail to send but proceed to read again and rewrite it's own buffer
                //       need a "wait for write readiness" control flag
                if let Some(dst_ip) = tun_to_udp.get(&tun_dst_ip) {
                    let send_result = udp_socket.send_to(&buf[..last_frame_size], dst_ip.clone());
                    let (send_result, send_successful) = handle_udp_send_result(send_result);
                    *tun_should_read = send_successful;
                    send_result?;

                } else if let Some(gateway) = &gateway { 
                    let send_result = udp_socket.send_to(&buf[..last_frame_size], gateway.clone());
                    let (send_result, send_successful) = handle_udp_send_result(send_result);
                    *tun_should_read = send_successful;
                    send_result?;
                 }
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
        
        let send_result = udp_socket.send_to(&buf[..last_frame_size], peer_addr);
        let (send_result, send_successful) = handle_udp_send_result(send_result);
        *tun_should_read = send_successful;
        send_result?;
        if !*tun_should_read { break }
    }
    Ok(())
})}

// Action flow:
//      1. at startup, discover mapped address through stun
//      2. send data to a an unknown tun IP 
//      3. data flows through gateway, at the same time, ask the sync server to

enum UDPMsgType {
    Keepalive,
    Stun,
    TunData,
}

struct UDPProtocolFrame {
    msg_t: UDPMsgType,
}

enum SyncMsgType {
    RequestDirect, // transaction_id
    RequestAccepted, // with transaction_id
    RequestDenied, // transaction_id, and failure explanation, either enum or msg TLV 
    // Acknowledge, // probably redundant on TCP keepalive connections
}

struct SyncProtocolFrame {
    msg_t: SyncMsgType
}

// discovery from sync server
struct Peer {
    tun_addr: net::Ipv4Addr,
    pub_addr: net::SocketAddr,
    direct: bool, // false means you should send the packets to the gateway or drop
}

struct SharedData {
    mapped_ip: Option<net::SocketAddr>,
    /// cache timeout for mapped_ip, to be refreshed
    mapped_freshness: std::time::Instant, // or SystemTime?
    peer_table: SmallVec<[Peer; 5]>,
}

trait SyncClient {
    fn request_direct_connection();
}


struct ThreadData {
    tun_iff: unix::io::RawFd,
    tun_addr: net::Ipv4Addr,
    udp_socket: mio::net::UdpSocket,
    gateway: Option<net::SocketAddr>,
    // sync_server: Option<net::SocketAddr>,
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