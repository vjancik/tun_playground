// https://www.kernel.org/doc/Documentation/networking/tuntap.txt
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h

use std::{io, cell, net, thread, mem, fmt, process, time,
    sync::{self, atomic}, os::unix, collections};
use nix::{unistd, errno};
use anyhow::{Result};
use mio;
use socket2;
use clap::{self, value_t};
use num_cpus;
use signal_hook;
use tracing::{debug, error, info};
use tracing_subscriber::FmtSubscriber;
use byteorder::{ByteOrder};
use parking_lot::RwLock;

mod tun;

const TUN_IFF: mio::Token = mio::Token(0);
const PUBLIC_IFF: mio::Token = mio::Token(1);
const CHAN_TOKEN: mio::Token = mio::Token(2);

struct IoFlags {
    should_read: bool,
    // should_write: bool
}

impl Default for IoFlags {
    fn default() -> Self {
        IoFlags { should_read: true, /* should_write: true */ }
    }
}

struct TunnelConfig {
    tun_name: String,
    tun_addr: net::Ipv4Addr,
    tun_iff: Option<tun::Tun>,
    tun_mask: u8,
    port: u16,
    thread_id: u8,
    gateway: Option<net::SocketAddr>,
    tun_to_udp: sync::Arc<RwLock<collections::HashMap<net::Ipv4Addr, net::SocketAddr>>>,
    channel: cell::RefCell<mio::net::UnixDatagram>,
}

impl fmt::Debug for TunnelConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelConfig")
         .field("tun_name", &self.tun_name)
         .field("tun_addr", &self.tun_addr)
         .field("tun_iff", &self.tun_iff)
         .field("tun_mask", &self.tun_mask)
         .field("port", &self.port)
         .field("thread_id", &self.thread_id)
         .field("gateway", &self.gateway)
         // TODO: doesn't print properly?
         .field("peer_table", &*self.tun_to_udp.read())
         .field("channel", &"UnixDatagram channel")
         .finish()
    }
}

fn initialize_tunnel(cfg: TunnelConfig) -> Result<()> 
{
    let tun_iff = match cfg.thread_id {
        0 => cfg.tun_iff.unwrap(),
        _ => {
            tun::Tun::new(cfg.tun_name)?
                .set_non_blocking()?
        }
    };
    let mut tun_iff_flags: IoFlags = Default::default();
    let mut tun_unsent_frame_size = 0;
    let mut tun_buf = [0u8; tun::MAX_SAFE_MTU];
        
    // let mtu = tun_iff.get_mtu()?;
    // println!("Interface MTU is: {}", mtu);
    
    use socket2::{Socket, Domain, Type, Protocol};
    let udp_sock = Socket::new(Domain::ipv6(), Type::dgram().non_blocking(), Some(Protocol::udp()))?;
    udp_sock.set_reuse_address(true)?;
    udp_sock.set_reuse_port(true)?;
    let mut udp_iff_flags: IoFlags = Default::default();
    let mut udp_unsent_frame_size = 0;
    let mut udp_buf = [0u8; tun::MAX_SAFE_MTU];
    udp_sock.bind(&format!{"[::0]:{}", cfg.port}.parse::<net::SocketAddr>()?.into())?;
    let mut udp_sock = mio::net::UdpSocket::from_std(udp_sock.into_udp_socket());
    
    let mut poll = mio::Poll::new()?;
    let mut events = mio::Events::with_capacity(1000);
    
    poll.registry().register(&mut mio::unix::SourceFd(&tun_iff.fd), TUN_IFF, 
        mio::Interest::READABLE.add(mio::Interest::WRITABLE))?;
    poll.registry().register(&mut udp_sock, PUBLIC_IFF, 
        mio::Interest::READABLE.add(mio::Interest::WRITABLE))?;
    poll.registry().register(&mut *cfg.channel.borrow_mut(), CHAN_TOKEN, mio::Interest::READABLE)?;

    let mut chan_buf = [0u8; 1];
    
    'event_loop: loop {
        poll.poll(&mut events, None)?;

        for event in events.iter() {
            if event.token() == TUN_IFF {
                // TUN read / write handler
                loop {
                    if tun_iff_flags.should_read {
                        tun_unsent_frame_size = match unistd::read(tun_iff.fd, &mut tun_buf) {
                            Err(nix::Error::Sys(errno::EWOULDBLOCK)) => break,
                            any => any,
                        }?;
                    }
                    let tun_dest_ip: net::Ipv4Addr = byteorder::BigEndian::read_u32(&tun_buf[16..20]).into();
                    let peer_addr = match cfg.tun_to_udp.read().get(&tun_dest_ip) {
                        Some(addr) => addr.clone(),
                        _ => match &cfg.gateway {
                            Some(gateway) => gateway.clone(),
                            _ => {
                                debug!(msg = "unknown peer", ?tun_dest_ip);
                                continue
                            }

                        }
                    };
                    
                    match udp_sock.send_to(&tun_buf[..tun_unsent_frame_size], peer_addr) {
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            tun_iff_flags.should_read = false;
                            break
                        },
                        Err(error) if error.kind() == io::ErrorKind::Other => {
                            if let Some(e_num) = io::Error::last_os_error().raw_os_error() {
                                if errno::Errno::from_i32(e_num) == errno::Errno::ENETUNREACH {
                                    tun_iff_flags.should_read = false;
                                    break
                                }
                            }
                            Err(error)
                        },
                        Err(any) => Err(any),
                        Ok(_) => {
                            tun_iff_flags.should_read = true; 
                            Ok(())
                        },
                    }?;
                }
            } 
            else if event.token() == PUBLIC_IFF {
                // UDP read / write handler
                loop {
                    if udp_iff_flags.should_read {
                        let (nread, addr) = match udp_sock.recv_from(&mut udp_buf) {
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            any => any,
                        }?;
                        udp_unsent_frame_size = nread;

                        let tun_src_ip: net::Ipv4Addr = byteorder::BigEndian::read_u32(&udp_buf[12..16]).into();

                        let addr_tb = cfg.tun_to_udp.read();
                        if !addr_tb.contains_key(&tun_src_ip) {
                            info!(msg = "unknown peer, adding", ?tun_src_ip);
                            drop(addr_tb);
                            cfg.tun_to_udp.write().insert(tun_src_ip, addr);
                        } else {
                            let old_addr = addr_tb.get(&tun_src_ip).unwrap().clone();
                            // peer's IP address changed - unsecure
                            if old_addr != addr { 
                                info!(msg = "updating peer's address", ?old_addr, ?addr, ?tun_src_ip);
                                drop(addr_tb);
                                cfg.tun_to_udp.write().insert(tun_src_ip, addr);
                            }
                        }
                    }

                    let tun_dst_ip: net::Ipv4Addr = byteorder::BigEndian::read_u32(&udp_buf[16..20]).into();
                    match tun_dst_ip == cfg.tun_addr {
                        true => {
                            match unistd::write(tun_iff.fd, &udp_buf[..udp_unsent_frame_size]) {
                                Err(nix::Error::Sys(errno::EWOULDBLOCK)) => {
                                    udp_iff_flags.should_read = false;
                                    break
                                },
                                Err(any) => Err(any),
                                Ok(_) => {
                                    udp_iff_flags.should_read = true;
                                    Ok(())
                                },
                            }?;
                        }
                        false => {
                            if let Some(dst_ip) = cfg.tun_to_udp.read().get(&tun_dst_ip) {
                                // TODO: MAJOR replication occuring
                                match udp_sock.send_to(&udp_buf[..udp_unsent_frame_size], dst_ip.clone()) {
                                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                        tun_iff_flags.should_read = false;
                                        break
                                    },
                                    Err(error) if error.kind() == io::ErrorKind::Other => {
                                        if let Some(e_num) = io::Error::last_os_error().raw_os_error() {
                                            if errno::Errno::from_i32(e_num) == errno::Errno::ENETUNREACH {
                                                tun_iff_flags.should_read = false;
                                                break
                                            }
                                        }
                                        Err(error)
                                    },
                                    Err(any) => Err(any) ,
                                    Ok(_) => {
                                        tun_iff_flags.should_read = true; 
                                        Ok(())
                                    },
                                }?;
                            // TODO: gateway forward
                            } else { continue }
                        }
                    }

                }
            }
            else if event.token() == CHAN_TOKEN {
                loop {
                    cfg.channel.borrow_mut().recv(&mut chan_buf)?;
                    let signal = unsafe { mem::transmute::<u8, i8>(chan_buf[0])};
                    if signal == -1 {
                        break 'event_loop;
                    }
                }
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_thread_ids(true).without_time()
        .with_writer(io::stderr).finish();

    tracing::subscriber::set_global_default(subscriber)?;

    let matches = clap::App::new("tun_playground")
        // .settings(&[clap::AppSettings::SubcommandRequired, clap::AppSettings::InferSubcommands])
        // .subcommand(clap::SubCommand::with_name("server"))
        // .subcommand(clap::SubCommand::with_name("client")
        //     .arg(clap::Arg::with_name("server_public").long("serv_pub").value_name("PUBLIC").required(true)
        //         .help("public IP:port server UDP socket"))
        //     .arg(clap::Arg::with_name("server_virtual").long("serv_virt").value_name("VIRTUAL").required(true))
        // )
        .arg(clap::Arg::with_name("tun").long("tun").value_name("NAME").required(true)
            .help("TUN interface name"))
        .arg(clap::Arg::with_name("mask").long("mask").value_name("MASK").default_value("24")
            .help("Subnet mask of the tunnel interface"))
        .arg(clap::Arg::with_name("virtual").long("virtual").value_name("ADDRESS").required(true)
            .help("IP address on the tunnel interface"))
        .arg(clap::Arg::with_name("port").long("port").value_name("PORT").required(true))
        .arg(clap::Arg::with_name("gateway").long("gw").value_name("ADDRESS")
            .help("Public address of a peer that acts like a gateway, without a gateway a node can't \
            initiate communication first."))
        .get_matches();

    let tun_name = matches.value_of("tun").unwrap().to_owned();
    let tun_addr = clap::value_t!(matches, "virtual", net::Ipv4Addr)?;
    let tun_mask = clap::value_t!(matches, "mask", u8)?;
    let tun_to_udp = sync::Arc::new(RwLock::new(collections::HashMap::new()));
    let port = clap::value_t!(matches, "port", u16)?;

    let gateway = match matches.value_of("gateway") {
        Some(_) => Some(clap::value_t!(matches, "gateway", net::SocketAddr)?),
        _ => None
    };

    // if let Some(subc_m) = matches.subcommand_matches("client") {
    //     let server_public = clap::value_t!(subc_m, "server_public", net::SocketAddr)?;
    //     let server_virtual = clap::value_t!(subc_m, "server_virtual", net::Ipv4Addr)?;
    //     tun_to_udp.write().insert(server_virtual, server_public);
    // }

    let mut tun_iff = Some(tun::Tun::new(tun_name.clone())?
        .set_non_blocking()?
        .set_mtu(tun::MAX_SAFE_MTU as _)?
        .set_addr(tun_addr)?
        .set_netmask(tun_mask)?
        .set_up()?);
    
    use signal_hook::{
        flag, 
        consts::TERM_SIGNALS,
        iterator::{SignalsInfo, exfiltrator::WithOrigin}};
    
    // valgrind reports memory leak
    let term_sig = sync::Arc::new(atomic::AtomicBool::new(false));
    for sig in TERM_SIGNALS {
        flag::register_conditional_shutdown(*sig, 1, sync::Arc::clone(&term_sig))?;
        flag::register(*sig, sync::Arc::clone(&term_sig))?;
    }
    
    let mut signals = SignalsInfo::<WithOrigin>::new(TERM_SIGNALS)?;

    let ncpus = num_cpus::get();
    let mut threads = Vec::<Option<thread::JoinHandle<Result<()>>>>::with_capacity(ncpus);
    let mut thread_channels = Vec::<unix::net::UnixDatagram>::with_capacity(ncpus);


    for thread_id in 0..ncpus as u8 {
        let tun_name = tun_name.clone();

        let (sender, receiver) = unix::net::UnixDatagram::pair()?;
        sender.set_nonblocking(true)?;
        receiver.set_nonblocking(true)?;

        let receiver = mio::net::UnixDatagram::from_std(receiver);
        thread_channels.push(sender);

        let cfg = TunnelConfig { thread_id, tun_name, tun_addr, tun_mask, port, gateway,
            tun_iff: tun_iff.take(),
            tun_to_udp: tun_to_udp.clone(),
            channel: cell::RefCell::new(receiver) };

        threads.push(Some(thread::spawn(move || -> Result<()> {
            match initialize_tunnel(cfg) {
                Err(err) => {
                    error!(msg = "Thread exited with error", ?err);
                    // give other threads a chance to fail as well
                    thread::sleep(time::Duration::from_secs(1));
                    // unrecoverable failure
                    process::exit(1); }
                Ok(_) => Ok(())
            }
        })));
    }

    for info in &mut signals {
        // eprintln!("Received a signal {:?}", info);
        if TERM_SIGNALS.contains(&info.signal) {
            eprintln!("Terminating");

            let mut chan_buf = [0u8; 1];
            chan_buf[0] = unsafe { mem::transmute::<i8, u8>(-1) };

            for i in 0..ncpus {
                // best effort send
                thread_channels[i].send(&chan_buf).ok();
            }
            break;
        }
    }

    for i in 0..ncpus {
        threads[i].take().unwrap().join().unwrap()?;
    }

    Ok(())
}