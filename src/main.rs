// https://www.kernel.org/doc/Documentation/networking/tuntap.txt
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h

use std::{io, net, thread, mem, sync::{self, atomic}, os::unix};
use nix::{unistd, errno};
use anyhow::{Result};
use mio;
use socket2;
use clap::{self, value_t};
use num_cpus;
use signal_hook;

mod tun;
// mod cyclic;

// naive ICMP request reply
// fn icmp_handler(src: &mut [u8]) {
//     // swap source destination
//     unsafe { ptr::swap_nonoverlapping(&mut src[12], &mut src[16], 4); }

//     // change request to reply
//     src[20] = 0;
// }

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


fn initialize_tunnel(tun_name: String, tun_addr: net::Ipv4Addr, tun_mask: u8, is_server: bool, 
                     server_addr: net::SocketAddr, mut channel: mio::net::UnixDatagram) -> Result<()> 
{
    let tun_iff = tun::Tun::new(tun_name)?
        .set_non_blocking()?
        .set_mtu(tun::MAX_SAFE_MTU as _)?
        .set_addr(tun_addr)?
        .set_netmask(tun_mask)?
        .set_up()?;
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
    if is_server {
        let port = server_addr.port();
        udp_sock.bind(&format!{"[::0]:{}", port}.parse::<net::SocketAddr>()?.into())?;
    } else {
        udp_sock.bind(&"[::0]:0".parse::<net::SocketAddr>()?.into())?;
    }
    let mut udp_sock = mio::net::UdpSocket::from_std(udp_sock.into_udp_socket());
    
    let mut poll = mio::Poll::new()?;
    let mut events = mio::Events::with_capacity(1000);
    
    poll.registry().register(&mut mio::unix::SourceFd(&tun_iff.fd), TUN_IFF, 
        mio::Interest::READABLE.add(mio::Interest::WRITABLE))?;
    poll.registry().register(&mut udp_sock, PUBLIC_IFF, 
        mio::Interest::READABLE.add(mio::Interest::WRITABLE))?;
    poll.registry().register(&mut channel, CHAN_TOKEN, mio::Interest::READABLE)?;

    let mut client_addr: net::SocketAddr = "0.0.0.0:0".parse()?; // filled on first packet

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

                    // println!("Writing {} bytes from TUN to UDP socket", nread);
                    // TODO: Address table for multiple clients
                    let peer_addr = match is_server {
                        true => client_addr,
                        false => server_addr
                    };
            
                    match udp_sock.send_to(&tun_buf[..tun_unsent_frame_size], peer_addr) {
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            tun_iff_flags.should_read = false;
                            break
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

                        if is_server {
                            client_addr = addr;
                        }
                    }

                    // println!("Writing {} bytes from UDP socket to TUN", nread);
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
            }
            else if event.token() == CHAN_TOKEN {
                loop {
                    channel.recv(&mut chan_buf)?;
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
    let matches = clap::App::new("tun_playground")
        .settings(&[clap::AppSettings::SubcommandRequired, clap::AppSettings::InferSubcommands])
        .subcommand(clap::SubCommand::with_name("server")
            .arg(clap::Arg::with_name("port").long("port").value_name("PORT").required(true))
        )
        .subcommand(clap::SubCommand::with_name("client")
            .arg(clap::Arg::with_name("server").long("server").value_name("SERVER").required(true)
                .help("public IP:port server address"))
        )
        .arg(clap::Arg::with_name("tun").long("tun").value_name("NAME").required(true)
            .help("TUN interface name"))
        .arg(clap::Arg::with_name("mask").long("mask").value_name("MASK").default_value("24")
            .help("Subnet mask of the tunnel interface"))
        .arg(clap::Arg::with_name("virtual").long("virtual").value_name("ADDRESS").required(true)
            .help("IP address on the tunnel interface"))
        .get_matches();

    let tun_name = matches.value_of("tun").unwrap();
    let tun_addr = clap::value_t!(matches, "virtual", net::Ipv4Addr)?;
    let tun_mask = clap::value_t!(matches, "mask", u8)?;

    let (is_server, server_addr) = match matches.subcommand() {
        ("server", Some(subc_m)) => {
            let port = clap::value_t!(subc_m, "port", u16)?;
            let server_addr = format!("0.0.0.0:{}", port).parse()?;
            (true, server_addr)
        },
        ("client", Some(subc_m)) => {
            let server_addr = clap::value_t!(subc_m, "server", net::SocketAddr)?;
            (false, server_addr)
        },
        (_, _) => Err(anyhow::anyhow!("Failed to correctly parse arguments"))?
    };
    
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



    for _ in 0..ncpus {
        let tun_name = tun_name.to_owned();

        let (sender, receiver) = unix::net::UnixDatagram::pair()?;
        sender.set_nonblocking(true)?;
        receiver.set_nonblocking(true)?;

        let receiver = mio::net::UnixDatagram::from_std(receiver);
        thread_channels.push(sender);

        threads.push(Some(thread::spawn(move || -> Result<()> {
            let result = initialize_tunnel(tun_name, tun_addr, tun_mask, is_server, server_addr, receiver);
            if result.is_err() {
                eprintln!("Thread exited with an error");
            }
            result
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
        if let Err(err) = threads[i].take().unwrap().join().unwrap() {
            eprintln!("Thread {}: {:?}", i, err);
        }
    }

    Ok(())
}