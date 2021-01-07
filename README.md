## tun_playground
Virtual network over a UDP tunnel PoC demonstration.

### Usage(WIP)
**Server**

`tun_playground --tun tunserver1 --virtual 10.0.0.1 --port 55555`

**Client** (`--gw` public IP for routing packets to unknown peers in the virtual subnet)

`tun_playground --tun tunclient1 --virtual 10.0.0.2 --port 55555 --gw <IP:port>`

### Performance
Benchmarked using `iperf`with baseline throughput (directly) of `93Mbit/s` achieved a throughput of `82Mbit/s` on a local `100Mbit/s` rated wired connection.
```
iperf -c 10.0.0.1 -t 30 -i 10 -P 8
```

### TODO
- [x] Multithreading support
- [x] IP_MULTI_QUEUE support
- [x] Routing for multiple clients
- [ ] Benchmarking tests & nix / std / socket2 / raw performance comparison
- [x] Separate readable & writeable Interest handling with a user-space write buffer
- [ ] Implement keepalive option for NAT tunneling
- [ ] Daemonize

### Extensions
- [ ] NAT traversal for P2P connections
- [ ] WireGuard protocol implementation

#### Notes
`iperf3` has a buggy TCP handshake code, reverted to `iperf` (version 2)
