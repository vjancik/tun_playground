## tun_playground
Virtual network over a UDP tunnel PoC demonstration.

### Usage(WIP)
`tun_playground --tun tunserver1 --virtual 10.0.0.1 server --port 55555`
`tun_playground --tun tunclient1 --virtual 10.0.0.2 client --server <IP:port>`

### Performance
Benchmarked using `iperf3`with baseline throughput (directly) of `93Mbit/s` achieved a throughput of `80Mbit/s` on a local `100Mbit/s` rated wired connection.
```
iperf3 -c 10.0.0.1 -t 30 -i 10 -P 8
```

### TODO
- [x] Multithreading support
- [x] IP_MULTI_QUEUE support
- [ ] Routing for multiple clients
- [ ] Benchmarking tests & nix / std / socket2 / raw performance comparison
- [x] Separate readable & writeable Interest handling with a user-space write buffer

### Extensions
- [ ] NAT traversal for P2P connections
- [ ] WireGuard protocol implementation