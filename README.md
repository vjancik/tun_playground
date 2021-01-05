## tun_playground
Virtual network over a UDP tunnel PoC demonstration.

### Usage(WIP)

`tun_playground --server --tun tunserver1 --public <placeholder IP>:<port> --virtual 10.0.0.1`

`tun_playground --client --tun tunclient1 --public <server IP>:<port> --virtual 10.0.0.2`

### Performance
Benchmarked using `iperf3`with baseline throughput (directly) of `93Mbit/s` achieved a throughput of `79Mbit/s` on a local `100Mbit/s` rated wired connection.
```
iperf3 -c 10.0.0.1 -t 30 -i 10 -P 8
```

### TODO
- [ ] Multithreading support
- [ ] IP_MULTI_QUEUE support
- [ ] Routing for multiple clients
- [ ] Benchmarking tests & nix / std / socket2 / raw performance comparison
- [ ] Separate readable & writeable Interest handling with a user-space write buffer

### Extensions
- [ ] NAT traversal for P2P connections
- [ ] WireGuard protocol implementation