## tun_playground
Virtual network over a UDP tunnel PoC demonstration.

### Usage(WIP)

`tun_playground --server --tun tunserver1 --public <placeholder IP>:<port> --virtual 10.0.0.1`

`tun_playground --client --tun tunclient1 --public <server IP>:<port> --virtual 10.0.0.2`

### Performance
Benchmarked using `iperf3` on a local `100Mbit/s` connection with baseline throughput (directly) of `90Mbit/s` achieved:
```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-30.00  sec  45.6 MBytes  12.7 Mbits/sec  149             sender
[  5]   0.00-30.01  sec  45.3 MBytes  12.7 Mbits/sec                  receiver
[  7]   0.00-30.00  sec  44.6 MBytes  12.5 Mbits/sec  138             sender
[  7]   0.00-30.01  sec  44.3 MBytes  12.4 Mbits/sec                  receiver
[  9]   0.00-30.00  sec  43.5 MBytes  12.2 Mbits/sec  145             sender
[  9]   0.00-30.01  sec  43.3 MBytes  12.1 Mbits/sec                  receiver
[ 11]   0.00-30.00  sec  47.1 MBytes  13.2 Mbits/sec  138             sender
[ 11]   0.00-30.01  sec  46.8 MBytes  13.1 Mbits/sec                  receiver
[SUM]   0.00-30.00  sec   181 MBytes  50.5 Mbits/sec  570             sender
[SUM]   0.00-30.01  sec   180 MBytes  50.2 Mbits/sec                  receiver
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