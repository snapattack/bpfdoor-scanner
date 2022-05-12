# BPFDoor Scanner - Check for Compromised Hosts

The BPFDoor malware, as discussed on [Kevin Beaumont's blog](https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896) and on [Twitter](https://twitter.com/GossiTheDog/status/1522964028284411907), is a sophisticatedly simple backdoor being attributed to a Chinese threat actor Red Menshen. The backdoor makes use of Berkley Packet Filters (BPF), hence the name.  This allows the malware to listen on all active ports on an infected host, and if the correct "magic packet" and password are sent, it will respond with a privileged shell. You can learn more about BPFDoor from [our blog](https://blog.snapattack.com) and [threat snapshots](https://youtu.be/BThiTaa7t4w).

## Installation and Usage

The BPFdoor scanner is a Python 3 script that you can download and use to scan your networks.  It has no additional requirements.  It is fast enough to scan targeted IP ranges, but intentionally slow enough not to be able to scan the whole Internet.

By default, it will scan the nmap "top 20" ports. Scanning every port is ill advised and not necessary, since the backdoor will listen on any open port on an infected machine.

```
usage: bpfdoor_scanner.py targets [options]

positional arguments:
  targets               IP address or range in CIDR notation to scan (e.g., 192.168.1.100 or 10.0.0.0/24)

optional arguments:
  -h, --help            show this help message and exit
  --target-ports TARGET_PORTS, -p TARGET_PORTS
                        Comma separated list of ports to scan. Ranges are OK. (e.g, 22,80,443 or 1-1000)
  --ip IP, -i IP        Your IP address
  --listen-port LISTEN_PORT, -l LISTEN_PORT
                        Port to listen on from your IP address
  --verbose, -v         Verbose mode - prints the current hosts and ports being scanned


Examples:

// This will scan the "top 20" ports for a single host, 10.0.75.88, 
// and return responses back to 10.101.72.100 on UDP port 8000
python3 bpfdoor_scanner 10.0.75.88 -1 10.101.72.100 -p 8000

// This will scan SSH/HTTP/HTTPS ports for a single host, 10.0.75.88, 
// and return responses back to 10.101.72.100 on UDP port 8000
python3 bpfdoor_scanner 10.0.75.88 -p 22,80,443 -1 10.101.72.100 -p 8000

// This will scan the first 1000 ports for entire 10.0.0.0/8 subnet
// and return responses back to 10.101.72.100 on UDP port 1337
python3 bpfdoor_scanner 10.0.0.0/8 -p 1-1000 -1 10.101.72.100 -p 1337

```

## How this scanner works

BPFdoor has a sort of "monitor mode" where in the main loop, if a magic packet is found and it does not contain a valid password (case 1 or case 0 below), it will send back a heartbeat UDP packet to the IP address and port specified with the payload `1`.  This can be used to scan for and identify compromised machines.  We implement this for TCP - if you wanted to scan with UDP or ICMP we'll leave that as an exercise to the reader.

Snippets below are from the source code originally found on [pastebin](https://pastebin.com/kmmJuuQP) and also available in the [sample folder](sample/bpfdoor.c).

```
    // void packet_loop()
    
    cmp = logon(mp->pass);
    switch(cmp) {
            case 1:
                    strcpy(sip, inet_ntoa(ip->ip_src));
                    getshell(sip, ntohs(tcp->th_dport));
                    break;
            case 0:
                    scli = try_link(bip, mp->port);
                    if (scli > 0)
                            shell(scli, NULL, NULL);
                    break;
            case 2:
                    mon(bip, mp->port);
                    break;
    }
```

```
    // int mon(in_addr_t ip, unsigned short port)

    if ((s_len = sendto(sock, "1", 1, 0, (struct sockaddr *)&remote, sizeof(struct sockaddr))) < 0) {
            close(sock);
            return -1;
    }
```

## Disclaimer and License

This software is licensed under the MIT License.

This software is provided as-is.  We make no representations that it will detect any or all compromised hosts, particularly if the magic numbers or payloads have changed.  This tool is provided for educational purposes and may be used to scan networks that you own.  We are not responsible for repercussions from misuse of this tool.
