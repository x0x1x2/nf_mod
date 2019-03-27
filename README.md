# nf_mod
Netfilter kernel module 
General:
This kernel module will block outgoing http request:
1) nf_mod.c : filter only TCP packets with payload.
2) http_parser.c : parse the TCP packet payload for http request line (assuming version 1.1)


Links
https://medium.com/@GoldenOak/linux-kernel-communication-part-1-netfilter-hooks-15c07a5a5c4e
https://jnc0x24dd099bb870.github.io/Network/TCP4/Sock3/index.html
https://www.netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO-3.html
http://vger.kernel.org/~davem/skb.html
http://vger.kernel.org/~davem/skb_data.html
https://github.com/rops/netfilter-stringscleaner/blob/master/xt_POLIMI.c
https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html


