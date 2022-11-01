1. Makefile
```
$ make          /* compile */
$ make clean    /* remove object files */
```

2. Annotaion
If the kernel send RST packet when it received a packet from peer, please execute the bellow command.
```
$ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```