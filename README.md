# ETS
EtherType Statistics

I wanted to see the ratio between IPv4 and IPv6 on my computers and decided to write a litle ncurses
based tool that does this, because '[IPtraf](https://en.wikipedia.org/wiki/IPTraf)' was a bit 
overkill and besides that, I couldn't find one for my Mac.

Just compile it (or run one of the supplied binaries) and keep it running for a while in a terminal. You'll be surprised ;-)

## build
Just do
```
gcc -Wall -o ets_osx ets.c -l pcap -l ncurses
```
(see makeit_imac2.sh), or add -lm for Linux.

Linux tip: you may need this first:
```
sudo apt install libncurses5-dev libpcap-dev
```
(and obviously gcc has to be present, the 'build-essential'-package will provide you with that)

## run
Just do
```
sudo tcpdump -i en0 -p --immediate-mode -U -s14 -w - 2> /dev/null | ./ets_osx -
```
(see doit_imac2.sh) or the equivalent for your build and OS (in particular mind the interface you use in tcpdump).

## screenshot
![Alt text](/screenshot1.png?raw=true "Screenshot")

## misc
You may also like:
* tshark -z hosts,ipv4,ipv6
