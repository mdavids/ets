#!/bin/bash
#
# An example of how you could run ets
# (please note: stderr redirect like this wont work on csh)

#clear

# Is your interface indeed en0 or eth0?
sudo tcpdump -i en0 -p --immediate-mode -U -s14 -w - 2>/dev/null | ./ets_osx -
#sudo tcpdump -i eth0 -p --immediate-mode -U -s14 -w -  2>/dev/null | ./ets_linux -

#
# Or do stuff like when testing:
# sudo tcpdump -i en0 -p --immediate-mode -U -s14 -w - -f '(ip or ip6) and host example.nl' 2>/dev/null | ./ets_osx -
#
 