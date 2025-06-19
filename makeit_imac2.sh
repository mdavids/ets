#!/bin/bash
#
# An example of how to compile ets
#

# gcc or cc...

export LDFLAGS="-L/opt/homebrew/opt/libpcap/lib"
export CPPFLAGS="-I/opt/homebrew/opt/libpcap/include"

cc -Wall -o ets_osx ets.c $CPPFLAGS $LDFLAGS -l pcap -l ncurses -l m

# for Linux it would be something like this
#cc -Wall -o ets_linux ets.c -l pcap -l ncurses -l m
