#!/bin/bash
#
# An example of how to compile ets
#

# gcc or cc...

cc -Wall -o ets_osx ets.c -l pcap -l ncurses -l m

# for Linux it would be something like this
#cc -Wall -o ets_linux ets.c -l pcap -l ncurses -l m
