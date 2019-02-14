#!/bin/bash
#
# An example of how to compile ets
#

gcc -Wall -o ets_osx ets.c -l pcap -l ncurses

# for Linux it would be something like this
#gcc -Wall -o ets_linux ets.c -l pcap -l ncurses -lm
