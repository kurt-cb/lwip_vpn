lwip_vpn
========

This library provides a user mode TCP/IP network that can be used to simulate netowrk traffic or
forward traffic to another network.  The underlying transport can be
 - IP over UDP
 - named sockets
 - serial ports


This project is a library that intersepts POSIX socket calls and creates the ability to add 
any number of fake interfaces that look like real NICs.

Applications
============
This library can be used to bypass normally restricted operations on Unix machines.  These
operations are things like:
- creating a network
- binding to a low port (ports below 1024 are admin only)
- using wireshark to examine traffic
- createing simulation networks for testing large numbers of devices



