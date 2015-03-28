What is NDWatch for?
====================

In geekspeak: The Neighborhood Discovery Watch daemon maps global scope temporary IPv6 addresses to 
names in local DNS databases, so that in tools like iftop, nmap, netstat, etc...
hostnames are shown even when machines instead of a sea of temporary addresses. The daemon
logs its actions to syslog, so that records can be maintained for long term maintenance.

# Why is this a problem?

In IPv4 networks where stricter management is wanted, addresses are given out by the Dynamic Host 
Configuration Protocol (DHCP.) In IPv6, Stateless Address AutoConfiguration (SLAAC) was originally 
supposed to replace DHCP, but it turns out that SLAAC did not really do the same thing, so people 
wanted DHCP back, and they started work on DHCP for IPv6 (DHCPv6.) DHCPv6 initially had a number 
of gaps, and the implementations have been evolving to fix them.  The result is that DHCPv6 does 
not work reliably with a wide variety of end point devices today.  SLAAC is what "just works." 
With SLAAC, the network guesses addresses, whereas DHCP, in managed networks, they can be assigned.

When using SLAAC, there are "privacy extensions" that change the addresses
used by hosts every few hours to prevent tracking of equipment globally.  For
local network security and management however, it is very practical to 
know which end points are using which addresses, at a given time.

While it is great to have the addresses mapped to human readable names, it is cumbersome
to map them to the ordinary, permanent addresses, as this can cause problems when 
temporary addresses expire.  So a suffix is used to identify them: "anon" by default.   


# How it works:
This daemon reads the router advertisements to determine what
network it is attached to, then it watches neighborhood discovery
protocol messages used by end points to claim addresses, and registers
the names claimed into forward and reverse DNS records for the 
domain and subnet.

# Security Considerations:
While there is nothing to force it, it is assumed that DNS is split-horizon 
and that the zones updated are only internally visible, as sharing the temporary addresses
publically may allow others to track end-point device use on your network.

Since neighborhood discovery is the same protocol used to be able to communicate 
over IPv6 at all, the daemon should work in any network with any combination of 
end points, and should be difficult to avoid or subvert.

If an unknown end-point connects to the network, the daemon will create DNS entries for
it, so that folks can do further auditing work to identify it.

# Future work:
 - clean up of records is not fully thought out yet. things get cleaned out by si46ib9d whenever 
   static changes made.  have dns_clean which only removes reverse addresses.  need to add fwd
   as well.
 - not trying to find those trying to use other devices' IP's yet. (ie. mac/host mismatch.)
 - should link level addresses be registered?
 - worry about mac spoofing?  same as nbd or arp today... don't see why.  if they use a different
   MAC they will be given an UNKNOWN, but remaint identifiable by MAC, would have to rotate MACs.
 - should we identify static addresses, and register those without the suffix? avoid need
   to create any host entries in IPv6, just create them on the fly as MACs show up.  

# Dependencies:

on ubuntu 12.04 or Debian 7.1:

python < 3 

apt-get install python-pcapy python-dpkt python-dnspython

mkdir /etc/ndwatch/
cp ndwatch.conf.sample /etc/ndwatch/ndwatch.conf

You need to have a working IPv6 network, which usually means
that SLAAC (Stateless Address Auto Configuration) is used to
assign addresses.  In an IPv6 network without DHCPv6, a 
router needs to be sending advertisements out.  

You also need a fully configured DNS for dynamic updates, including the IPv6
reverse zone that will be updated.  For a small network starting from scratch, 
si46ib9d ( https://github.com/petersilva/si46ib9d ) is what I use 
(sets up ipv4 and ipv6 bind9 dns, as well as dhcp server for ipv4,
and the configuration file for ndwatch from a single configuration file.)
still a little unix filtering on a dhcp configuration file should give you mac 
to host name mappings.


Edit /etc/ndwatch/ndwatch.conf

```
domain <set your domain.>
# <setup for dynamic updates to your DNS.>
dnsmaster <the master dns server host.>
dnskey  
	-- obtain user name and key 

for each host on the net
host <name preferrd in DNS> mac-address
```

put that in this file.

If you assign IPv4 addresses to machines via dhcp, then bring
that information over into host declarations.

python ndwatch.py >watch.out 2>&amp;1 &amp;

Start up the daemon, and it should create reverse records for 
known MACs that point to the same server.   there is also a sample init script and crontab entry included.

# Caveats:
 - added records, but cleanup of old ones is incomplete. not a problem if used in conjunction with si46ib9d
   which re-writes the entire db every time there is a change to permanent addresses.
