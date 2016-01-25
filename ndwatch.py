#!/usr/bin/env python
# coding: utf-8
"""
  neighborhood watch

Listen for IPv6 neighbor discovery protocol for router and neigbour advertisements.
Read a configuration file ( /etc/ndwatch/ndwatch.conf ) for a list of relationships between
MAC addresses and host names.

When a given MAC advertises an address, create a reverse lookup (PTR) record 
corresponding to the ad.  If the address is a permanenet global one,
then create a forward DNS record (AAAA.)  If the address is a temporary one,
record when it was seen.

If invoked with --clean, then look at the list of temporary records, and delete the 
old ones (which are no longer used.)

"""
 
# packet capture & decoding
import pcapy
import dpkt

#for DNS lookups.
import dns
import dns
import dns.tsigkeyring
import dns.update
import dns.query
import dns.reversename
import dns.resolver
import subprocess
import syslog

# for ipv62str
import struct
import re

# for persistence...
import shelve
import time

def hexdump(s):
    return( ":".join("{0:02x}".format(ord(c)) for c in s))

def ipv62str(a):
    l = struct.unpack('>HHHHHHHH',a)
    s = ":".join( ( "{0:0x}".format(i)) for i in l ) 
    t = re.sub( r'(:0)+',':',s)
    return(t)

def mac2host(fname):
    dddomain=""
    dnsmaster=""
    dnskey=""
    m2hf = open(fname,"r")
    macmap={}
    l=m2hf.readline()
    while l != "":
        ll = l.split()
        if len(ll) < 1 :
            pass
        elif ll[0] == 'host' :
            macmap[ll[2].lower()] = ll[1]
        elif ll[0] == 'domain':
            dddomain = ll[1]
        elif ll[0] == 'dnsmaster':
            dnsmaster = ll[1]
        elif ll[0] == 'dnskeyuser':
            dnskeyuser = ll[1]
        elif ll[0] == 'dnskey':
            dnskey = ll[1]
            
        l=m2hf.readline()
    m2hf.close()
    return( macmap, dddomain, dnsmaster, dnskeyuser, dnskey )

def dns_fwd_addr(fqdn,dns_server):
    """
    return all addresses resolvable host fully qualified domain name 
    """

    ret = []
    resolver = dns.resolver.Resolver()
    resolver.nameservers = dns_server

    try:
        answers= resolver.query(fqdn,'AAAA')
        ret = list(set( map( lambda x: x.to_text(), answers )))

    except:
        #except dns.resolver.NXDOMAIN:
        ret = []
	pass

    # FIXME: would like to be more specific about exeptions, but
    #  had to get rid of just catching NXDOMAIN, because was returning blank exceptions.
    #except Exception as ex:
    #	print "DNS lookup of %s failed: %s" % ( fqdn, str(ex) )
    #	exit(1)

    return(ret)

def dns_rev_host(addr):
   raddr=dns.reversename.from_address(addr)
   try:
       answers=dns.resolver.query(raddr,'PTR')
       return(answers[0].to_text())

   except dns.resolver.NXDOMAIN:
       return('AddrNotFound')

   except Exception as ex:
	msge( "DNS lookup of %s failed: %s" % ( addr, str(ex) ) )
	exit(1)

verbose = False

def msgd(str):
    syslog.syslog( syslog.LOG_DEBUG, str )
    print 'debug: ' + str

def msge(str):
    syslog.syslog( syslog.LOG_ERR, str )
    print 'error: ' +  str

def msgi(str):
    syslog.syslog( syslog.LOG_INFO, str )
    print 'error: ' +  str

class neighborhood_watch:

    def __init__ (self,opts,args):

        self.options = opts.__dict__
        cfg = self.options["etc"] + "/ndwatch.conf"
        ( self.mac2hostmap, self.domain, self.dnsmaster, dnskeyuser, dnskey ) = mac2host(cfg)
        self.arguments = args
        self.prefixes = []
	self.suffix = self.options["suffix"] 
        self.dnskeyring = dns.tsigkeyring.from_text({ dnskeyuser : dnskey })
        self.temp_record = shelve.open(self.options["etc"] + "/temp_record.shlf")

        if self.options["dump"]:
           self.dump_neigbour_advertisement_timestamps()
           exit()

	self.verbose = self.options["verbose"]

        if self.options["verbose"]:
            verbose=True
              
	self.primed = False
     
        msgd( "opts: %s " % self.options )
        msgd( "self.options['offline']=%s" % str(self.options['offline']) )
        msgd( "in ndwatch, domain set to %s" % self.domain )
        #print "dnskeyring=", self.dnskeyring
      
  

    def start (self):
        # TODO: specify a device or select all devices
        # dev = pcapy.findalldevs()[0]

        if self.options['offline'] is None :
            p = pcapy.open_live(self.options['interface'], 65536, False, 1)
        else:
            p = pcapy.open_offline(self.options['offline'])

	#print "p.loop"
        p.loop(-1, self.handle_packet)
 
    def save_neighbor_advertisement_timestamp(self, addr, mac ):
        """
        store the time of the last adverstisement for a given address.
        on persistent storage.

        Should we find ff:fe (permanent addresses, ) and skip them (they are permanent!)
             otoh, so what? still want to know what machine it is... 
	     register them with the suffix?
               
        """
        #print "FIXME: not checking whether addr is temporary or not"
        self.temp_record[ addr ] = ( int(time.time()), mac )
        self.temp_record.sync()

    def dump_neigbour_advertisement_timestamps(self):
        print( "neigbour ads: begin" )
        for a in self.temp_record.keys():
            print( "%s - %s" % ( a, self.temp_record[ a ] ) )
        print( "neigbour ads: end" )


    def prime(self):
	""" 
        read known addresses from ip -6 neigh, check for known macs, and register them.

2607:fa48:6e5e:5510:d589:ca42:e926:cc47 dev eth0 lladdr 10:68:3f:71:fd:c3 REACHABLE
2607:fa48:6e5e:5510:16b:273c:4d78:d863 dev eth0  FAILED
2607:fa48:6e5e:5510:451c:fa2a:d259:32a4 dev eth0 lladdr bc:f5:ac:f4:93:c9 STALE

	"""
        msgi( "priming maps by checking neighbor table" )
        p=subprocess.Popen( [ "ip", "-6", "neigh" ], stdout=subprocess.PIPE )
        for line in p.stdout:
            l=line.split()
            if len(l) <= 4:  # no mac available.
		continue

            addr=l[0]
            b = addr.split(':')

	    if b[0] == 'fe80' or ( b[0][0] == 'f' and (b[0][1] in [ 'd', 'e', 'f' ] )):
                msgd( "primer: skipping link-level address %s" % addr )
		continue

            mac=l[4].lower()
            if mac in self.mac2hostmap.keys():
                host = self.mac2hostmap[ mac ]
            else:
                host = "UNKNOWN-%s" % re.sub( r':','-',mac)

            msgd( "priming call dnsupdate( %s, %s, %s )" % ( host, mac, addr) )
            self.dnsupdates( host, mac, addr )
       
        self.primed=True
        return

    def dns_clean_old( self, threshold ):
        """
  
        Issue DNS updates to remove address records which have not been updated since threshold.
        threshold is a gmt time in seconds (as returned by time.now() )

	FIXME: only removes reverse, not fwd.
  
        """
        zone = str(dns.reversename.from_address( self.prefix[0:-4] ))[0:63]
        pfx= int(self.prefix[-2:])
        rzone="%s.ip6.arpa." % zone[-(pfx/2)+1:]
        msgi("dns_clean cycle: ageing threshold: %s seconds " % threshold )
  
        for addr in self.temp_record.keys():
          msgi( "addr=%s, mac=%s, last seen: %s" % ( addr , \
                  self.temp_record[ addr ][1], \
                  time.asctime(time.localtime(self.temp_record[ addr ][0])) ) )
  
          if ( time.time()-threshold > (self.temp_record[ addr ][0]) ):
              update = dns.update.Update( rzone, keyring=self.dnskeyring )
              raddr = dns.reversename.from_address(addr)
              fqdn = dns_rev_host(addr) 
              update.delete( raddr, 'ptr', fqdn )
              response = dns.query.tcp(update,self.dnsmaster)
              if response.rcode() != 0:
                  msge( "removal of reverse registration of %s failed" % addr )
                  msge( response )
              else:
                  msgi( "removal of reverse registration of %s succeeded" % addr )
                  del self.temp_record[ addr ]
              
        self.temp_record.sync()
        self.temp_record.close()

    def dnsupdates( self, host, mac, addr ):
      """
          determine and run needed DNS updates.
      """
  
      host_s= "%s-%s" % ( host, self.suffix )
      fqdn= "%s.%s" % ( host_s, self.domain)
      msgd( "DNS check mac: %s asking for: %s" % ( mac, addr ) )

      addr_si = dns_rev_host(addr)
  
      if ( addr_si != 'AddrNotFound' ) : # address already known.
           msgd( "mac: %s asking for %s, rev is already %s" % ( mac, addr, addr_si ) )
           return

      if ( addr in dns_fwd_addr( "%s.%s" % (host, self.domain) , self.dnsmaster)) :
           msgd( "mac: %s asking for %s, which it already has." % ( mac, host, addr ) )
           return

      if not ( addr in dns_fwd_addr(fqdn,self.dnsmaster) ) :
          if ( addr[0] == 'f' ) and ( addr[1] in [ 'd', 'e', 'f' ] ):
             msgd( "ignoring link level address %s" % addr )
             return

          update = dns.update.Update( self.domain, keyring=self.dnskeyring )
          update.add( host_s, 300, 'aaaa', addr )
          response = dns.query.tcp(update,self.dnsmaster)
          if response.rcode() != 0:
              msge( "forward registration of %s failed" % host )
              msge( response )
          else:
              msgi( "fwd of %s for mac: %s as %s succeeded" % ( host_s, mac, addr ) )
      else:
          msgd( "skipped fwd of %s for %s, already in DNS OK" % ( host_s, mac ) )
  
      # fwd done, now check reverse...
  
      # FIXME: only works for 2 digit netmask /48, /64, etc...
      zone = str(dns.reversename.from_address( self.prefix[0:-4] ))[0:63]
      pfx= int(self.prefix[-2:])
      rzone="%s.ip6.arpa." % zone[-(pfx/2)+1:]
  
      msgd( "mac: %s DNS Add rev %s -> %s" % ( mac, addr, fqdn ) )

      update = dns.update.Update( rzone, keyring=self.dnskeyring )
      
      update.add( dns.reversename.from_address(addr), 300, 'ptr', fqdn )
      response = dns.query.tcp(update,self.dnsmaster)
      if response.rcode() != 0:
          msge( "reverse registration of %s failed" % host )
          msge( response )
      else:
          msgi( "rev registration of %s-%s succeeded" % ( host, self.suffix ))
  
      return



  
    def handle_neighbor_advertisement(self, icmp):
      """ 
        parse received neighbour advertisement.
          -- extract mac and IP address.
          -- query mac2host table to identify a hostname.
          -- query DNS to ascertain consistency.
          --  & trigger requisite updates.
  
        spelled like an American... even though it looks odd.
        rationale: that is how the RFC's spell neighbour.
  
      """
      target_address=ipv62str(icmp.data[8:24])
  
      # skip link local addresses
      if target_address[0:4] == "fe80" :
          return
  
      if len(icmp.data) > 24:
          optype = ord(icmp.data[24])
          oplen = ord(icmp.data[25])
  
          if optype > 5 :
              msge( "malformed advert" )
          elif ((optype == 1) or (optype==2)):
              mac =  hexdump(icmp.data[26:])
  
              if mac in self.mac2hostmap.keys():
                  host = self.mac2hostmap[ mac ]
              else:
                  host = "UNKNOWN-%s" % re.sub( r':','-',mac)
              
              self.save_neighbor_advertisement_timestamp( \
                  target_address, mac )
              self.dnsupdates( host, mac, target_address )
  
  
    def handle_router_advertisement(self, icmp):
      """
          handle router advertisemet packet when received.
               decode and extract network prefix in the advert.
              see if it is known.
              save it.
          #
          # sample router advert!
          #length:  88                   a  b  c  d  e  f
               0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 
  
          00    86:00:0c:60:40:00:00:1e:00:00:00:00:00:00:00:00:
          10  16    03:04:40:a0:00:01:51:80:00:01:51:80:00:00:00:00:
          20  32    26:07:fa:48:6d:5a:4d:50:00:00:00:00:00:00:00:00:
          30  48    19:03:00:00:00:00:00:0a:26:07:fa:48:6d:5a:4d:50:
          40  64  00:00:00:00:00:00:00:01:05:01:00:00:00:00:05:00:
                  50  80  01:01:00:01:c0:02:f6:da:
      """
      # FIXME! radvd always reports prefix as first option...
      #  this will break if the option order changes.
      if ( ord(icmp.data[16]) == 3 ) : 
          net = ipv62str( icmp.data[32:48] )
          prefixlen = ord(icmp.data[18])
          prefix="%s:/%d" % ( net, prefixlen )
  
          if prefix not in self.prefixes :
              msgi( "New router advertisement prefix received: %s" % prefix )
              self.prefixes.append(prefix)
              self.prefix=prefix
  
  
    def handle_packet (self, header, data):
        eth = dpkt.ethernet.Ethernet (data)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ip = eth.data
            ip_data = ip.data
            if isinstance (ip_data, dpkt.icmp6.ICMP6):
                icmp = ip_data
                #print "length: %d code: %s" % ( len(icmp.data), hexdump(icmp.data) )
            else:
		return
            if icmp.type == dpkt.icmp6.ND_ROUTER_ADVERT:
                self.handle_router_advertisement( icmp )
            elif  self.prefixes == [] :
                return
            elif self.options['clean']:
                self.dns_clean_old( (self.options['age']*3600*24) )
                exit()
            elif icmp.type == dpkt.icmp6.ND_NEIGHBOR_ADVERT:
                self.handle_neighbor_advertisement( icmp )    
	        if not self.primed:
                    self.prime()
                    msgi("Setup complete. now just listening...")
  
from optparse import OptionParser
  
def MainParseOptions():
     parser = OptionParser()
  
     parser.add_option("-a", "--age", action="store_true", 
                    dest="age", default=7,
                    help="maximum age of temporary addresses, in days.")
     parser.add_option("-c", "--clean", action="store_true", 
                    dest="clean", default=False,
                    help="clean old addresses out.")
     parser.add_option("-d", "--dump", action="store_true", 
                    dest="dump", default=False,
                    help="view stored addresses.")
     parser.add_option("-e", "--etc", action="store_true", 
                    dest="etc", default="/etc/ndwatch",
                    help="config file location.")
     parser.add_option("-i", "--interface", dest="interface",
                    help="list on interface", metavar="INTERFACE")
     parser.add_option("-o", "--offline", dest="offline",
                    help="read given packet capture file instead of interface", 
                    metavar="OFFLINE")
     parser.add_option("-q", "--quiet",
                    action="store_false", dest="verbose", default=True,
                    help="don't print status messages to stdout")
     parser.add_option("-s", "--suffix", action="store_true", 
                    dest="suffix", default="anon",
                    help="suffix to add to fqdn for temporary addresses.")
     parser.add_option("-v", "--verbose",
                    action="store_true", dest="verbose", default=True,
                    help="messages to stdout")
  
     return( parser.parse_args() )
  
  
def main():
      ( opt, arg ) = MainParseOptions()
      msgi("Setup starting.")
      neighborhood_watch(opt,arg).start()
   
if __name__=="__main__":
      main()
  
  
