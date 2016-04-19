#!/bin/bash

# Written by: https://github.com/turkgrb
# Website: https://daulton.ca
# Purpose: This script will stop most port scanning attempts, UDP Floods,                  
# SYN Floods, TCP Floods, Handshake Exploits, XMAS Packets,                       
# Smurf Attacks, ICMP Bombs, LAND attacks and RST Floods. Additionally types of
# connections that are allowed in or out over a particular port etc is restricted
# to the following, operating in a default deny for all input, output, and forwarding tables:  
#
# * Denies all uninitiated ipv4 inbound connections except for torrents (if desired) so peers can connect
# * Denies all uninitiated ipv6 inbound connections
# * Drops inbound pings, allows outbound for both ipv4 and ipv6
# * Allows established connections inbound on ports 67/68, 80, 53, 443, 1994/1995 but NOT new connections
#	coming inbound
# * Allows new and established outbound connections for both ipv4 and ipv6          

# Save existing iptables rules before changing anything. iptables-restore script can be used to 
# restore old rules if necessary
iptables-save > /tmp/iptables.rules

################## VARIABLES ##################

# Allow OpenVPN to establish? YES/NO
allowVPN=NO
# Allow inbound pings? YES/NO
allowPINGS=NO
# Allow inbound SSH? YES/NO
allowSSH=NO
# Allow inbound traffic on port 80/443? YES/NO
allowHTTP=NO
# Allow inbound/outbound torrent traffic? YES/NO
allowTorrents=NO

# Do you want to enable the inNewConnection array to have the script input the entered ports
# into iptables? YES/NO
enableInNewConnection=NO
# Enter numerical port values here for new inbound connections that you want to establish. As an example
# if you want new inbound SSH sessions to be allowed, you'd put 22. 
# inNewConnection=("22" "5900") 
inNewConnection=("")

# Do you want to enable the InEstabConnection array to have the script input the entered ports
# into iptables? YES/NO
enableInEstabConnection=NO
# Enter numerical port values here for allowed established inbound connections, these are connections
# you establish. So to allow browser to establish HTTP sessions you'd enter port 80 if you want to allow
# that.
# Example: inEstabConnection=("5900" "3389" "3390" "6667")
inEstabConnection=("")

# Do you want to enable the enableOutboundConnections array to have the script input the entered ports
# into iptables? YES/NO
enableOutPorts=NO
# Enter numerical port values here for allowed outbound connections, since the script operates in a default
# drop/deny state you need to enter values here for ports you want to allow connections outbound on that
# are ports outside the default 80, 443, 22, 53
# Example: enableOutboundConnections=("5900" "3389" "3390" "6667")
enableOutboundConnections=("")

# Ports for the labeled traffic types. Change accordingly if your torrent client or SSH
# configuration uses a different port.
# Note: For your torrent client turn off random ports and select a port, then enter that here
WEB=80
DNS=53
SSL=443
SSH=22
TORRENTS=51413

# Change accordingly to your interface naming scheme and the ones you
# are using.
ETH=eth0
WLAN=wlan0
TUN=tun0

#TCPBurstNew: # of Packets a new connection can send in 1 request
#TCPBurstEst: # of Packets an existing connection can send in 1 request
TCPBurstNew=200
TCPBurstEst=50

#################################################

# Flush old rules, old custom tables
echo "* Flushing old rules"
iptables --flush
iptables --delete-chain

ip6tables --flush
ip6tables --delete-chain

# IPv4 default policies
echo "* Setting default policies"
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# IPv6 default policies
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP

##################################################
###############       INPUT        ###############
##################################################

echo "* Allow access for the interfaces loopback, tun, and tap"
iptables -A INPUT -i lo -p all -j ACCEPT
iptables -A INPUT -i tun -p all -j ACCEPT
iptables -A INPUT -i tap -p all -j ACCEPT

iptables -A INPUT -p udp -m udp --dport $DNS -m state --state ESTABLISHED -j ACCEPT

if  [[ $allowTorrents == YES ]] || [[ $allowTorrents == YES ]]; then
	echo "* Allowing inbound/outbound traffic on port $TORRENTS for torrent traffic"
	iptables -A INPUT -p tcp --dport $TORRENTS -m state --state NEW,ESTABLISHED -j ACCEPT
fi

if  [[ $allowPINGS == NO ]] || [[ $allowPINGS == no ]]; then
	echo "* Block all incoming PINGS, Although they should be blocked already"
	iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j REJECT --reject-with icmp-proto-unreachable
fi

if  [[ $allowSSH == YES ]] || [[ $allowSSH == yes ]]; then
	echo "* Allowing inbound SSH sessions"
	iptables -A INPUT -p tcp --dport $SSH -m state --state NEW,ESTABLISHED -j ACCEPT
fi

if  [[ $allowHTTP == YES ]] || [[ $allowHTTP == yes ]]; then
	echo "* Allowing inbound HTTP(S) traffic"
	iptables -A INPUT -p tcp --dport $HTTP -m state --state NEW,ESTABLISHED -j ACCEPT
	iptables -A INPUT -p tcp --dport $SSL -m state --state NEW,ESTABLISHED -j ACCEPT
else
	iptables -A INPUT -p tcp -m tcp --dport $SSL -m state --state ESTABLISHED -j ACCEPT
	iptables -A INPUT -p tcp -m tcp --dport $WEB -m state --state ESTABLISHED -j ACCEPT
fi

if  [[ $enableInNewConnection == YES ]] || [[ $enableInNewConnection == yes ]]; then
	inNewConnectionLength=${#inNewConnection[@]}
	adjustedLength=$(( $inNewConnectionLength - 1 ))

	for i in $( eval echo {0..$adjustedLength} )
	do
		iptables -A INPUT -p tcp --dport ${inNewConnection[$i]} -m state --state NEW,ESTABLISHED -j ACCEPT
		iptables -A INPUT -p udp --dport ${inNewConnection[$i]} -m state --state NEW,ESTABLISHED -j ACCEPT
	done
fi

if  [[ $enableInEstabConnection == YES ]] || [[ $enableInEstabConnection == yes ]]; then
	enableInEstabConnectionLength=${#enableInEstabConnection[@]}
	adjustedLength=$(( $enableInEstabConnectionLength - 1 ))

	for i in $( eval echo {0..$adjustedLength} )
	do
		iptables -A INPUT -p tcp --dport ${enableInEstabConnection[$i]} -m state --state ESTABLISHED -j ACCEPT
		iptables -A INPUT -p udp --dport ${enableInEstabConnection[$i]} -m state --state ESTABLISHED -j ACCEPT
	done
fi

# Force Fragments packets check
# Packets with incoming fragments drop them. This attack result into Linux server panic such data loss.
iptables -A INPUT -f -j DROP

# XMAS packets: Incoming malformed XMAS packets drop them
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

#Drop all NULL packets: Incoming malformed NULL packets
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

echo "* Enabling the 3 Way Hand Shake and limiting TCP Requests."
# IF YOU ARE USING CLOUD FLARE AND EXPERIENCE ISSUES INCREASE TCPBurst
# All TCP sessions should begin with SYN
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
# Allow established and related packets
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport $WEB -m state --state NEW -m limit --limit 50/minute --limit-burst $TCPBurstNew -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -m limit --limit 50/second --limit-burst $TCPBurstEst -j ACCEPT

echo "* Adding Protection from LAND Attacks"
# Remove ranges that are required
iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j DROP
iptables -A INPUT -s 192.168.0.0/24 -j DROP
iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP

echo "* Stop ICMP SMURF Attacks at the Door"
iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type 0 -m limit --limit 1/second -j ACCEPT

echo "* Next were going to drop all INVALID packets"
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP

echo "* Drop VALID but INCOMPLETE packets"
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP 
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP 
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP 
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP 
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP 
iptables -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP

echo "* Now we're going to enable RST Flood Protection"
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

echo "* Protection from Port Scans"
# Attacking IP will be locked for 24 hours (3600 x 24 = 86400 Seconds)
iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

echo "* Banned IP addresses are removed from the list every 24 Hours"
iptables -A INPUT -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove

echo "* Creating rules to add scanners to the PortScanner list and log the attempt"
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG
iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

echo "* We will block ALL OTHER INBOUND TRAFFIC"
iptables -A INPUT -j REJECT

##################################################
###############       OUTPUT       ###############
##################################################

iptables -A OUTPUT -o lo+ -j DROP

iptables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

if  [[ $allowVPN == YES ]] || [[ $allowVPN == yes ]]; then
	echo "* Allowing OpenVPN"
	iptables -A OUTPUT -o tun+ -j ACCEPT
	iptables -A INPUT -p udp --sport 1194:1195 -j ACCEPT
	
	iptables -A OUTPUT -o tun+ -p tcp --dport 1194:1195 -m state --state NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -o eth+ -p tcp --dport 1194:1195 -m state --state NEW,ESTABLISHED -j ACCEPT
	
	iptables -A OUTPUT -o tun+ -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -o eth+ -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
	
	iptables -A OUTPUT -o tun+ -p udp --dport 1194:1195 -m state --state NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -o eth+ -p udp --dport 1194:1195 -m state --state NEW,ESTABLISHED -j ACCEPT
	
	iptables -A OUTPUT -o tun+ -p udp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -o eth+ -p udp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
fi

if  [[ $enableOutPorts == YES ]] || [[ $enableOutPorts == yes ]]; then
	enableOutboundConnectionsLength=${#enableOutboundConnections[@]}
	adjustedLength=$(( $enableOutboundConnectionsLength - 1 ))

	for i in $( eval echo {0..$adjustedLength} )
	do
		iptables -A OUTPUT -p tcp --dport ${enableOutboundConnections[$i]} -m state --state ESTABLISHED -j ACCEPT
		iptables -A OUTPUT -p udp --dport ${enableOutboundConnections[$i]} -m state --state ESTABLISHED -j ACCEPT
	done
fi

if  [[ $allowTorrents == YES ]] || [[ $allowTorrents == YES ]]; then
	iptables -A OUTPUT -p tcp -m tcp --dport $TORRENTS -j ACCEPT
fi

echo "* Allowing DNS out over port $DNS"
iptables -A OUTPUT -p udp -m udp --dport $DNS -j ACCEPT

echo "* Allowing HTTP out over port $WEB"
iptables -A OUTPUT -p tcp -m tcp --dport $WEB -j ACCEPT

echo "* Allowing HTTPS Port $SSL"
iptables -A OUTPUT -p tcp -m tcp --dport $SSL -j ACCEPT

echo "* Allowing SSH Port $SSH"
iptables -A OUTPUT -p tcp -m tcp --dport $SSH -j ACCEPT

echo "* Allowing Outgoing PING Type ICMP Requests, So we don't break things."
iptables -A OUTPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

echo "* Allowing DHCP"
iptables -A OUTPUT -d 255.255.255.255 -j ACCEPT

echo "* Rejecting all other Outbound traffic"
iptables -A OUTPUT -j REJECT

##################################################
###############       FORWARD       ##############
##################################################

# accept forwarding from tun0 to eth0/wlan0 and vice versa:
iptables -A FORWARD -i $ETH -o $TUN -j ACCEPT
iptables -A FORWARD -i $TUN -o $ETH -j ACCEPT
iptables -A FORWARD -i $WLAN -o $TUN -j ACCEPT
iptables -A FORWARD -i $TUN -o $WLAN -j ACCEPT

echo "* Dropping all other forwarded traffic"
iptables -A FORWARD -j DROP

##################################################
###############     POSTROUTING     ##############
##################################################

iptables -t nat -A POSTROUTING -o $TUN -j MASQUERADE


##################################################
##############     IPv6 section     ##############
##################################################

ip6tables -F
ip6tables -X
ip6tables -t mangle -F
ip6tables -t mangle -X
 
# loopback
ip6tables -A INPUT -i lo -j DROP
ip6tables -A OUTPUT -o lo -j ACCEPT
 
# Allow full outbound connection but no inbound
ip6tables -A INPUT -i $ETH -m state --state ESTABLISHED,RELATED -j ACCEPT
ip6tables -A OUTPUT -o $ETH -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
 
# ICMP ping, allow out and deny in
ip6tables -A OUTPUT -o $ETH -p ipv6-icmp -j ACCEPT

if  [[ $allowPINGS == NO ]] || [[ $allowPINGS == no ]]; then
	ip6tables -A INPUT -i $ETH -p ipv6-icmp -j DROP
fi

echo " * saving settings"
/etc/init.d/iptables save

