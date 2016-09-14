#!/usr/bin/env bash
# Written by: https://gitlab.com/u/huuteml
# Website: https://daulton.ca
#
# This script will help stop most port scanning attempts, UDP Floods, SYN Floods, TCP Floods, 
# Handshake Exploits, XMAS Packets, Smurf Attacks, ICMP Bombs, LAND attacks and RST Floods. Additionally 
# types of connections that are allowed in or out over a particular port etc is restricted to the
# following, operating in a default deny for all inbound, outbound, and forwarding tables:  
#
# * Denies all uninitiated ipv4 inbound connections except for torrents (if desired) so peers can connect
# * Denies all uninitiated ipv6 inbound connections
# * Drops inbound pings, allows outbound for both ipv4 and ipv6
# * Allows established connections inbound on ports 67/68, 80, 53, 443, 1994/1995 but NOT new connections
#	coming inbound
# * Allows new and established outbound connections for both ipv4 and ipv6          
#
# Note: This script requires some tuning to be optimized for a least privledge sort of policy where things
# work and are locked down and/or work the way you want. Don't expect to run this and be done, you'll need 
# to continue reading and configure for your specific system and needs
#
####################################################################################################
# Policy Definitions:
# Accept – Allow the connection.
#
# Drop – Drop the connection, act like it never happened. This is best if you don’t want the source to 
# realize your system exists.
#
# Reject – Don’t allow the connection, but send back an error. This is best if you don’t want a particular 
# source to connect to your system, but you want them to know that your firewall blocked them.
#
########################################## VARIABLES ################################################
#
# Allow OpenVPN to establish? Y/N
allowVPN=N
#
# Allow inbound pings? Y/N
allowPINGS=N
#
# Allow inbound SSH? Y/N
allowSSH=N
#
# Allow inbound traffic on port 80/443? Y/N
allowHTTP=N
#
# Allow inbound/outbound torrent traffic? Y/N
allowTorrents=N
#
# Allowing traffic forwarding between internal interfaces such as eth0 and wlan0? Y/N
internalForward=N
#
# Disable IPv6 completely (Y) or use the basic iptables configuration included (N)?
# If set to 'Y' then you should also assure to set the IPv6 policy below to either DROP or REJECT
disableIPv6=N
#
# Allow QUIC (Quick UDP Internet Connections) on port 443 outbound? Y/N
enableQuic=N
#
####################################################################################################
# The following policies can accept the following different inputs, DROP, REJECT, or ACCEPT
# 1. Remember to read the definitions above to help in deciding what to enter
# 2. Type your selection in UPPER CASE
####################################################################################################
# Default inbound policy for ipv4 be?
inputPolicy=DROP
#
# Default outbound policy for ipv4
outputPolicy=DROP
#
# Default forwarding policy for ipv4
forwardPolicy=DROP
#
# Default inbound policy for ipv6
ipv6InputPolicy=DROP
#
# Default outbound  policy for ipv6
ipv6OutputPolicy=DROP
#
# Default forwarding policy for ipv6
ipv6ForwardPolicy=DROP
#
####################################################################################################
# 									Opening ports section
####################################################################################################
#
# Do you want to enable the inNewConnection array to have the script input the entered ports
# into iptables? Y/N
enableInNewConnection=N
# Enter numerical port values here for NEW uninitiated inbound connections that you want to allow to 
# establish. As an example, if you want NEW uninitiated inbound NFS sessions to be allowed, you'd put 111. 
#
# Example: inNewConnection=("5900" "111") 
inNewConnection=("")
#
# Do you want to enable the enableOutboundConnections array to have the script input the entered ports
# into iptables? Y/N
enableOutPorts=N
# Enter numerical port values here for allowed outbound connections, enter values here for ports you want 
# to allow connections outbound on. These are also entered into the input chain to allow established and
# related connections back in.
#
# These are allowed out by default: HTTP, HTTPS, SSH, DNS, DHCP so do not worry about allowing those here
#
# Example: enableOutboundConnections=("5900" "3389" "3390" "6667")
enableOutboundConnections=("")
#
# Ports for the labeled traffic types. Change accordingly if your torrent client or SSH
# configuration uses a different port.
# Note: For your torrent client turn off random ports and select a port, then enter that here
WEB=80
DNS=53
SSL=443
SSH=22
TORRENTS=51413

# Change accordingly to your interface naming scheme and the interfaces you are using.
# Default is the 'old' naming scheme for Linux boxes, change to the new or BSD style if
# required for your box
ETH=eth0
WLAN=wlan0
TUN=tun0

# Disable traffic in and out of an interface. Answer Y or N here
disableEth=N
disableWlan=N
disableTun=N

# TCPBurstNew: # of Packets a new connection can send in 1 request
# TCPBurstEst: # of Packets an existing connection can send in 1 request
# IF YOU ARE USING CLOUD FLARE AND EXPERIENCE ISSUES INCREASE TCPBurst
TCPBurstNew=200
TCPBurstEst=50

####################################################################################################
# Warning: For most people it is not recommended to touch 
# the following.
####################################################################################################

# Save existing iptables rules before changing anything. restore_iptables.sh script can be used to 
# restore old rules if necessary - included in the repo.
if [ -f "/tmp/original_iptables.rules" ]; then
	today_date=$( date +%I_%M_%b_%d_%Y)
	iptables-save > /tmp/${today_date}_iptables.rules
else 
	iptables-save > /tmp/original_iptables.rules
fi

# saveTables()
# Modified function from below, purpose is to detect which distribution is running so
# the rules may be saved in a way for each distribution as to work on a wider range of
# systems rather then just Gentoo.
# From: https://danielgibbs.co.uk/2013/04/bash-how-to-detect-os/
saveTables(){
	arch=$(uname -m)
	kernel=$(uname -r)
	voidLinux=$(cat /proc/version | cut -d " " -f 4)
	if [ -f /etc/lsb-release ]; then
		echo " * Saving all iptables settings"
		/etc/init.d/iptables save
		/etc/init.d/ip6tables save
	elif [ -f /etc/debian_version ]; then
		echo " * Saving all iptables settings"
		iptables-save > /etc/iptables/rules.v4
		ip6tables-save > /etc/iptables/rules.v6
	elif [ -f /etc/redhat-release ]; then
		echo " * Saving all iptables settings"
		iptables-save > /etc/sysconfig/iptables
		ip6tables-save > /etc/sysconfig/ip6tables
	elif [ $voidLinux == "(xbps-builder@build.voidlinux.eu)" ]; then
		echo " * Saving all iptables settings"
		iptables-save > /etc/iptables/iptables.rules
		ip6tables-save > /etc/iptables/ip6tables.rules
	else
		echo "Warning: Your distribution was unable to be detected which means the"
		echo "iptables rules are unable to be automatically saved and made persistent."
		echo "You will need to search of how to save them for your distribution." 
		echo
		echo "Please report this error! remember to include which distribution you are using"
		echo "https://gitlab.com/huuteml/restricted_iptables"
	fi
}

# Flush old rules, old custom tables
# Note: If there is an error deleting existing chains and you have modified this script
# then assure to remove references to them first
echo "* Flushing old rules"
iptables --flush
iptables --delete-chain

ip6tables --flush
ip6tables --delete-chain

# IPv4 default policies
echo "* Setting default policies for input, outbound, and forwarding tables"
iptables -P INPUT $inputPolicy
iptables -P OUTPUT $outputPolicy
iptables -P FORWARD $forwardPolicy

# IPv6 default policies
ip6tables -P INPUT $ipv6InputPolicy
ip6tables -P OUTPUT $ipv6OutputPolicy
ip6tables -P FORWARD $ipv6ForwardPolicy

####################################################################################################
# 										INBOUND
####################################################################################################

# Disable traffic into the specified interfaces
# Ethernet
if  [[ $disableEth == "Y" ]] || [[ $disableEth == "y" ]]; then
	echo "* Disabling traffic input into $ETH"
	iptables -A INPUT -i $ETH -j DROP
fi

# Wlan
if  [[ $disableWlan == "Y" ]] || [[ $disableWlan == "y" ]]; then
	echo "* Disabling traffic input into $WLAN"
	iptables -A INPUT -i $WLAN -j DROP
fi

# Tun
if  [[ $disableTun == "Y" ]] || [[ $disableTun == "y" ]]; then
	echo "* Disabling traffic input into $TUN"
	iptables -A INPUT -i $TUN -j DROP
fi

# Attempt to block portscans
# Anyone who tried to portscan us is locked out for an entire day.
iptables -A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

# Once the day has passed, remove them from the portscan list
iptables -A INPUT   -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove

# These rules add scanners to the portscan list, and log the attempt.
iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

echo "* Allowing all loopback (lo) traffic and drop all traffic to 127/8 that doesn't use lo"
iptables -A INPUT -i lo+ -j ACCEPT
iptables -A INPUT ! -i lo+ -d 127.0.0.0/8 -j REJECT

echo "* Enabling the 3 Way Hand Shake and limiting TCP Requests."
# All TCP sessions should begin with SYN
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
# Allow established and related packets
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport $WEB -m state --state NEW -m limit --limit 50/minute --limit-burst $TCPBurstNew -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -m limit --limit 50/second --limit-burst $TCPBurstEst -j ACCEPT

# Force Fragments packets check
# Packets with incoming fragments drop them. This attack result into Linux server panic such data loss.
iptables -A INPUT -f -j DROP

# XMAS packets: Incoming malformed XMAS packets drop them
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

#Drop all NULL packets: Incoming malformed NULL packets
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

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

echo "* Enabling RST Flood Protection"
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

echo "* Allowing established DNS requests back in"
iptables -A INPUT -p udp -m udp --dport "$DNS" -m state --state ESTABLISHED,RELATED -j ACCEPT

# This occurs if allowTorrents was entered as 'Y' to allow torrent traffic
if  [[ $allowTorrents == "Y" ]] || [[ $allowTorrents == "y" ]]; then
	echo "* Allowing inbound/outbound traffic on port $TORRENTS for torrent traffic"
	iptables -A INPUT -p tcp --dport "$TORRENTS" -m state --state NEW,ESTABLISHED -j ACCEPT
	iptables -A INPUT -p udp --dport  "$TORRENTS" -m state --state NEW,ESTABLISHED -j ACCEPT
fi

# This occurs if allowPINGS was entered as 'No' to block all incoming pings
if  [[ $allowPINGS == "N" ]] || [[ $allowPINGS == "n" ]]; then
	echo "* Block all incoming pings, although they should be blocked already"
	iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j REJECT --reject-with icmp-proto-unreachable
fi

# This occurs if allowSSH is entered as 'Y' to allow incoming SSH connections
if  [[ $allowSSH == "Y" ]] || [[ $allowSSH == "y" ]]; then
	echo "* Allowing inbound SSH sessions"
	iptables -A INPUT -p tcp -m state --state NEW,ESTABLISHED,RELATED --dport $SSH -j ACCEPT
fi

# This occurs if allowHTTP is entered as 'Y' to allow new incoming HTTP(S) connections.
# This is needed for things such as web servers. Else it will only allow established connections
# back in on ports 80, 443
if  [[ $allowHTTP == "Y" ]] || [[ $allowHTTP == "y" ]]; then
	echo "* Allowing inbound HTTP(S) traffic"
	iptables -A INPUT -p tcp --dport "$HTTP" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	iptables -A INPUT -p tcp --dport "$SSL" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
else
	echo "* Allowing regular HTTP(S) traffic back in"
	iptables -A INPUT -p tcp -m tcp --dport "$SSL" -m state --state ESTABLISHED,RELATED -j ACCEPT
	iptables -A INPUT -p tcp -m tcp --dport "$WEB" -m state --state ESTABLISHED,RELATED -j ACCEPT
fi

# If enableQuic has been set to 'Y' this is enabled. This is Quick UDP Internet Connections proptocol that
# Google is experimenting with for Google chrome and its other services to eventually replace TCP
if  [[ $enableQuic == "Y" ]] || [[ $enableQuic == "y" ]]; then
	echo "* Allowing UDP traffic back in on port 443 for QUIC support"
	iptables -A INPUT -p udp --dport "$SSL" -m state --state ESTABLISHED,RELATED -j ACCEPT
fi

# If enableInNewConnection is 'Y' this will create rules for all entered ports in the inNewConnection
# array. This for for allowing new and established connections in on the entered ports.
if  [[ $enableInNewConnection == "Y" ]] || [[ $enableInNewConnection == "y" ]]; then
	inNewConnectionLength=${#inNewConnection[@]}
	adjustedLength=$(( inNewConnectionLength - 1 ))

	for i in $( eval echo {0..$adjustedLength} )
	do
		iptables -A INPUT -p tcp --dport "${inNewConnection[$i]}" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
		iptables -A INPUT -p udp --dport "${inNewConnection[$i]}" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	done
fi

# This is similar to the above, except it uses the enableOutboundConnections array. The purpose of this
# is to allow established and related connections back in on outbound connections using the same ports 
# entered into the array
if  [[ $enableOutPorts == "Y" ]] || [[ $enableOutPorts == "y" ]]; then
	enableOutboundConnectionsLength=${#enableOutboundConnections[@]}
	adjustedLength=$(( enableOutboundConnectionsLength - 1 ))

	for i in $( eval echo {0..$adjustedLength} )
	do
		iptables -A INPUT -p tcp --dport "${enableOutboundConnections[$i]}" -m state --state ESTABLISHED,RElATED -j ACCEPT
		iptables -A INPUT -p udp --dport "${enableOutboundConnections[$i]}" -m state --state ESTABLISHED,RElATED -j ACCEPT
	done
fi

if  [[ $inputPolicy == DROP ]] || [[ $inputPolicy == drop ]]; then
	echo "* DROPPING ALL OTHER INBOUND TRAFFIC"
	iptables -A INPUT -j DROP
fi

if  [[ $inputPolicy == REJECT ]] || [[ $inputPolicy == reject ]]; then
	echo "* REJECTING ALL OTHER INBOUND TRAFFIC"
	iptables -A INPUT -j REJECT
fi

####################################################################################################
# 											OUTBOUND
####################################################################################################

# Disable traffic out of the specified interfaces depending on the answers given 
# Ethernet
if  [[ $disableEth == "Y" ]] || [[ $disableEth == "y" ]]; then
	echo "* Disabling traffic outbound for $ETH"
	iptables -A OUTPUT -o $ETH -j DROP
fi

# Wlan
if  [[ $disableWlan == "Y" ]] || [[ $disableWlan == "y" ]]; then
	echo "* Disabling traffic outbound for $WLAN"
	iptables -A OUTPUT -o $WLAN -j DROP
fi

# Tun
if  [[ $disableTun == "Y" ]] || [[ $disableTun == "y" ]]; then
	echo "* Disabling traffic outbound for $TUN"
	iptables -A OUTPUT -o $TUN -j DROP
fi

iptables -A OUTPUT -o lo+ -j DROP

# Allows OpenVPN sessions to establish if allowVPN is selected as 'Y'
# This may or may not work with other VPN types if they use a different port. Either copy
# and paste this, change the variable to your own, change the ports, etc or change the ports in
# this one if you are not using OpenVPN at all
if  [[ $allowVPN == "Y" ]] || [[ $allowVPN == "y" ]]; then
	echo "* Allowing OpenVPN traffic in and outbound"
	
	iptables -A OUTPUT -o $TUN -p tcp --dport 1194:1195 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	iptables -A OUTPUT -o $ETH -p tcp --dport 1194:1195 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	
	iptables -A OUTPUT -o $TUN -p tcp --dport 443 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	iptables -A OUTPUT -o $ETH -p tcp --dport 443 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	
	iptables -A OUTPUT -o $TUN -p udp --dport 1194:1195 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	iptables -A OUTPUT -o $ETH -p udp --dport 1194:1195 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	
	iptables -A OUTPUT -o $TUN -p udp --dport 443 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	iptables -A OUTPUT -o $ETH -p udp --dport 443 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
fi

# If enableOutPorts is selected as 'Y' then the entered ports in the enableOutboundConnections array
# will have rules created to allow those ports to make outbound connections
if  [[ $enableOutPorts == "Y" ]] || [[ $enableOutPorts == "y" ]]; then
	enableOutboundConnectionsLength=${#enableOutboundConnections[@]}
	adjustedLength=$(( enableOutboundConnectionsLength - 1 ))

	for i in $( eval echo {0..$adjustedLength} )
	do
		iptables -A OUTPUT -p tcp --dport "${enableOutboundConnections[$i]}" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
		iptables -A OUTPUT -p udp --dport "${enableOutboundConnections[$i]}" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	done
fi

# If allowTorrents has been set to 'Y' then torrent traffic will be allowed out on both udp and tcp
# for the entered torrent port
if  [[ $allowTorrents == "Y" ]] || [[ $allowTorrents == "y" ]]; then
	iptables -A OUTPUT -p tcp -m tcp --dport $TORRENTS -j ACCEPT
	iptables -A OUTPUT -p udp -m udp --dport $TORRENTS -j ACCEPT
fi

# If enableQuic has been set to 'Y' this is enabled. This is Quick UDP Internet Connections proptocol that
# Google is experimenting with for Google chrome and its other services to eventually replace TCP
if  [[ $enableQuic == "Y" ]] || [[ $enableQuic == "y" ]]; then
	iptables -A OUTPUT -p udp -m udp --dport $SSL -j ACCEPT
fi

echo "* Allowing DNS over port $DNS outbound"
iptables -A OUTPUT -p udp -m udp --dport $DNS -j ACCEPT

echo "* Allowing HTTP over port $WEB outbound"
iptables -A OUTPUT -p tcp -m tcp --dport $WEB -j ACCEPT

echo "* Allowing HTTPS Port $SSL outbound"
iptables -A OUTPUT -p tcp -m tcp --dport $SSL -j ACCEPT

echo "* Allowing SSH Port $SSH outbound"
iptables -A OUTPUT -p tcp -m tcp --dport $SSH -j ACCEPT

echo "* Allowing outbound PING Type 8 ICMP Requests, so we don't break things."
iptables -A OUTPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

echo "* Allowing DHCP (Broadcasts) outbound"
iptables -A OUTPUT -d 255.255.255.255 -j ACCEPT

if  [[ $outputPolicy == DROP ]] || [[ $outputPolicy == drop ]]; then
	echo "* DROPPING ALL OTHER OUTBOUND TRAFFIC"
	iptables -A OUTPUT -j DROP
fi

if  [[ $outputPolicy == REJECT ]] || [[ $outputPolicy == reject ]]; then
	echo "* REJECTING ALL OTHER OUTBOUND TRAFFIC"
	iptables -A OUTPUT -j REJECT
fi

####################################################################################################
# 										FORWARDING
####################################################################################################

# Prevent internal forwarding between interfaces as it is a risk that traffic may try
# to get out a different interface if available to circumvent blocking rules in place
# on another interface
if  [[ $internalForward == "N" ]] || [[ $internalForward == "n" ]]; then
	iptables -A FORWARD -i $ETH -o $TUN -j DROP
	iptables -A FORWARD -i $TUN -o $ETH -j DROP
	iptables -A FORWARD -i $WLAN -o $TUN -j DROP
	iptables -A FORWARD -i $TUN -o $WLAN -j DROP
fi

if  [[ $forwardPolicy == DROP ]] || [[ $forwardPolicy == drop ]]; then
	echo "* DROPPING all other forwarded traffic"
	iptables -A FORWARD -j DROP
fi

if  [[ $forwardPolicy == REJECT ]] || [[ $forwardPolicy == reject ]]; then
	echo "* REJECTING all other forwarded traffic"
	iptables -A FORWARD -j REJECT
fi

####################################################################################################
# 									ALL IPV6 SECTIONS
####################################################################################################

# If disableIPv6 is set to yes but ipv6InputPolicy and related ipv6 policy were not also set to
# DROP or REJECT then this will correct that so traffic is appropriately dropped
if  [[ $disableIPv6 == Y ]] || [[ $disableIPv6 == y ]]; then	
	# Input
	if  [[ $ipv6InputPolicy == ACCEPT ]] || [[ $ipv6InputPolicy == accept ]]; then
		ip6tables -A INPUT -j DROP
	fi
	
	# Output
	if  [[ $ipv6OutputPolicy == ACCEPT ]] || [[ $ipv6OutputPolicy == accept ]]; then
		ip6tables -A OUTPUT -j DROP
	fi
	
	# Forwarding
	if  [[ $ipv6ForwardPolicy == ACCEPT ]] || [[ $ipv6ForwardPolicy == accept ]]; then
		ip6tables -A FORWARD -j DROP
	fi
fi

if  [[ $disableIPv6 == N ]] || [[ $disableIPv6 == n ]]; then	 
	echo "* IPv6: Allow full outbound connection but no inbound"
	ip6tables -A INPUT -i $ETH -m state --state ESTABLISHED,RELATED -j ACCEPT
	ip6tables -A OUTPUT -o $ETH -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	
	ip6tables -A INPUT -i $WLAN -m state --state ESTABLISHED,RELATED -j ACCEPT
	ip6tables -A OUTPUT -o $WLAN -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	 
	echo "* IPv6: ICMP ping is being allowed outbound"
	ip6tables -A OUTPUT -o $ETH -p ipv6-icmp -j ACCEPT

	if  [[ $allowPINGS == NO ]] || [[ $allowPINGS == no ]]; then
		echo "* IPv6: ICMP ping is being dropped inbound"
		ip6tables -A INPUT -i $ETH -p ipv6-icmp -j DROP
	else
		echo "* IPv6: ICMP ping is being accepted inbound"
		ip6tables -A INPUT -i $ETH -p ipv6-icmp -j ACCEPT
	fi
fi

# Inbound for ipv6
if  [[ $ipv6InputPolicy == DROP ]] || [[ $ipv6InputPolicy == drop ]]; then
	echo "* Ipv6: Dropping all other input traffic"
	ip6tables -A INPUT -j DROP
fi

if  [[ $ipv6InputPolicy == REJECT ]] || [[ $ipv6InputPolicy == reject ]]; then
	echo "* Ipv6: Rejecting all other input traffic"
	ip6tables -A INPUT -j REJECT
fi

# Outboumd for ipv6
if  [[ $ipv6OutputPolicy == DROP ]] || [[ $ipv6OutputPolicy == drop ]]; then
	echo "* Ipv6: Dropping all other outbound traffic"
	ip6tables -A OUTPUT -j DROP
fi

if  [[ $ipv6OutputPolicy == REJECT ]] || [[ $ipv6OutputPolicy == reject ]]; then
	echo "* Ipv6: Rejecting all other outbound traffic"
	ip6tables -A OUTPUT -j REJECT
fi

# Forwarding for ipv6
if  [[ $ipv6ForwardPolicy == DROP ]] || [[ $ipv6ForwardPolicy == drop ]]; then
	echo "* Ipv6: Dropping all other forwarded traffic"
	ip6tables -A FORWARD -j DROP
fi

if  [[ $forwardPolicy == REJECT ]] || [[ $forwardPolicy == reject ]]; then
	echo "* Ipv6: Rejecting all other forwarded traffic"
	ip6tables -A FORWARD -j REJECT
fi

####################################################################################################

saveTables

