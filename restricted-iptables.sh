#!/usr/bin/env bash
# Written by: 			Daulton
# Website: 				https://daulton.ca
# Repository:			https://github.com/jeekkd
# Script repository: 	https://github.com/jeekkd/restricted-iptables
#
# This is the 'action' part of the script, configuration is done in the 'configuration.sh' script. This
# script imports the configuration done in the 'configuration.sh' script so your desired action(s) and 
# decision(s) can be carried out by the script for the firewall.
#
#####################################################################################################
# Warning: For most people it is not recommended to touch the following.
#####################################################################################################
#
# Enable during debugging for some extra help. When an error occurs the program exits with a notification 
# displaying the exit code and line that the fault occurred at
# trap 'echo "Error $? at $LINENO; aborting." 1>&2; exit $?' ERR
#
# get_script_dir()
# Gets the directory the script is being ran from. To be used with the import() function
# so the configuration is imported from its absolute path
get_script_dir() {
	script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
}

# Leave here to get scripts running location
get_script_dir

# import()
# Important module(s) for the purpose of modularizing the script.
import() {
  module=$1
  . "$script_dir"/${module}.sh
}

import configuration
import functions

# Flush old rules, old custom tables
# Note: If there is an error deleting existing chains and you have modified this script
# then assure to remove references to them first
iptables --flush
iptables --delete-chain

ip6tables --flush
ip6tables --delete-chain

# IPv4 default policies
iptables -P INPUT "$inputPolicy"
iptables -P OUTPUT "$outputPolicy"
iptables -P FORWARD "$forwardPolicy"

# IPv6 default policies
ip6tables -P INPUT "$ipv6InputPolicy"
ip6tables -P OUTPUT "$ipv6OutputPolicy"
ip6tables -P FORWARD "$ipv6ForwardPolicy"

# New chain creation
if  [[ $disableSecurity == "N" ]] || [[ $disableSecurity == "n" ]]; then
	iptables -N NMAP-LOG
fi

####################################################################################################
# 										INBOUND
####################################################################################################

# Disable traffic into the specified interfaces
# Ethernet
if [[ $disableEth == "Y" ]] || [[ $disableEth == "y" ]]; then
	iptables -A INPUT -i $ETH -j DROP
fi

# Wlan
if  [[ $disableWlan == "Y" ]] || [[ $disableWlan == "y" ]]; then
	iptables -A INPUT -i $WLAN -j DROP
fi

# Tun
if  [[ $disableTun == "Y" ]] || [[ $disableTun == "y" ]]; then
	iptables -A INPUT -i $TUN -j DROP
fi

# This does not occur if disableSecurity is set to Y, as the section will be skipped.
# The purpose being if a user needs to troubleshoot and suspects the firewall is blocking too much, 
# additional security measures can be turned off. This is not recommended for regular usage.
if  [[ $disableSecurity == "N" ]] || [[ $disableSecurity == "n" ]]; then
	# Block portscans, anyone who tried to portscan us is locked out for a day
	iptables -A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j DROP
	iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

	# Once the day has passed, remove them from the portscan list
	iptables -A INPUT   -m recent --name portscan --remove
	iptables -A FORWARD -m recent --name portscan --remove

	# These rules add scanners to the portscan list, and log the attempt.
	iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
	iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

	# Nmap blocks are set for inbound connections
	# Borrowed from LutelWall - Source: http://www.lutel.pl/lutelwall/
	iptables -A NMAP-LOG -p tcp -m tcp --tcp-flags ALL URG,PSH,SYN,FIN  -j LOG --log-prefix "O_SCAN "
	iptables -A NMAP-LOG -p tcp -m tcp --tcp-flags ALL URG,PSH,SYN,FIN -j DROP
	iptables -A NMAP-LOG -p tcp -m tcp --tcp-flags ALL FIN  -j LOG --log-prefix "sF_SCAN "
	iptables -A NMAP-LOG -p tcp -m tcp --tcp-flags ALL FIN -j DROP
	iptables -A NMAP-LOG -p tcp -m tcp --tcp-flags ALL URG,PSH,FIN  -j LOG --log-prefix "sX_SCAN "
	iptables -A NMAP-LOG -p tcp -m tcp --tcp-flags ALL URG,PSH,FIN -j DROP
	iptables -A NMAP-LOG -p tcp -m tcp --tcp-flags ALL NONE  -j LOG --log-prefix "sN_SCAN "
	iptables -A NMAP-LOG -p tcp -m tcp --tcp-flags ALL NONE -j DROP
	iptables -A NMAP-LOG -p tcp -m tcp --tcp-flags ALL ACK  -j LOG --log-prefix "sA_SCAN "
	iptables -A NMAP-LOG -p tcp -m tcp --tcp-flags ALL ACK -j DROP
	iptables -A NMAP-LOG -p tcp -m tcp --tcp-flags ALL RST -j DROP
	iptables -A NMAP-LOG -p tcp -m tcp  -j LOG --log-prefix "BAD_FLAGS "
	iptables -A NMAP-LOG -j DROP

	# allowing all loopback (lo) traffic and drop all traffic to 127/8 that doesn't use lo
	iptables -A INPUT -i lo+ -j ACCEPT
	iptables -A INPUT ! -i lo+ -d 127.0.0.0/8 -j REJECT

	# Enabling the 3 Way Hand Shake and limiting TCP Requests
	# All TCP sessions should begin with SYN
	iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
	# Allow established and related packets
	iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	iptables -A INPUT -p tcp --dport $HTTP -m state --state NEW -m limit --limit 50/minute --limit-burst $TCPBurstNew -j ACCEPT
	iptables -A INPUT -m state --state RELATED,ESTABLISHED -m limit --limit 50/second --limit-burst $TCPBurstEst -j ACCEPT

	# Force Fragments packets check for inbound traffic
	# Packets with incoming fragments drop them. This attack result into Linux server panic such data loss.
	iptables -A INPUT -f -j DROP

	# XMAS packets: Incoming malformed XMAS packets drop them
	iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

	# Drop all NULL packets: Incoming malformed NULL packets
	iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

	# Adding Protection from LAND Attacks. Remove ranges that are required
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

	# Stop ICMP SMURF Attacks
	iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
	iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
	iptables -A INPUT -p icmp -m icmp --icmp-type 0 -m limit --limit 1/second -j ACCEPT

	# Next were going to drop all INVALID packets
	iptables -A INPUT -m state --state INVALID -j DROP
	iptables -A FORWARD -m state --state INVALID -j DROP
	iptables -A OUTPUT -m state --state INVALID -j DROP

	# Drop VALID but INCOMPLETE packets
	iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP 
	iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP 
	iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP 
	iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP 
	iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP 
	iptables -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP

	# Enabling RST Flood Protection
	iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
fi

# Allowing established DNS requests back in
if  [[ "$inputPolicy" == DROP ]] || [[ "$inputPolicy" == drop ]]; then
	iptables -A INPUT -p udp -m udp --dport "$DNS" -m state --state ESTABLISHED,RELATED -j ACCEPT
fi

# Relates to the openPortRanges array where the user is asked to enter port range(s) they wish to open
if [ ${#openPortRanges[@]} -gt 0 ]; then
	openPortRangesLength=${#openPortRanges[@]}
	adjustedLength=$(( openPortRangesLength - 1 ))

	for i in $( eval echo {0..$adjustedLength} )
	do
		iptables -A INPUT -p tcp --match multiport --dports "${openPortRanges[$i]}" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
		iptables -A INPUT -p udp --match multiport --dports "${openPortRanges[$i]}" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	done
fi

# Allowing inbound/outbound traffic. This occurs if allowTorrents was entered as 'Y' to allow torrent traffic
if  [[ $allowTorrents == "Y" ]] || [[ $allowTorrents == "y" ]]; then
	iptables -A INPUT -p tcp --dport "$TORRENTS" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	iptables -A INPUT -p udp --dport "$TORRENTS" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
fi

# This occurs if allowPINGS was entered as 'No' to block all incoming pings
if  [[ $allowPINGS == "N" ]] || [[ $allowPINGS == "n" ]]; then
	iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j REJECT --reject-with icmp-proto-unreachable
else
	iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
fi

# This occurs if allowSSH is entered as 'Y' to allow incoming SSH connections
if  [[ $allowSSH == "Y" ]] || [[ $allowSSH == "y" ]]; then
	if [ ${#sshNetworkRestrict[@]} -gt 0 ]; then
		sshNetworkRestrictLength=${#sshNetworkRestrict[@]}
		adjustedLength=$(( sshNetworkRestrictLength - 1 ))

		for i in $( eval echo {0..$adjustedLength} )
		do
			iptables -A INPUT -p tcp --source "${sshNetworkRestrict[$i]}" --dport $SSH -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 
		done
	else
		iptables -A INPUT -p tcp -m state --state NEW,ESTABLISHED,RELATED --dport $SSH -j ACCEPT
	fi
else
	iptables -A INPUT -p tcp -m state --state ESTABLISHED,RELATED --dport $SSH -j ACCEPT
fi

# This occurs if allowHTTP is entered as 'Y' to allow new incoming HTTP(S) connections.
# This is needed for things such as web servers. Else it will only allow established connections
# back in on ports 80, 443
if  [[ $allowHTTP == "Y" ]] || [[ $allowHTTP == "y" ]]; then
	iptables -A INPUT -p tcp --dport "$HTTP" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	iptables -A INPUT -p tcp --dport "$SSL" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
else
	iptables -A INPUT -p tcp --dport "$HTTP" -m state --state ESTABLISHED,RELATED -j ACCEPT
	iptables -A INPUT -p tcp --dport "$SSL" -m state --state ESTABLISHED,RELATED -j ACCEPT
fi

if  [[ $allowVPN == "Y" ]] || [[ $allowVPN == "y" ]]; then
	iptables -A INPUT -i $TUN -p tcp --dport 1194:1195 -m state --state ESTABLISHED,RELATED -j ACCEPT
	iptables -A INPUT -i $ETH -p tcp --dport 1194:1195 -m state --state ESTABLISHED,RELATED -j ACCEPT
	iptables -A INPUT -i $TUN -p udp --dport 1194:1195 -m state --state ESTABLISHED,RELATED -j ACCEPT
	iptables -A INPUT -i $ETH -p udp --dport 1194:1195 -m state --state ESTABLISHED,RELATED -j ACCEPT
fi

# If enableQuic has been set to 'Y' this is enabled. This is Quick UDP Internet Connections proptocol that
# Google is experimenting with for Google chrome and its other services to eventually replace TCP
if  [[ $enableQuic == "Y" ]] || [[ $enableQuic == "y" ]]; then
	iptables -A INPUT -p udp --dport "$SSL" -m state --state ESTABLISHED,RELATED -j ACCEPT
fi

# Allow DNS traffic out if inputpolicy is set to drop
if  [[ "$inputPolicy" == DROP ]] || [[ "$inputPolicy" == drop ]]; then
	iptables -A INPUT -p tcp --dport 53 -m state --state ESTABLISHED,RElATED -j ACCEPT
	iptables -A INPUT -p udp --dport 53 -m state --state ESTABLISHED,RElATED -j ACCEPT
fi

# If the inNewConnection array has contents it will enter the array values into iptables. This for for 
# allowing new and established connections in on the entered ports.
if [ ${#inNewConnection[@]} -gt 0 ]; then
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
if [ ${#enableOutboundConnections[@]} -gt 0 ]; then
	enableOutboundConnectionsLength=${#enableOutboundConnections[@]}
	adjustedLength=$(( enableOutboundConnectionsLength - 1 ))

	for i in $( eval echo {0..$adjustedLength} )
	do
		iptables -A INPUT -p tcp --dport "${enableOutboundConnections[$i]}" -m state --state ESTABLISHED,RElATED -j ACCEPT
		iptables -A INPUT -p udp --dport "${enableOutboundConnections[$i]}" -m state --state ESTABLISHED,RElATED -j ACCEPT
	done
fi

# Drop all other inbound traffic if inputPolicy is set to DROP
if  [[ $inputPolicy == DROP ]] || [[ $inputPolicy == drop ]]; then
	iptables -A INPUT -j DROP
fi

# Drop all other inbound traffic if inputPolicy is set to REJECT
if  [[ $inputPolicy == REJECT ]] || [[ $inputPolicy == reject ]]; then
	iptables -A INPUT -j REJECT
fi

####################################################################################################
# 											OUTBOUND
####################################################################################################

# Disable traffic out of the specified interfaces depending on the answers given 
# Ethernet
if  [[ $disableEth == "Y" ]] || [[ $disableEth == "y" ]]; then
	iptables -A OUTPUT -o $ETH -j DROP
fi

# Wlan
if  [[ $disableWlan == "Y" ]] || [[ $disableWlan == "y" ]]; then
	iptables -A OUTPUT -o $WLAN -j DROP
fi

# Tun
if  [[ $disableTun == "Y" ]] || [[ $disableTun == "y" ]]; then
	iptables -A OUTPUT -o $TUN -j DROP
fi

# Allows OpenVPN sessions to establish if allowVPN is selected as 'Y'
# This may or may not work with other VPN types if they use a different port. Either copy
# and paste this, change the variable to your own, change the ports, etc or change the ports in
# this one if you are not using OpenVPN at all
if  [[ $allowVPN == "Y" ]] || [[ $allowVPN == "y" ]]; then	
	iptables -A OUTPUT -o $TUN -p tcp --dport 1194:1195 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	iptables -A OUTPUT -o $ETH -p tcp --dport 1194:1195 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	
	iptables -A OUTPUT -o $TUN -p tcp --dport 443 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	iptables -A OUTPUT -o $ETH -p tcp --dport 443 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	
	iptables -A OUTPUT -o $TUN -p udp --dport 1194:1195 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	iptables -A OUTPUT -o $ETH -p udp --dport 1194:1195 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	
	iptables -A OUTPUT -o $TUN -p udp --dport 443 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	iptables -A OUTPUT -o $ETH -p udp --dport 443 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
fi

# If there are any entered ports in the enableOutboundConnections array this will have rules created to 
# allow those ports to make outbound connections.
if [ ${#enableOutboundConnections[@]} -gt 0 ]; then
	enableOutboundConnectionsLength=${#enableOutboundConnections[@]}
	adjustedLength=$(( enableOutboundConnectionsLength - 1 ))

	for i in $( eval echo {0..$adjustedLength} )
	do
		iptables -A OUTPUT -p tcp --dport "${enableOutboundConnections[$i]}" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
		iptables -A OUTPUT -p udp --dport "${enableOutboundConnections[$i]}" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
	done
fi

# Relates to the openPortRanges array where the user is asked to enter port range(s) they wish to open. This
# is triggered when there is anything entered in the openPortRanges array.
if [ ${#openPortRanges[@]} -gt 0 ]; then
	openPortRangesLength=${#openPortRanges[@]}
	adjustedLength=$(( openPortRangesLength - 1 ))

	for i in $( eval echo {0..$adjustedLength} )
	do
		iptables -A OUTPUT -p tcp --match multiport --dports "${openPortRanges[$i]}" -j ACCEPT
		iptables -A OUTPUT -p udp --match multiport --dports "${openPortRanges[$i]}" -j ACCEPT
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

# Allowing DNS over port $DNS outbound"
iptables -A OUTPUT -p udp -m udp --dport $DNS -j ACCEPT

# Allowing HTTP over port $HTTP outbound"
iptables -A OUTPUT -p tcp -m tcp --dport $HTTP -j ACCEPT

# Allowing HTTPS Port $SSL outbound"
iptables -A OUTPUT -p tcp -m tcp --dport $SSL -j ACCEPT

# Allowing SSH Port $SSH outbound"
iptables -A OUTPUT -p tcp -m tcp --dport $SSH -j ACCEPT

# Allowing outbound PING Type 8 ICMP Requests, so we don't break things."
iptables -A OUTPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

# Allowing DHCP outbound"
iptables -A OUTPUT -d 255.255.255.255 -j ACCEPT

# Dropping all other outbound traffic if outputPolicy is set to DROP
if  [[ $outputPolicy == DROP ]] || [[ $outputPolicy == drop ]]; then
	iptables -A OUTPUT -j DROP
fi

# Dropping all other outbound traffic if outputPolicy is set to REJECT
if  [[ $outputPolicy == REJECT ]] || [[ $outputPolicy == reject ]]; then
	iptables -A OUTPUT -j REJECT
fi

####################################################################################################
# 										FORWARDING
####################################################################################################

# Prevent internal forwarding between interfaces as it is a risk that traffic may try
# to get out a different interface if available to circumvent blocking rules in place
# on another interface
if  [[ $internalForward == "N" ]] || [[ $internalForward == "n" ]]; then	
	if [[ ${ETH} -gt 0 ]] && [[ ${TUN} -gt 0 ]]; then
		iptables -A FORWARD -i $ETH -o $TUN -j DROP
		iptables -A FORWARD -i $TUN -o $ETH -j DROP
	fi
	if [[ ${WLAN} -gt 0 ]] && [[ ${TUN} -gt 0 ]]; then
		iptables -A FORWARD -i $WLAN -o $TUN -j DROP
		iptables -A FORWARD -i $TUN -o $WLAN -j DROP
	fi
	if [[ ${WLAN} -gt 0 ]] && [[ ${ETH} -gt 0 ]]; then
		iptables -A FORWARD -i $WLAN -o $ETH -j DROP
		iptables -A FORWARD -i $ETH -o $WLAN -j DROP
	fi	
fi

# Dropping all other forwarded traffic if forwardPolicy is set to DROP
if  [[ $forwardPolicy == DROP ]] || [[ $forwardPolicy == drop ]]; then
	iptables -A FORWARD -j DROP
fi

# Dropping all other forwarded traffic if forwardPolicy is set to DROP
if  [[ $forwardPolicy == REJECT ]] || [[ $forwardPolicy == reject ]]; then
	iptables -A FORWARD -j REJECT
fi

####################################################################################################
# 										IPv6 INBOUND
####################################################################################################

# Depending on allowPINGS answer, either DROP or ACCEPT inbound pings
if  [[ $allowPINGS == NO ]] || [[ $allowPINGS == no ]]; then
	ip6tables -A INPUT -p ipv6-icmp -j DROP
else
	ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
fi

if  [[ $ipv6InputPolicy == DROP ]] || [[ $ipv6InputPolicy == drop ]]; then
	ip6tables -A INPUT -j DROP
fi

if  [[ $ipv6InputPolicy == REJECT ]] || [[ $ipv6InputPolicy == reject ]]; then
	ip6tables -A INPUT -j REJECT
fi

####################################################################################################
# 										IPv6 OUTBOUND
####################################################################################################

# Allow outbound pings 
ip6tables -A OUTPUT -o $ETH -p ipv6-icmp -j ACCEPT

if  [[ $ipv6OutputPolicy == DROP ]] || [[ $ipv6OutputPolicy == drop ]]; then
	ip6tables -A OUTPUT -j DROP
fi

if  [[ $ipv6OutputPolicy == REJECT ]] || [[ $ipv6OutputPolicy == reject ]]; then
	ip6tables -A OUTPUT -j REJECT
fi

####################################################################################################
# 										IPv6 FORWARDING
####################################################################################################

if  [[ $ipv6ForwardPolicy == DROP ]] || [[ $ipv6ForwardPolicy == drop ]]; then
	ip6tables -A FORWARD -j DROP
fi

if  [[ $ipv6ForwardPolicy == REJECT ]] || [[ $ipv6ForwardPolicy == reject ]]; then
	ip6tables -A FORWARD -j REJECT
fi

####################################################################################################

# If disableIPv6 is set to yes but ipv6InputPolicy and related ipv6 policy were not also set to
# DROP or REJECT then this will correct that to assure traffic is dropped.
if  [[ $disableIPv6 == Y ]] || [[ $disableIPv6 == y ]]; then	
	ip6tables --flush
	ip6tables --delete-chain
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
