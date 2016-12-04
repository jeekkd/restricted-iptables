#!/usr/bin/env bash
# Written by: 			Daulton
# Website: 				https://daulton.ca
# Repository:			https://github.com/jeekkd
# Script repository: 	https://github.com/jeekkd/restricted-iptables
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
# This is the configuration portion of this script, the primary script is restricted_iptables.sh. After
# configuration is done here it is restricted_iptables.sh that you launch to have iptables then be setup.
#
######################################## Policy Definitions ########################################
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
# Enable or disable additional the security measures such as port scanning attempts, UDP Floods, SYN Floods, 
# TCP Floods, Handshake Exploits, XMAS Packets, etc. This is not recommended for regular usage, but can be
# helpful to be able to turn off if troubleshooting is necessary.
disableSecurity=N
#
####################################################################################################
#									Default table policies
#
# The following policies can accept the following different inputs, DROP, REJECT, or ACCEPT. Consider
# reading the definitions above to help in deciding what to enter
####################################################################################################
#
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
# Open a range of ports - enter the beginning and end ports seperated by a colon (:). This will allow 
# TCP/UDP traffic both in and outbound for the entered port range(s). More ranges can be added by separating 
# each range by a space like so
# Example: openPortRanges=(6780:6999 48808:51413 24155:27810)
openPortRanges=()
#
# Enter numerical port values here for NEW uninitiated inbound connections that you want to allow to 
# establish. As an example, if you have an  IRC server and want inbound connections to be allowed, you'd put 
# 6667 to open that required port. 
# Example: inNewConnection=(5900 111 2049 6667) 
inNewConnection=()
#
# Enter numerical port values here for allowed outbound connections, enter values here for ports you want 
# to allow connections outbound on. These are also entered into the input chain to allow established and
# related connections back in.
#
# The following traffic is allowed out by default: HTTP, HTTPS, SSH, DNS, DHCP. Do not enter any of these
# here.
#
# Example: enableOutboundConnections=(5900 3389 3390 6667)
enableOutboundConnections=()
#
####################################################################################################
# 									Network restrictions section
####################################################################################################
#
# Inbound access restriction for SSH by network. Networks entered here are allowed to access SSH if
# 'Allow inbound SSH' is set to 'Y'. Enter a network and its subnet in the format of
# 10.0.0.0/16 which is network address then forward slash (/) then the CIDR. Multiple networks can be 
# entered if they are space delimited like so: sshNetworkRestrict=(192.168.1.0/24 10.0.0.0/16)
sshNetworkRestrict=()

####################################################################################################
# Ports for the labeled traffic types. Change accordingly if your torrent client or SSH
# configuration uses a different port.
# Note: For your torrent client turn off random ports and select a port, then enter that here
HTTP=80
DNS=53
SSL=443
SSH=22
TORRENTS=51413
#
# Change accordingly to your interface naming scheme and the interfaces you are using.
# Default is the 'old' naming scheme for Linux boxes, change to the new or BSD style if
# required for your box
#
# NOTE: Do not put an interface for one you are not using. If you just have ethernet, do not fill out wlan
# as that would mean you have wifi. And vice versa, if you only have wifi do not fill out eth. If you have
# both then fill them out. Only fill out TUN if you have tunnel interface(s) for anything.
#
# Tip: To view which network interfaces you have, use 'ifconfig' or 'ip link'
#
ETH=
WLAN=
TUN=
#
# Disable traffic in and out of an interface. Answer Y or N here
disableEth=N
disableWlan=N
disableTun=N
#
# TCPBurstNew: # of Packets a new connection can send in 1 request
# TCPBurstEst: # of Packets an existing connection can send in 1 request
# IF YOU ARE USING CLOUD FLARE AND EXPERIENCE ISSUES INCREASE TCPBurst
# Defaults: TCPBurstNew - 200	TCPBurstEst - 50
TCPBurstNew=200
TCPBurstEst=50

# Select location to save iptables rules to. This is for the automatic rule backup, used for returning to a
# previous set of rules through restore_iptables.sh.
#
saveRulesDir=/tmp
