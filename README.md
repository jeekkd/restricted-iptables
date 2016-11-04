Purpose
===

This script will stop most UDP Floods, SYN Floods, TCP Floods, Handshake Exploits
XMAS Packets, Smurf Attacks, ICMP Bombs, LAND attacks and RST Floods. Additionally 
types of connections that are allowed in or out over a particular port etc is restricted to the
following, operating in a default deny for all input, output, and forwarding tables:  

* Denies all uninitiated ipv4 inbound connections except for torrents (if desired) so peers can connect
* Denies all uninitiated ipv6 inbound connections
* Drops inbound pings, allows outbound for both ipv4 and ipv6
* Allows established connections inbound on ports 67/68, 80, 53, 443, 1994/1995 but NOT new connections
coming inbound
* Allows new and established outbound connections for both ipv4 and ipv6          

Additonal ports that might be required such as 6667 for IRC can be added, in the variables section
below I will make examples to make adding new ports for inbound and/or outbound connections easier.

> **Note:** 
> This script requires some tuning to be optimized for a least privledge sort of policy where things
> work and are locked down. Don't expect to run this and be done, you'll need to continue reading and fill
> things out for your specific system
>
> Additonally, many of the default behaviors can be overridden with the given variables at the top of
> the script if you do not like it so restricted.

Pictures
===

![daulton.ca](https://daulton.ca/lib/exe/fetch.php/bash_script_pictures:iptables.png?cache=)

By default before each time the script is ran your existing rules are saved. There is a companion script 
called 'restore_iptables.sh' that will restore your iptables rules back to those before the new rules were 
set. It saves an original copy of your rules the first time the script is ran, so long as that file exists 
still it will create time and date stamped rules files each time after to give you a selection of which 
point in time to restore your rules to.

![daulton.ca](https://daulton.ca/lib/exe/fetch.php/bash_script_pictures:restore_complete.png?w=600&h=133&tok=60f97e)

Setting the variables
===

Near the top of the script there is a variables section, this requires a little bit of configuration
to adjust it to your specific needs. I'll outline some examples below for what to expect and what this
series of options requires

- The first set of variables are simple Y or N questions which outline whether a specific thing to be 
allowed or blocked depending which question

```
# Allow OpenVPN to establish? Y/N
allowVPN=Y
# Allow inbound pings? Y/N
allowPINGS=N
# Allow inbound SSH? Y/N
allowSSH=N
# Allow inbound traffic on port 80/443? Y/N
allowHTTP=N
# Allow inbound/outbound torrent traffic? Y/N
allowTorrents=Y
# Allowing traffic forwarding between internal interfaces such as eth0 and wlan0? Y/N
internalForward=N
# Disable IPv6 completely (Y) or use the basic iptables configuration included (N)?
# If set to 'Y' then you should also assure to set the IPv6 policy below to either DROP or REJECT
disableIPv6=Y
# Allow QUIC (Quick UDP Internet Connections) on port 443 outbound? Y/N
enableQuic=Y
```

- The following is asking the default behavior for each type of table. As shown inbound, outbound, and
forwarding chains for both ipv4 and ipv6 accept a DROP, REJECT, or ACCEPT here allowing granular configuration

```
####################################################################################################
# The following policies can accept the following different inputs, DROP, REJECT, or ACCEPT
# Read the definitions above to aid in deciding what to enter
####################################################################################################
# What should the default input policy for ipv4 be?
inputPolicy=DROP
# What should the default outbound policy for ipv4 be?
outputPolicy=ACCEPT
# What should the default forwarding policy for ipv4 be?
forwardPolicy=DROP
# What should the default input policy for ipv6 be?
ipv6InputPolicy=DROP
# What should the default out policy for ipv6 be?
ipv6OutputPolicy=DROP
# What should the default forwarding policy for ipv6 be?
ipv6ForwardPolicy=DROP
```

- The next bit consists of two arrays, they are for each inbound and outbound ports. These can be enabled
or disabled by setting 'Y' or 'N' to each one individually. 

The first is for allowing new inbound connections over a specific port. An example of this is allowing
someone to SSH into your machine. So you might enter port 22 in this section to allow that through

The second, this is allowing outbound new and established connections to get out of the machine. Anything 
extra such as 6667 for IRC must be entered here to be allowed out. 

- In the event you changed your default ports or use a different torrent client then transmission etc
you may change the default ports in this section here

```
# Ports for the labeled traffic types. Change accordingly if your torrent client or SSH
# configuration uses a different port.
# Note: For your torrent client turn off random ports and select a port, then enter that here
WEB=80
DNS=53
SSL=443
SSH=22
TORRENTS=51413
```

- Next is setting your interface names. You can check what yours are by issuing 'ifconfig' in your terminal

```
# Change accordingly to your interface naming scheme and the interfaces you are using.
# Default is the 'old' naming scheme for Linux boxes, change to the new or BSD style if
# required for your box
ETH=eth0
WLAN=wlan0
TUN=tun0
```


How to use
===

- Lets get the source

```
git clone https://github.com/jeekkd/restricted-iptables.git && cd restricted-iptables
```

- This will make the script readable, writable, and executable to root and your user. 

```
sudo chmod 770 restricted_iptables.sh restore_iptables.sh
```

- Open the script in your text editor of choice. You need to edit the variables in the highlighted variables section near the top.

```
gedit restricted_iptables.sh
```

- You will want to make sure you've saved, then launch the script by doing the following:

```
sudo bash restricted_iptables.sh
```

By launching the script it will set the rules automatically and as is set in the configuration done.

> **Note:** 
> Make sure you've installed the 'iptables' package for your distribution and if your distribution
> such as Gentoo requires you to configure your own kernel [assure that iptables is configured/enabled](https://wiki.gentoo.org/wiki/Iptables)

Restoring previous rules
===

By default before each time the script is ran your existing rules are saved. There is a companion script 
called 'restore_iptables.sh' that will restore your iptables rules back to those before the new rules were 
set. It saves an original copy of your rules the first time the script is ran, so long as that file exists 
still it will create time and date stamped rules files each time after to give you a selection of which point 
in time to restore your rules to.

- To restore your old rules launch the script as such and follow the prompts

```
sudo bash restore_iptables.sh
```


> **Note:** 
> Rules are stored in /tmp by default, /tmp is cleaned automatically so if you wish to keep your rules 
> permanently you can either change the location the scripts use or manually save by doing the following
>
> Saving:
> ```
 iptables-save > /directory/example.rules
>
>```
> Restoring:
> ```
 iptables-restore < /directory/example.rules
> ```
