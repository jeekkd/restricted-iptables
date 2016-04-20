Purpose
===

This script will stop most port scanning attempts, UDP Floods, SYN Floods, TCP Floods, 
Handshake Exploits, XMAS Packets, Smurf Attacks, ICMP Bombs, LAND attacks and RST Floods. 

Additionally types of connections that are allowed in or out over a particular port etc is 
restricted to the following, operating in a default deny for all input, output, and forwarding tables:  

- Denies all uninitiated ipv4 inbound connections except for torrents (if desired) so peers can connect
- Denies all uninitiated ipv6 inbound connections
- Drops inbound pings, allows outbound for both ipv4 and ipv6
- Allows established connections inbound on ports 67/68, 80, 53, 443, 1994/1995 but NOT new connections
coming inbound
- Allows new and established outbound connections for both ipv4 and ipv6

Additonal ports that might be required such as 6667 for IRC can be added, in the variables section
below I will make examples to make adding new ports for inbound and/or outbound connections easier.

Setting the variables
===

Near the top of the script there is a variables section, this requires a little bit of configuration
to adjust it to your specific needs. I'll outline some example changes below.

- The first set of variables are simple yes/no answers asking you if you want to allow certain
things to occur.

```
# Allow OpenVPN to establish? YES/NO
allowVPN=NO
```

- The next bit consists of three arrays, they are for different inbound/output and connection states. These
are each enabled by their corresponding enable option by typing YES/NO where asked.

The first is for allowing new inbound connections over a specific port. An example of this is allowing
someone to SSH into your machine. So you might enter port 22 in this section to allow that through

The second, this is for allowing established connections back in. This is necessary for things such
as HTTP for after you request content a response is sent back with that content, so it must be allowed
back in. 

The third, this is allowing outbound new and established connections to get out of the machine. By
default ports 80, 443, 22, 53, 67/68 and outbound pings are allowed so regular function can be allowed.
Anything extra such as 6667 for IRC must be entered here to be allowed out.

- Next is setting your interface names. You can check what yours are by issuing 'ifconfig' in your terminal

```
# Change accordingly to your interface naming scheme and the ones you are using.
ETH=eth0
WLAN=wlan0
TUN=tun0
```


How to use
===

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
