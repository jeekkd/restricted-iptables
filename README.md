Purpose
===

This script will stop most port scanning attempts, UDP Floods, SYN Floods, TCP Floods, 
Handshake Exploits, XMAS Packets, Smurf Attacks, ICMP Bombs, LAND attacks and RST Floods. 

Additionally types of connections that are allowed in or out over a particular port etc is 
restricted to the following, operating in a default deny for all input, output, and forwarding tables:  

- Denies all uninitiated ipv4 inbound connections except for torrents (if desired) so peers can connect
- Denies all uninitiated ipv6 inbound connections
- Drops inbound pings (if desired), allows outbound for both ipv4 and ipv6
- Allows established connections inbound on ports 67/68, 80, 53, 443, 1994/1995 but NOT new connections
coming inbound
- Allows new and established outbound connections for both ipv4 and ipv6

Additonal ports that might be required such as 6667 for IRC can be added, in the variables section
below I will make examples to make adding new ports for inbound and/or outbound connections easier.

> **Note:** 
> This script requires some tuning to be optimized for a least privledge sort of policy where things
> work and are locked down. Don't expect to run this and be done, you'll need to continue reading and fill
> things out for your specific system

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

- The following is askin the default behavior for each chain, you may enter drop, reject, or accept here

```
# What should the default input policy for ipv4 be? DROP, REJECT, or ACCEPT?
inputPolicy=DROP
# What should the default out policy for ipv4 be? DROP, REJECT, or ACCEPT?
outputPolicy=ACCEPT
# What should the default forwarding policy for ipv4 be? DROP, REJECT, or ACCEPT?
forwardPolicy=DROP
```

- The next bit consists of two arrays, they are for different inbound/output and connection states. These
are each enabled by their corresponding enable option by typing YES/NO where asked.

The first is for allowing new inbound connections over a specific port. An example of this is allowing
someone to SSH into your machine. So you might enter port 22 in this section to allow that through

The second, this is allowing outbound new and established connections to get out of the machine. By
default ports 80, 443, 22, 53, 67/68 and outbound pings are allowed so regular function can be allowed.
Anything extra such as 6667 for IRC must be entered here to be allowed out. 

Additionally, ports entered in this array are entered into the input chain to allow established and related 
connections back in on that port. This is required as the connections would otherwise be DROPPED or REJECTED
by the input policy by default behavior.

- In the event you changed your default ports or use a different torrent client then transmission etc
you may change some default ports in this section

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
