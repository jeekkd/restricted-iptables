Purpose
===

This is a configurable iptables firewall script, meant to make firewalls easier. 

Extended purpose
===

This script will stop most UDP Floods, SYN Floods, TCP Floods, Handshake Exploits, XMAS Packets, 
Smurf Attacks, ICMP Bombs, LAND attacks and RST Floods. Additionally types of connections that are 
allowed in or out over a particular port etc is restricted to the following, operating in a default 
deny for all input, output, and forwarding tables:  

* Denies all uninitiated ipv4 inbound connections except for torrents (if desired) so peers can connect
* Denies all uninitiated ipv6 inbound connections
* Drops inbound pings, allows outbound for both ipv4 and ipv6
* Allows established connections inbound on ports 67/68, 80, 53, 443, 1994/1995 but NOT new connections
coming inbound
* Allows new and established outbound connections for both ipv4 and ipv6          

Additonal ports that might be required such as 6667 for IRC can be opened selectively for either or both
inbound and outbound, this can be done in the opening ports section of configuration.sh. Additionally 
opening ranges of ports is possible.

All sorts of knobs are available in configuration.sh for enabling or disabling various parts of the
script. Not everything is mentioned here, so if you are curious I suggest taking a look in configuration.sh
to see what is available.

> **Note:** 
> This script is originally intended to be a restricted firewall, operating in a default deny sort of
> manner where it is very locked down. Since the beginning it has been expanded, allowing default policies
> and variables changed as the user desires through the options given. This allows you to suit the firewall
> to your needs better.
>
> This script requires you to fill out the variables in configuration.sh to your preference before running
> it. Otherwise it will not work as it is missing information is requires to properly set the firewall.

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

Within configuration.sh there are variables which must be filled out, this requires a little bit of 
configuration to adjust it to your specific needs. Each section is thoroughly commented so read them 
at each step and you will not have any issues.


How to use
===

- Lets get the source

```
git clone https://github.com/jeekkd/restricted-iptables.git && cd restricted-iptables
```

- This will make the scripts readable, writable, and executable to root and your user. 

```
chmod 770 *.sh
```

- Open the configuration.sh script in your text editor of choice. You need to read each section and fill it out accordingly

```
gedit configuration.sh
```

- Make sure you've saved, then launch the main script by doing the following:

```
sudo bash launch.sh
```

> **Note:** 
> Make sure you have installed the 'iptables' package for your distribution and if your distribution
> such as Gentoo requires you to configure your own kernel [assure that the various iptables kernel 
modules are enabled](https://wiki.gentoo.org/wiki/Iptables)

Restoring previous rules
===

By default before each time the script is ran your existing rules are saved. There is a companion script 
called 'restore_iptables.sh' that will restore your iptables rules back to those before the new rules were 
set. It saves an original copy of your rules the first time the script is ran, so long as that file exists 
still it will create time and date stamped rules files each time after to give you a selection of which point 
in time to restore your rules to.

- To restore your old rules launch the script as such and follow the prompts

```
sudo bash restore-iptables.sh
```


> **Note:** 
> Rules are stored in /tmp by default, /tmp is cleaned automatically so if you wish to keep your rules 
> permanently you can either change the location the script uses (This is possible near the bottom of 
configuration.sh) or manually save by doing the following:
>
> Saving:
> ```
 iptables-save > /path/to/rules/example.rules
>
>```
> Restoring:
> ```
 iptables-restore < /path/to/rules/example.rules
> ```
> For your specific distribution you will want to search how to permanently save your rules. 
>
