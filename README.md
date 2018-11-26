Purpose
===

This is a configurable iptables firewall script, meant to make firewalls easier. 

All sorts of knobs are available in configuration.sh for enabling or disabling various parts of the
script. If you are curious what is available I suggest taking a look in configuration.sh to see, there 
is a fair amount you can do.

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

After the configuration.sh file is set with your configuration, this is what running launch.sh
looks like

![daulton.ca](https://daulton.ca/images/bash-script-screenshots/iptables-00.png)

If your rule changes sever your connection, say you were on SSH but forgot to allow it, automatically
your most recent rules will be re-applied.

![daulton.ca](https://daulton.ca/images/bash-script-screenshots/iptables-02.png)

By default before each time launch.sh is ran your existing rules are saved. There is a companion script 
called 'restore-iptables.sh' that will restore your iptables rules back to those before the new rules were 
set. It saves an original copy of your rules the first time the script is ran, so long as that file exists 
still it will create time and date stamped rules files each time after to give you a selection of which 
point in time to restore your rules to.

![daulton.ca](https://daulton.ca/images/bash-script-screenshots/iptables-01.png)

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

- This will make the scripts readable, writable, and executable to root and your user

```
chmod 770 *.sh
```

- Open the configuration.sh script in your text editor of choice. You need to read each section and fill it out accordingly

```
gedit configuration.sh
```

- Make sure you've saved, then launch the main script by doing the following

```
sudo bash launch.sh
```

> **Note:** 
> Make sure you have installed the 'iptables' package for your distribution and if your distribution
> such as Gentoo requires you to configure your own kernel [assure that the various iptables kernel 
modules are enabled](https://wiki.gentoo.org/wiki/Iptables)

Restoring previous rules
===

- To restore your old rules launch restore-iptables.sh as such and follow the prompts

```
sudo bash restore-iptables.sh
```


> **Note:** 
> Rules are stored in /tmp by default, /tmp is cleaned automatically so if you wish to keep your rules 
> permanently you can either change the location the script uses (This is possible near the bottom of 
configuration.sh) or manually save by doing the following:
>
> Saving:
>```
> iptables-save > /path/to/rules/example.rules
>
>```
> Restoring:
>```
> iptables-restore < /path/to/rules/example.rules
>```
>
>For your specific distribution you will want to search how to permanently save your rules. 

