#!/bin/bash

# Written by: https://github.com/turkgrb
# Website: https://daulton.ca
# Purpose: This is a companion script to restricted_iptables.sh to restore the old rules if necessary

# fn_distro()
# Modified function from below, purpose is to detect which distribution is running so
# the rules may be saved in a way for each distribution as to work on a wider range of
# systems rather then just Gentoo.
# From: https://danielgibbs.co.uk/2013/04/bash-how-to-detect-os/
fn_distro(){
	arch=$(uname -m)
	kernel=$(uname -r)
	if [ -f /etc/lsb-release ]; then
		echo " * Saving all settings"
		/etc/init.d/iptables save
		/etc/init.d/ip6tables save
	elif [ -f /etc/debian_version ]; then
		echo " * Saving all settings"
		iptables-save > /etc/iptables/rules.v4
		ip6tables-save > /etc/iptables/rules.v6
	elif [ -f /etc/redhat-release ]; then
		echo " * Saving all settings"
		iptables-save > /etc/sysconfig/iptables
		ip6tables-save > /etc/sysconfig/ip6tables
	else
		echo "Warning: Your distribution was unable to be detected which means the"
		echo "iptables rules are unable to be automatically saved and made persistent."
		echo "You will need to search of how to save them for your distribution." 
		echo
		echo "Please report this error! Include which distribution you are using"
	fi
}

echo "Selected which rules you'd like to restore by typing its corresponding number"
ls /tmp | grep "iptables.rules" | cat -n
read answer
selected_rule=$(ls /tmp | grep "iptables.rules" | sed -n $answer\p)

echo "This will restore the rule set: \"$selected_rule\". Are you sure? Y/N"
read answer
if [[ $answer == "Y" || $answer == "y" || $answer = "" ]]; then
	iptables-restore < /tmp/$selected_rule
	if [ $? -eq 0 ]; then
		fn_distro
		if [ $? -eq 0 ]; then
			echo "Restoration completed!"
		fi
	else
		echo "Error: iptables restoration failed. Investigate issue"
	fi
else
	echo "No selected, exiting now"
	exit
fi
