#!/usr/bin/env bash
# Written by: 			Daulton
# Website: 				https://daulton.ca
# Repository:			https://github.com/jeekkd
# Script repository: 	https://github.com/jeekkd/restricted-iptables
# Purpose: This is a companion script to restricted_iptables.sh to restore the old rules if necessary

########################################## VARIABLES ################################################
# Select location to restore iptables rules from. This must match what is set in the same variable in
# configuration.sh, so you are saving and restoring from the same directory. This is by default at /tmp.
restoreRulesDir=/tmp
#####################################################################################################

# control_c()
# Trap Ctrl-C for a quick exit when necessary
control_c() {
	echo "Control-c pressed - exiting NOW"
	exit 1
}

trap control_c SIGINT

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
		echo "https://github.com/jeekkd/restricted-iptables"
	fi
}

echo "Selected which rule set to restore by typing its corresponding number: "
ls /tmp | grep "iptables.rules" | cat -n
read answer
selected_rule=$(ls "$restoreRulesDir/" | grep "iptables.rules" | sed -n $answer\p)
echo
echo "This will restore the rule set: \"$selected_rule\". Are you sure? Y/N"
read answer
if [[ $answer == "Y" || $answer == "y" || $answer = "" ]]; then
	iptables-restore < "$restoreRulesDir"/$selected_rule
	if [ $? -eq 0 ]; then
		saveTables
		if [ $? -eq 0 ]; then
			echo
			echo "Restoration completed!"
		fi
	else
		echo
		echo "Error: iptables restoration failed. Investigate issue"
	fi
else
	echo
	echo "No selected, exiting now"
	exit
fi
