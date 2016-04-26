#!/bin/bash

# Written by: https://github.com/turkgrb
# Website: https://daulton.ca
# Purpose: This is a companion script to restricted_iptables.sh to restore the old rules if necessary

echo "Selected which rules you'd like to restore by typing its corresponding number"
ls /tmp | grep "iptables.rules" | cat -n
read answer
selected_rule=$(ls /tmp | grep "iptables.rules" | sed -n $answer\p)

echo "This will restore the rule set: \"$selected_rule\". Are you sure? Y/N"
read answer
if [[ $answer == "Y" || $answer == "y" || $answer = "" ]]; then
	iptables-restore < /tmp/$selected_rule
	/etc/init.d/iptables save
	/etc/init.d/ip6tables save
	if [ $? -eq 0 ]; then	
		echo "Restoration completed!"
	else
		echo "Error: iptables restoration failed. Investigate issue"
	fi
else
	echo "No selected, exiting now"
	exit
fi
