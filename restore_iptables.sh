#!/bin/bash

# Written by: https://github.com/turkgrb
# Website: https://daulton.ca
# Purpose: This is a companion script to restricted_iptables.sh to restore the old rules if necessary

echo "Selected which rules you'd like to restore by typing its corressponding number"
ls /tmp | grep "iptables.rules" | cat -n
read answer
selected_rule=$(ls /tmp | grep "iptables.rules" | sed -n $answer\p)

echo "This will restore your iptables rules. Are you sure? Y/N"
read answer
if [[ $answer == "Y" || $answer == "y" || $answer = "" ]]; then
	iptables-restore < /tmp/$selected_rule
	if [ $? -eq 0 ]; then	
		echo "Complete! Restoration done"
	else
		echo "Error: iptables restoration failed. Investigate issue, start by issuing iptables -L"
	fi
else
	echo "No selected, exiting now"
	exit
fi
