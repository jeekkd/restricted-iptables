#!/usr/bin/env bash
# Written by: 			Daulton
# Website: 				https://daulton.ca
# Repository:			https://github.com/jeekkd
# Script repository: 	https://github.com/jeekkd/restricted-iptables
# Purpose: This is a companion script to restricted_iptables.sh to restore the old rules if necessary
####################################################################################################
#
# get_script_dir()
# Gets the directory the script is being ran from. To be used with the import() function
# so the configuration is imported from its absolute path
get_script_dir() {
	script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
}

# Leave here to get scripts running location
get_script_dir

# import()
# Important module(s) for the purpose of modularizing the script.
import() {
  module=$1
  . "$script_dir"/${module}.sh
}

import configuration
import functions

# Trap any ctrl+c and call control_c function provided through functions.sh
trap control_c SIGINT

####################################################################################################

echo "Selected which rule set to restore by typing its corresponding number: "
ls /tmp | grep "iptables.rules" | cat -n
read answer
selected_rule=$(ls "$saveRulesDir" | grep "iptables.rules" | sed -n $answer\p)
echo
echo "This will restore the rule set: \"$selected_rule\". Are you sure? Y/N"
read answer
if [[ $answer == "Y" || $answer == "y" || $answer = "" ]]; then
	iptables-restore < "$saveRulesDir"/$selected_rule
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
