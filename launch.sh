#!/usr/bin/env bash
# Written by: 			Daulton
# Website: 				https://daulton.ca
# Repository:			https://github.com/jeekkd
# Script repository: 	https://github.com/jeekkd/restricted-iptables
# This is the launch script for restricted-iptables. For additional information view the README or
# configuration.sh file.
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

# Save existing iptables rules before changing anything. restore_iptables.sh script can be used to 
# restore old rules if necessary - included in the repo.
if [ -f "/tmp/original-iptables.rules" ]; then
	iptables-save > "$saveRulesDir"/${todaysDate}-iptables.rules
	ip6tables-save > "$saveRulesDir"/${todaysDate}-ip6tables.rules
	whichRules=1
else 
	iptables-save > "$saveRulesDir"/original-iptables.rules
	ip6tables-save > "$saveRulesDir"/original-ip6tables.rules
	whichRules=0
fi

unshare -n -- sh -c "bash \"$script_dir\"/restricted-iptables.sh ; iptables-save > \"$saveRulesDir\"/${todaysDate}-unshare-iptables.rules ; ip6tables-save > \"$saveRulesDir\"/${todaysDate}-unshare-ip6tables.rules"
if [ $? -eq 0 ]; then
	iptables-restore < "$saveRulesDir"/${todaysDate}-unshare-iptables.rules
	ip6tables-restore < "$saveRulesDir"/${todaysDate}-unshare-ip6tables.rules
	if [ $? -eq 0 ]; then
		saveTables
		echo "Success: The new iptables rules have been applied"
	elif [ $? -gt 0 ]; then
		if [ $whichRules == 0 ]; then
			rulesToRestore="$saveRulesDir"/original-iptables.rules
			IPv6rulesToRestore="$saveRulesDir"/original-ip6tables.rules
		else
			rulesToRestore="$saveRulesDir"/${todaysDate}-iptables.rules
			IPv6rulesToRestore="$saveRulesDir"/${todaysDate}-ip6tables.rules
		fi	
		echo "Error: A non-zero exit code has occured attempting the apply the following rules: "
		echo "$saveRulesDir/${todaysDate}-unshare-iptables.rules."
		echo
		echo "Restoring previous ruleset of: "
		iptables-restore < $rulesToRestore
		ip6tables-restore < $IPv6rulesToRestore
		if [ $? -eq 0 ]; then
			saveTables
			echo "Success: The previous iptables rules have been re-applied"
		fi
	fi
fi

echo
read -t 30 -p "Press any key within 30 seconds to confirm that you still have connectivity... "
if (( $? >= 128 )); then
	echo
	echo "Error: No key press registered, connectivity must have been severed. Restoring previous"
	echo "set of rules."
	if [ $whichRules == 0 ]; then
		rulesToRestore="$saveRulesDir"/original-iptables.rules
		IPv6rulesToRestore="$saveRulesDir"/original-ip6tables.rules
	else
		rulesToRestore="$saveRulesDir"/${todaysDate}-iptables.rules
		IPv6rulesToRestore="$saveRulesDir"/${todaysDate}-ip6tables.rules
	fi	
	
	iptables-restore < $rulesToRestore
	ip6tables-restore < $IPv6rulesToRestore
	if [ $? -eq 0 ]; then
		saveTables
		echo "Success: The previous iptables rules have been re-applied"
	fi
fi
