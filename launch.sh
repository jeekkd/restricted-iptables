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
else 
	iptables-save > "$saveRulesDir"/original-iptables.rules
fi

unshare -n -- sh -c "bash \"$script_dir\"/restricted_iptables.sh ; iptables-save > \"$saveRulesDir\"/${todaysDate}-unshare-iptables.rules"
if [ $? -eq 0 ]; then
	iptables-restore < "$saveRulesDir"/${todaysDate}-unshare-iptables.rules
	if [ $? -eq 0 ]; then
		saveTables
		echo "Success: The new iptables rules have been applied"
	else
		echo "Error: A non-zero exit code has occured attempting the restore the following rules: "
		echo "\"$saveRulesDir\"/${todaysDate}-unshare-iptables.rules"
	fi
fi
