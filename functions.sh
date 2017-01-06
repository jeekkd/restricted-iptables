#!/usr/bin/env bash
# Written by: 			Daulton
# Website: 				https://daulton.ca
# Repository:			https://github.com/jeekkd
# Script repository: 	https://github.com/jeekkd/restricted-iptables
# This is the functions file for restricted-iptables. For additional information view the README or
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

# control_c()
# Trap Ctrl-C for a quick exit when necessary
control_c() {
	echo "Control-c pressed - exiting NOW"
	exit 1
}

# saveTables()
# Modified function from below, purpose is to detect which distribution is running so
# the rules may be saved in a way for each distribution as to work on a wider range of
# systems rather then just Gentoo.
# From: https://danielgibbs.co.uk/2013/04/bash-how-to-detect-os/
saveTables(){
	arch=$(uname -m)
	kernel=$(uname -r)
	voidLinux=$(cat /proc/version | cut -d " " -f 4)
	ubuntuLinux=$(cat /etc/lsb-release | head -n 1 | cut -d = -f 2)
	if [ "$ubuntuLinux" == "Ubuntu" ]; then
		echo "To easily manage iptables a new package named iptables-services must be installed. Proceed? Y/N"
		read -r packageAnswer
		if [[ $packageAnswer == "Y" || $packageAnswer == "y" ]]; then
			apt-get update
			apt-get install iptables-persistent
			echo
			echo " * Saving all iptables settings"
			/etc/init.d/iptables-persistent save
		fi
	elif [ -f /etc/debian_version ]; then
		echo " * Saving all iptables settings"
		mkdir /etc/iptables
		iptables-save > /etc/iptables/rules.v4
		ip6tables-save > /etc/iptables/rules.v6
		iptables-restore < /etc/iptables/rules.v4
		ip6tables-restore < /etc/iptables/rules.v6
	elif [ -f /etc/arch-release ]; then	
		echo " * Saving all iptables settings"
		iptables-save > /etc/iptables/iptables.rules
		ip6tables-save > /etc/iptables/ip6tables.rules
		echo "Enable iptables at boot and start service? Y/N"
		read -r systemdAnswer
		if [[ $systemdAnswer == "Y" || $systemdAnswer == "y" ]]; then
			echo "User entered: $systemdAnswer - enabling and starting iptables services"
			systemctl enable iptables.service
			systemctl enable ip6tables.service
			systemctl start iptables.service
			systemctl start ip6tables.service
		else
			echo "Skipping starting and enabling iptables systemd units"
		fi
	elif [ -f /etc/redhat-release ]; then
		echo " * Saving all iptables settings"
		echo "To easily manage iptables a new package named iptables-services must be installed. Proceed? Y/N"
		read -r packageAnswer
		if [[ $packageAnswer == "Y" || $packageAnswer == "y" ]]; then
			echo
			yum install -y iptables-services
		fi
		echo
		systemctl enable ip6tables
		systemctl enable iptables
		systemctl start iptables
		systemctl start ip6tables
		service iptables save
		service ip6tables save
		echo
		echo "It is necessary to disable firewalld if using iptables. Proceed? Y/N"
		read -r firewallAnswer
		if [[ $firewallAnswer == "Y" || $firewallAnswer == "y" ]]; then
			echo "User entered: $firewallAnswer - Disabling firewalld"
			systemctl stop firewalld
			systemctl mask firewalld
		fi
	elif [ "$voidLinux" == "(xbps-builder@build.voidlinux.eu)" ]; then
		echo " * Saving all iptables settings"
		iptables-save > /etc/iptables/iptables.rules
		ip6tables-save > /etc/iptables/ip6tables.rules
	elif [ -f /etc/lsb-release ] || [ -f /etc/gentoo-release ]; then
		echo " * Saving all iptables settings"
		/etc/init.d/iptables save
		/etc/init.d/ip6tables save
	else
		echo "Warning: Your distribution was unable to be detected which means the"
		echo "iptables rules are unable to be automatically saved and made persistent."
		echo "You will need to search of how to save them for your distribution." 
		echo
		echo "Please report this error! remember to include which distribution you are using"
		echo "https://github.com/jeekkd/restricted-iptables"
	fi
}

# get_script_dir()
# Gets the directory the script is being ran from. To be used with the import() function
# so the configuration is imported from its absolute path
get_script_dir() {
	script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
}

# remTrailingSlash()
# Remove trailing forward slashes ex: fixedDir=$(rem_trailing_slash $Dir)
remTrailingSlash() {
    echo $1 | sed 's/\/*$//g'
}

# Set the date and time in a standard format for use through out the script
todaysDate=$( date +%H%M-%b-%d-%Y)

# Remove any trailing forward slash from saveRulesDir that is set in configuration.sh
saveRulesDir=$(remTrailingSlash "$saveRulesDir")

# fixCase()
# Convert the contents of all important variables from lower to upper case to assure
# the variables are upper case which is required for iptables table names
fixCase() {
	inputPolicy=$(echo "$inputPolicy" | tr '[:lower:]' '[:upper:]')
	outputPolicy=$(echo "$outputPolicy" | tr '[:lower:]' '[:upper:]')
	forwardPolicy=$(echo "$forwardPolicy" | tr '[:lower:]' '[:upper:]')
	ipv6InputPolicy=$(echo "$ipv6InputPolicy" | tr '[:lower:]' '[:upper:]')
	ipv6OutputPolicy=$(echo "$ipv6OutputPolicy" | tr '[:lower:]' '[:upper:]')
	ipv6ForwardPolicy=$(echo "$ipv6ForwardPolicy" | tr '[:lower:]' '[:upper:]')
}

# Trap any ctrl+c and call control_c function provided through functions.sh
trap control_c SIGINT
