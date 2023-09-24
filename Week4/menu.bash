#!/bin/bash

# Storyline: Menu for admin, VPN, and security functions

function invalid_opt() {

	echo ""
	echo "Invalid option!"
	echo ""
	sleep 2

}

function menu() {

	# Clears the screen
	clear

	echo "[1] Admin Menu"
	echo "[2} Security Menu"
	echo "[3] Exit"
	read -p "Please enter a choice above: " choice

	case "$choice" in
		1) admin_menu
		;;
		2) security_menu
		;;
		3) exit 0
		;;
		*)
			invalid_opt

			# Call the main menu
			menu

		;;
	esac
}

function admin_menu() {

	clear
	echo "[L]ist Running Processes"
	echo "[N]etwork Sockets"
	echo "[V]PN Menu"
	echo "[B]lock List Menu"
	echo "[4] Exit"
	read -p "Please enter a choice above: " choice

	case "$choice" in

		L|l) ps -ef |less
		;;
		N|n) netstat -an --inet|less
		;;
		V|v) vpn_menu
		;;
		B|b) block_list_menu
		;;
		4) exit 0
		;;

		*)
			invalid_opt
			admin_menu
		;;
	esac
admin_menu
}

function vpn_menu() {

	clear
	echo "[A]dd a peer"
	echo "[D]elete a peer"
	echo "[C]heck if peer exists"
	echo "[B]ack to main menu"
	echo "[M]ain menu"
	echo "[E]xit"
	read -p "Please select an option: " choice

	case "$choice" in

		A|a)
			bash peer.bash
		;;
		D|d)
			read -p "Which user would you like to delete?" user
			bash manage-users.bash -d -u ${user}
			read -p "Press any button to continue: " response
		;;
		C|c)
			read -p "Which user would you like to check?" user
			bash manage-users.bash -c -u ${user}
			read -p "Press any button to continue:" response
		;;
		B|b) admin_menu
		;;
		M|m) menu
		;;
		E|e) exit 0
		;;
		*)
			invalid_opt
			vpn_menu
		;;

	esac
vpn_menu
}

function security_menu() {

	clear
	echo "[N]etwork Sockets"
	echo "[R]oot UID check"
	echo "[L]ast 10 users"
	echo "[C]urrent user(s)"
	echo "[M]ain menu"
	echo "[E]xit"
	read -p "Please select an option: " choice

	case "$choice" in

		N|n) netstat -an --inet|less
		;;
		R|r)

		if [[ "$(cut -d: -f1,3 /etc/passwd | grep -v "root:0" | grep ":0")" != "" ]]
		then

			echo "User other than root with UID 0 found"

		else

			echo "No user besides root has UID 0."

		fi

		read -p "Press any button to continue: " response
		;;
		L|l) last -n 10 |less
		;;
		C|c) who |less
		;;
		M|m) menu
		;;
		E|e) exit 0
		;;
		*)
			invalid_opt
			security_menu
		;;

	esac
security_menu
}


function block_list_menu() {
	clear
	echo "[I]ptables"
	echo "[C]isco"
	echo "[W]indows firewall"
	echo "[M]ac OS"
	echo "[P]arse Cisco"
	echo "[E]xit to admin menu"
	read -p "Please enter a choice above: " choice

	case "$choice" in
		I|i) bash parse-threat.bash -i
		;;
		C|c) bash parse-threat.bash -c
		;;
		W|w) bash parse-threat.bash -w
		;;
		M|m) bash parse-threat.bash -m
		;;
		P|p) bash parse-threat.bash -p
		;;
		E|e) admin_menu
		;;
		*)
			invalid_opt
			block_list_menu
		;;
	esac
block_list_menu
}

# Call the main function
menu
