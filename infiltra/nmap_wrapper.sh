#!/bin/bash
# nmap_wrapper.sh

# Set terminal title based on the type of scan
if [[ $1 == "tcp" ]]; then
    echo -ne "\033]0;NMAP TCP Scan\007"
elif [[ $1 == "udp" ]]; then
    echo -ne "\033]0;NMAP UDP Scan\007"
fi

# Run nmap with sudo and pass all the remaining arguments (skipping the first one)
sudo nmap "${@:2}"