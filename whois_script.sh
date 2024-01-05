#!/bin/bash

# Define output file name with date and time
output_file="whois_output_$(date +%Y-%m-%d_%H-%M-%S).txt"

# Function to perform whois query and extract OrgName
perform_whois() {
    local ip=$1
    local org_name

    # Check if the IP address is valid
    if ! [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$ip is not a valid IP address." | tee -a "$output_file"
        return 1
    fi

    # Run whois and extract OrgName
    org_name=$(whois "$ip" | grep -i "OrgName:" | awk -F": " '{print $2}')

    # Check if OrgName was found and output to file
    if [ -n "$org_name" ]; then
        echo "$ip - $org_name" | tee -a "$output_file"
    else
        echo "$ip - Org name not found" | tee -a "$output_file"
    fi
}

# Check if a file or single IP is provided as an argument
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <file_with_ip_addresses or single IP>"
    exit 1
fi

input=$1

# Check if the input is a file or a single IP
if [ -f "$input" ]; then
    # It's a file, read IPs one by one and output to file
    while IFS= read -r ip; do
        perform_whois "$ip"
    done < "$input"
elif [[ $input =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    # It's a single IP, output to file
    perform_whois "$input"
else
    echo "Error: The argument is neither a valid IP address nor a file."
    exit 1
fi

echo "Whois results saved to $output_file"
