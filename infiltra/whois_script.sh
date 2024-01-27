#!/bin/bash

# ANSI color code for yellow
YELLOW='\033[1;33m'
# ANSI color code for no color
NC='\033[0m'

# Define output file name with date and time
output_file="whois_output_$(date +%Y-%m-%d_%H-%M-%S).txt"
not_found_messages=()

# Function to perform whois query and extract OrgName
perform_whois() {
    local ip=$1
    local org_name

    # Run whois and extract all occurrences of OrgName, using case-insensitive match and allowing for variable spaces
    mapfile -t org_names < <(whois "$ip" | grep -i "OrgName:" | sed -e 's/OrgName:[[:space:]]*//I')

    # Check if OrgName was found
    if [ ${#org_names[@]} -eq 0 ]; then
        not_found_messages+=("$ip - Org name not found, please verify manually.")
    else
        # Check for unique OrgNames
        local unique_org_name="${org_names[0]}"
        for name in "${org_names[@]:1}"; do
            if [ "$name" != "$unique_org_name" ]; then
                # If a new unique name is found, append it to the output
                unique_org_name+=", $name"
            fi
        done
        echo "$ip - $unique_org_name" | tee -a "$output_file"
    fi
}

# Function to validate IP address
is_valid_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # Basic regex match for an IP address
        return 0 # valid
    fi
    return 1 # invalid
}

# Process the input
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <file_with_ip_addresses or single IP>"
    exit 1
fi

input=$1

if [ -f "$input" ]; then
    # It's a file, process each line as an IP
    while IFS= read -r ip || [[ -n "$ip" ]]; do
        perform_whois "$ip"
    done < "$input"
elif is_valid_ip "$input"; then
    # It's a valid IP, process it
    perform_whois "$input"
else
    echo "Error: The argument is neither a valid IP address nor a file."
    exit 1
fi

# Print Org name not found messages in yellow
echo -e "\n"
for msg in "${not_found_messages[@]}"; do
    echo -e "${YELLOW}$msg${NC}" | tee -a "$output_file"
done
echo -e "\n"
echo -e "\033[32;1mWhois results saved to $output_file\033[0m"