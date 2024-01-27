#!/bin/bash
# nmap-grep.sh
# Script for parsing and splitting grepable nmap output files
# Created by Ted Raffle and improvements made by Bobby Methiven

# Set these variables to 'Y' to always perform the action
varShowSummary="Y"
varShowPortList="Y"

# Use the first argument as the scan type
varScanType=$2  # Assuming $1 is the output file
if [ "$varScanType" == "TCP" ]; then
    varOutPath="tcp_parsed/"
elif [ "$varScanType" == "UDP" ]; then
    varOutPath="udp_parsed/"
else
    echo "Invalid scan type provided. Please use TCP or UDP."
    exit 1
fi

varTempRandom=$(( ( RANDOM % 9999 ) + 1 ))
varTempFile="temp-nmp-$varTempRandom.txt"
if [ -f "$varTempFile" ]; then rm $varTempFile; fi
varDateCreated="12/28/2015"
varDateLastMod="1/1/2016"
varDoSummary="Y"
varDoSplit="Y"
varRenameSplit="Y"
varDoWebUrl="Y"
varDoSmbUrl="Y"
varDoLiveHosts="Y"
varInFile="notset"
# varYMDHMS=$(date +%F-%H-%M-%S)
varChangeOutDir="N"
varCustomOut=""
varFlagOutExists="N"

# Function for providing help/usage text
function usage
{
  echo
  echo "===========[ nmap-grep.sh ]==========="
  echo
  echo "Parse grepable Nmap output files to create (by default):"
  echo "- A summary of hosts and their open ports."
  echo "- Split *-hosts.txt files for each open port."
  echo "- Name split files for common services instead of port numbers."
  echo "- Create web-urls.txt and smb-urls.txt as applicable."
  echo "- List hosts reported as 'up'."
  echo  
  echo "Created $varDateCreated, last modified $varDateLastMod."
  echo
  echo "============================[ usage ]============================"
  echo
  echo "./nmap-grep.sh [input file] [options]"
  echo
  echo "[input file]      Your grepable nmap file."
  echo
  echo "--out-dir [path]  Set a custom output directory."
  echo "                  Default is nmap-grep-YYYY-MM-DD-HH-MM-SS/"
  echo "                  Directory will be created if it does not exist."
  echo "                  Use . to output to the current directory."
  echo "                  Ex: --out-dir /tasks/client/"
  echo "                  Ex: --out-dir . "
  echo
  echo "--no-summary      Do not create summary output."
  echo
  echo "--no-split        Do not split open ports into *-hosts.txt files."
  echo
  echo "--no-label-split  Leave split hosts files named for port numbers."
  echo "                  By default, known ports will use service names."
  echo "                  Ex: ftp-hosts.txt instead of 21-tcp-hosts.txt."
  echo
  echo "--no-web-urls     Don't create web-urls.txt."
  echo "                  By default, URLs will be created for ports 80,"
  echo "                   443, 8080, and 8443."
  echo
  echo "--no-smb-urls     Don't create smb-urls.txt."
  echo
  echo "--no-up           Don't create up-hosts.txt"
  echo
  exit
}

# Start script

# Check for input file as first parameter, error if it doesn't exist as a file
varInFile="$1"
if [ ! -f "$varInFile" ]; then echo; echo "Error: Input file doesn't exist."; usage; exit; fi

# Check for options
while [ "$1" != "" ]; do
  case $1 in
    --no-summary ) varDoSummary="N"
         ;;
    --no-split ) varDoSplit="N"
         varRenameSplit="N"
         ;;
    --no-label-split ) varRenameSplit="N"
         ;;
    --out-dir ) shift 
         varChangeOutDir="Y"
         varCustomOut=$1
         ;;
    --no-web-urls ) varDoWebUrl="N"
         ;;
    --no-smb-urls ) varDoSmbUrl="N"
         ;;
    --no-up ) varDoLiveHosts="N"
         ;;
    -h ) usage
         exit
         ;;
  esac
  shift
done

# Check output parameters
if [ "$varChangeOutDir" = "N" ]; then
  # varOutPath="nmap-grep-$varYMDHMS/"
# If the default output path is used, make sure it doesn't exist
  if [ -e "$varOutPath" ]; then
    echo; echo "Error: $varOutPath exists."; usage; exit
  else
    mkdir $varOutPath
  fi
else
# If a custom output path is used, first check for "."
  if [ "$varChangeOutDir" = "Y" ] && [ "$varCustomOut" = "." ]; then
    varOutPath=""
  elif [ "$varChangeOutDir" = "Y" ] && [ "$varCustomOut" != "." ] && [ "$varCustomOut" != "" ]; then
# Add dir if it doesn't exist, error if it isn't a directory
    if [ ! -d "$varCustomOut" ] && [ -e "$varCustomOut" ]; then echo; echo "Error: $varCustomOut isn't a directory."; usage; exit; fi
    if [ ! -e "$varCustomOut" ]; then
      mkdir "$varCustomOut"
    else
      varFlagOutExists="Y"
    fi
# Add trailing slash to end of varOutPath if it isn't on varCustomOut
    varCheckTrailingSlash=$(echo "$varCustomOut" | grep '/$')
    if [ "$varCheckTrailingSlash" != "" ]; then
      varOutPath=$varCustomOut
    else
      varOutPath="${varCustomOut}/"
    fi    
  fi
fi

#echo
#echo "===========[ nmap-grep.sh ]==========="
#echo
#echo "Input File: $varInFile"
#if [ "$varOutPath" != "" ]; then echo "Output Path: $varOutPath"; fi
#if [ "$varOutPath" = "" ]; then echo "Output Path: Current Directory"; fi
#echo
#echo "Functions:"
#if [ "$varDoLiveHosts" = "Y" ]; then echo "- Create up-hosts.txt"; fi
#if [ "$varDoSummary" = "Y" ]; then echo "- Create summary.txt"; fi
#if [ "$varDoSplit" = "Y" ]; then echo "- Create [port]-[tcp/udp]-hosts.txt for each open port"; fi
#if [ "$varRenameSplit" = "Y" ]; then echo "- Rename split hosts files for common services"; fi
#if [ "$varDoWebUrl" = "Y" ]; then echo "- Create web-urls.txt"; fi
#if [ "$varDoSmbUrl" = "Y" ]; then echo "- Create smb-urls.txt"; fi
#echo
#if [ "$varFlagOutExists" = "Y" ]; then echo "Note: $varOutPath already existed. Files may be appended."; echo; fi
# Automatic overwrite confirmation
if [ -e "$varOutPath" ]; then
  echo "The directory $varOutPath already exists. Overwriting..."
  rm -r "$varOutPath"
fi
mkdir -p "$varOutPath"

# ...

# Remove the confirmation prompts
# read -p "Press Enter to confirm..." is removed
#echo
#echo "===========================[ results ]==========================="

# Read input file for up-hosts.txt
if [ "$varDoLiveHosts" = "Y" ]; then
  varLine=""
  varLastIP=""
  while read varLine; do
    varOutIP=""
    varOutIP=$(echo $varLine | grep 'Status: Up' | awk '{print $2}')
    if [ "$varOutIP" != "" ] && [ "$varOutIP" != "$varLastIP" ]; then echo "$varOutIP" >> ${varOutPath}up-hosts.txt; varLastIP=$varOutIP; fi
  done < $varInFile
fi

# Process each comma-separated open port result to the CSV temp file, with the host IP
varLine=""
while read varLine; do
  varCheckForOpen=""
  varCheckForOpen=$(echo $varLine | grep '/open/')
  if [ "$varCheckForOpen" != "" ]; then
    varLineHost=$(echo $varLine | awk '{print $2}')
    varLinePorts=$(echo $varLine | awk '{$1=$2=$3=$4=""; print $0}')
# Create temporary file to write each port result for this host
      varTempRandom2=$(( ( RANDOM % 9999 ) + 1 ))
      varTempFile2="temp-nmp2-$varTempRandom2.txt"
      if [ -f "$varTempFile2" ]; then rm $varTempFile2; fi
      echo "$varLinePorts" | tr "," "\n" | sed 's/^ *//g' >> $varOutPath$varTempFile2
# Read the per-host temp file to write each open port as a line to the CSV temp file
    while read varTempLine; do
      varCheckForOpen=""
      varCheckForOpen=$(echo $varTempLine | grep "/open/")
      if [ "$varCheckForOpen" != "" ]; then
        varLinePort=$(echo $varTempLine | awk -F '/' '{print $1}')
        varLineTCPUDP=$(echo $varTempLine | awk -F '/' '{print $3}')
        varLineProto=$(echo $varTempLine | awk -F '/' '{print $5}')
        varLineSvc=$(echo $varTempLine | awk -F '/' '{print $7}')
        echo "$varLineHost,$varLinePort,$varLineTCPUDP,$varLineProto,$varLineSvc" >> $varOutPath$varTempFile
      fi
    done < $varOutPath$varTempFile2
    rm $varOutPath$varTempFile2
  fi
done < $varInFile

mv $varOutPath$varTempFile ${varOutPath}unsorted.txt
cat ${varOutPath}unsorted.txt | sort -V | uniq > $varOutPath$varTempFile
rm ${varOutPath}unsorted.txt

# Create summary file
if [ "$varDoSummary" = "Y" ] && [ -e "$varOutPath$varTempFile" ]; then
  echo "+------------------+--------------+-----------------------------------------------------+" >> ${varOutPath}summary.txt
  printf "%-18s %-14s %-52.52s %-2s \n" "| HOST " "| OPEN PORT " "| PROTOCOL - SERVICE" " |" >> ${varOutPath}summary.txt
  varLastHost=""
  while read varLine; do
    varLineHost=""
    varLinePort=""
    varLineTCPUDP=""
    varLineProto=""
    varLineSvc=""
    varLineHost=$(echo $varLine | awk -F ',' '{print $1}')
    varLinePort=$(echo $varLine | awk -F ',' '{print $2}')
    varLineTCPUDP=$(echo $varLine | awk -F ',' '{print $3}')
    varLineProto=$(echo $varLine | awk -F ',' '{print $4}')
    varLineSvc=$(echo $varLine | awk -F ',' '{print $5}')
    if [ "$varLineHost" != "$varLastHost" ]; then echo "+------------------+--------------+-----------------------------------------------------+" >> ${varOutPath}summary.txt; fi
    if [ "$varLineSvc" = "" ]; then
      varLineSvc=""
    else
      varLineSvc="- $varLineSvc"
    fi
    printf "%-18s %-14s %-52.52s %-2s \n" "| $varLineHost " "| $varLinePort / $varLineTCPUDP " "| $varLineProto $varLineSvc" " |" >> ${varOutPath}summary.txt
    varLastHost="$varLineHost"
  done < $varOutPath$varTempFile
  echo "+------------------+--------------+-----------------------------------------------------+" >> ${varOutPath}summary.txt
fi

# Create split hosts files for each protocol
if [ "$varDoSplit" = "Y" ]; then
  while read varLine; do
    varLineHost=""
    varLinePort=""
    varLineTCPUDP=""
    varLineHost=$(echo $varLine | awk -F ',' '{print $1}')
    varLinePort=$(echo $varLine | awk -F ',' '{print $2}')
    varLineTCPUDP=$(echo $varLine | awk -F ',' '{print $3}')
    echo $varLineHost >> $varOutPath${varLinePort}-${varLineTCPUDP}-hosts.txt
  done < $varOutPath$varTempFile
fi

# Rename hosts files for common protocols
if [ "$varRenameSplit" = "Y" ]; then
  if [ -f "${varOutPath}21-tcp-hosts.txt" ]; then mv ${varOutPath}21-tcp-hosts.txt ${varOutPath}ftp-hosts.txt; fi
  if [ -f "${varOutPath}22-tcp-hosts.txt" ]; then mv ${varOutPath}22-tcp-hosts.txt ${varOutPath}ssh-hosts.txt; fi
  if [ -f "${varOutPath}23-tcp-hosts.txt" ]; then mv ${varOutPath}23-tcp-hosts.txt ${varOutPath}telnet-hosts.txt; fi
  if [ -f "${varOutPath}25-tcp-hosts.txt" ]; then mv ${varOutPath}25-tcp-hosts.txt ${varOutPath}smtp-hosts.txt; fi
  if [ -f "${varOutPath}53-tcp-hosts.txt" ]; then mv ${varOutPath}53-tcp-hosts.txt ${varOutPath}dns-tcp-hosts.txt; fi
  if [ -f "${varOutPath}53-udp-hosts.txt" ]; then mv ${varOutPath}53-udp-hosts.txt ${varOutPath}dns-udp-hosts.txt; fi
  if [ -f "${varOutPath}69-udp-hosts.txt" ]; then mv ${varOutPath}69-udp-hosts.txt ${varOutPath}tftp-hosts.txt; fi
  if [ -f "${varOutPath}80-tcp-hosts.txt" ]; then mv ${varOutPath}80-tcp-hosts.txt ${varOutPath}http-hosts.txt; fi
  if [ -f "${varOutPath}110-tcp-hosts.txt" ]; then mv ${varOutPath}110-tcp-hosts.txt ${varOutPath}pop3-hosts.txt; fi
  if [ -f "${varOutPath}123-udp-hosts.txt" ]; then mv ${varOutPath}123-udp-hosts.txt ${varOutPath}ntp-hosts.txt; fi
  if [ -f "${varOutPath}143-tcp-hosts.txt" ]; then mv ${varOutPath}143-tcp-hosts.txt ${varOutPath}imap-hosts.txt; fi
  if [ -f "${varOutPath}161-udp-hosts.txt" ]; then mv ${varOutPath}161-udp-hosts.txt ${varOutPath}snmp-hosts.txt; fi
  if [ -f "${varOutPath}162-udp-hosts.txt" ]; then mv ${varOutPath}162-udp-hosts.txt ${varOutPath}snmptrap-hosts.txt; fi
  if [ -f "${varOutPath}179-tcp-hosts.txt" ]; then mv ${varOutPath}179-tcp-hosts.txt ${varOutPath}bgp-hosts.txt; fi
  if [ -f "${varOutPath}389-tcp-hosts.txt" ]; then mv ${varOutPath}389-tcp-hosts.txt ${varOutPath}ldap-hosts.txt; fi
  if [ -f "${varOutPath}443-tcp-hosts.txt" ]; then mv ${varOutPath}443-tcp-hosts.txt ${varOutPath}https-hosts.txt; fi
  if [ -f "${varOutPath}445-tcp-hosts.txt" ]; then mv ${varOutPath}445-tcp-hosts.txt ${varOutPath}smb-hosts.txt; fi
  if [ -f "${varOutPath}465-tcp-hosts.txt" ]; then mv ${varOutPath}465-tcp-hosts.txt ${varOutPath}smtps-hosts.txt; fi
  if [ -f "${varOutPath}500-udp-hosts.txt" ]; then mv ${varOutPath}500-udp-hosts.txt ${varOutPath}ike-hosts.txt; fi
  if [ -f "${varOutPath}513-tcp-hosts.txt" ]; then mv ${varOutPath}513-tcp-hosts.txt ${varOutPath}rlogin-hosts.txt; fi
  if [ -f "${varOutPath}514-tcp-hosts.txt" ]; then mv ${varOutPath}514-tcp-hosts.txt ${varOutPath}remoteshell-hosts.txt; fi
  if [ -f "${varOutPath}636-tcp-hosts.txt" ]; then mv ${varOutPath}636-tcp-hosts.txt ${varOutPath}ldaps-hosts.txt; fi
  if [ -f "${varOutPath}873-tcp-hosts.txt" ]; then mv ${varOutPath}873-tcp-hosts.txt ${varOutPath}rsync-hosts.txt; fi
  if [ -f "${varOutPath}989-tcp-hosts.txt" ]; then mv ${varOutPath}989-tcp-hosts.txt ${varOutPath}ftps-data-hosts.txt; fi
  if [ -f "${varOutPath}990-tcp-hosts.txt" ]; then mv ${varOutPath}990-tcp-hosts.txt ${varOutPath}ftps-hosts.txt; fi
  if [ -f "${varOutPath}992-tcp-hosts.txt" ]; then mv ${varOutPath}992-tcp-hosts.txt ${varOutPath}telnets-hosts.txt; fi
  if [ -f "${varOutPath}993-tcp-hosts.txt" ]; then mv ${varOutPath}993-tcp-hosts.txt ${varOutPath}imaps-hosts.txt; fi
  if [ -f "${varOutPath}995-tcp-hosts.txt" ]; then mv ${varOutPath}995-tcp-hosts.txt ${varOutPath}pop3s-hosts.txt; fi
  if [ -f "${varOutPath}1433-tcp-hosts.txt" ]; then mv ${varOutPath}1433-tcp-hosts.txt ${varOutPath}mssql-hosts.txt; fi
  if [ -f "${varOutPath}3389-tcp-hosts.txt" ]; then mv ${varOutPath}3389-tcp-hosts.txt ${varOutPath}rdp-hosts.txt; fi
  if [ -f "${varOutPath}5432-tcp-hosts.txt" ]; then mv ${varOutPath}5432-tcp-hosts.txt ${varOutPath}postgresql-hosts.txt; fi
  if [ -f "${varOutPath}8080-tcp-hosts.txt" ]; then mv ${varOutPath}8080-tcp-hosts.txt ${varOutPath}http-8080-hosts.txt; fi
  if [ -f "${varOutPath}8443-tcp-hosts.txt" ]; then mv ${varOutPath}8443-tcp-hosts.txt ${varOutPath}http-8443-hosts.txt; fi
fi

# Create web-urls.txt
if [ "$varDoWebUrl" = "Y" ]; then
  while read varLine; do
    varLineHost=""
    varLinePort=""
    varLineHost=$(echo $varLine | awk -F ',' '{print $1}')
    varLinePort=$(echo $varLine | awk -F ',' '{print $2}')
    if [ "$varLinePort" = "80" ]; then echo "http://${varLineHost}/" >> ${varOutPath}web-urls.txt; fi
    if [ "$varLinePort" = "443" ]; then echo "https://${varLineHost}/" >> ${varOutPath}web-urls.txt; fi
    if [ "$varLinePort" = "8080" ]; then echo "http://${varLineHost}:8080/" >> ${varOutPath}web-urls.txt; fi
    if [ "$varLinePort" = "8443" ]; then echo "https://${varLineHost}:8443/" >> ${varOutPath}web-urls.txt; fi
  done < $varOutPath$varTempFile
fi

# Create smb-urls.txt
if [ "$varDoSmbUrl" = "Y" ]; then
  while read varLine; do
    varLineHost=""
    varLinePort=""
    varLineHost=$(echo $varLine | awk -F ',' '{print $1}')
    varLinePort=$(echo $varLine | awk -F ',' '{print $2}')
    if [ "$varLinePort" = "445" ]; then echo "smb://${varLineHost}/" >> ${varOutPath}smb-urls.txt; fi
  done < $varOutPath$varTempFile
fi

rm $varOutPath$varTempFile

# Create portList.txt (comma-separated list of unique open ports to copy and paste into nmap scans)
cat ${varOutPath}summary.txt | grep -Eo '([0-9]{1,5})\s/\s' | grep -Eo '[0-9]{1,5}' > ${varOutPath}port-list.txt
sort ${varOutPath}port-list.txt | uniq > ${varOutPath}tmp.txt
mv -f ${varOutPath}tmp.txt ${varOutPath}port-list.txt
sed -z 's/\n/,/g;s/,$/\n/' ${varOutPath}port-list.txt > ${varOutPath}tmp.txt
mv -f ${varOutPath}tmp.txt ${varOutPath}port-list.txt

## Output Summary
#echo
#if [ "$varFlagOutExists" = "Y" ]; then echo "Note: $varOutPath already existed."; echo "Files listed may have already existed, or been appended."; echo; fi
#if [ -e "${varOutPath}summary.txt" ]; then echo "summary.txt exists"; fi
#if [ -e "${varOutPath}smb-urls.txt" ]; then echo "smb-urls.txt exists"; fi
#if [ -e "${varOutPath}web-urls.txt" ]; then echo "web-urls.txt exists"; fi
#if [ -e "${varOutPath}summary.txt" ] || [ -e "${varOutPath}smb-urls.txt" ] || [ -e "${varOutPath}web-urls.txt" ]; then echo; fi
#echo "*-hosts.txt in $varOutPath:"
#echo
#wc -l ${varOutPath}*-hosts.txt | grep -v 'total' | tr '/' ' ' | awk '{print $1, $NF}'
#echo

# Display summary without asking
if [ "$varShowSummary" = "Y" ]; then
  cat ${varOutPath}summary.txt
  echo
fi

# Display port list without asking
#if [ "$varShowPortList" = "Y" ] && [ -e "${varOutPath}port-list.txt" ]; then
#  cat ${varOutPath}port-list.txt
#  echo
#fi

#echo "=============================[ fin ]============================="
#echo

#if [ "$varShowPortList" = "Y" ] || [ "$varShowPortList" = "y" ]; then
#  echo
#  cat ${varOutPath}port-list.txt
#  echo
#fi
