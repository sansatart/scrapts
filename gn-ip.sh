#!/usr/bin/env bash

RED=$(tput setaf 1)
BLUE=$(tput setaf 4)
WHITE=$(tput setaf 7)
NORMAL=$(tput sgr0)

##Quick PCAP analysis: Greynoise, whob, file extraction (HTTP)
##Tested on Ubuntu 18.04.2 LTS

##Dependency Check

#whob
if ! [ -x "$(command -v whob)" ]; then
    printf "\n"
    echo "${RED}Error: whob doesn't appear to be installed.${NORMAL}"
    printf "\n"
    echo "${WHITE}Try: https://pwhois.org/lft/${NORMAL}"
    exit
fi

#greynoise
if ! [ -x "$(command -v greynoise)" ]; then
    printf "\n"
    echo "${RED}Error: greynoise doesn't appear to be installed.${NORMAL}"
    printf "\n"
    echo "${WHITE}Try: sudo -H pip3 install greynoise --upgrade${NORMAL}"
    exit
fi

#tshark
if ! [ -x "$(command -v tshark)" ]; then
    printf "\n"
    echo "${RED}Error: tshark doesn't appear to be installed.${NORMAL}"
    printf "\n"
    echo "${WHITE}Try: sudo apt install tshark${NORMAL}"
    exit
fi

timestamp=$(date +%Y-%m-%d:%H:%M)

pcap_file=$(zenity --file-selection --title "PCAP File" --text "Select PCAP File" --file-filter='*.pcap*' 2> >(grep -v 'GtkDialog' >&2))

if [ ! -d "pcap-$timestamp-out" ]; then

    mkdir "pcap-$timestamp-out"

fi

cd "pcap-$timestamp-out"

#Initial parse of pcap file using tshark
if [ -n "$pcap_file" ]; then
    tshark -r $pcap_file -T fields -e ip.src | grep -vE '^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)' | sort -u > $timestamp-ip-out.txt
    whob -gnupf "$timestamp-ip-out.txt" > whob-$timestamp-ip-out.txt
else
    zenity --error --text "No file found, exiting" 2> >(grep -v 'GtkDialog' >&2)
    exit
fi

#pass IPs to greynoise
if [ -s "$timestamp-ip-out.txt" ]; then
    
    while read ip; do
    
    greynoise "$ip" > gn-"$ip"-out.txt
    
    done < "$timestamp-ip-out.txt"
    
    grep -Z -l "No results found" gn-*.txt | xargs -0 rm
    
    gnmatches=$(ls gn-*.txt | egrep -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}")
    
    printf "\n"
    echo "${WHITE}IPs found in Greynoise:${NORMAL}"
    printf "\n"
    
    echo "${BLUE}"$gnmatches"${NORMAL}"
    
else
    zenity --error --text "Empty file found, exiting" 2> >(grep -v 'GtkDialog' >&2)
    exit
fi

#grab all objects from PCAP

tshark -r $pcap_file --export-objects "http,objects" > /dev/null
cd objects
sha256sum * | sort -u > ../sha256-out-file.txt
sha256sum * | awk '{ print $1 }' | sort -u > ../sha256-out-hash.txt

