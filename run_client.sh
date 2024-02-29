#!/bin/bash

# Check if the text file argument is provided
if [ $# -ne 4 ]; then
    echo "Usage: $0 ip port text_file timeout"
    exit 1
fi

# Check if the provided file exists
if [ ! -f "$3" ]; then
    echo "Error: File $3 not found."
    exit 1
fi

# Read the text file line by line and execute Python program for each line
while read -r line; do
    echo "Running client.py on domain: $line"
    python3 client.py "$1" "$2" "$line" "$4"
done < "$3"