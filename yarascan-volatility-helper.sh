#!/bin/bash

# Default values
RULES_DIRS=()
MEMORY_DUMP=""
OUTPUT_FILE=""
LOG_FILE="script.log"
match_found=false
total_rules=0
triggered_rules=0
triggered_rules_output=""

# Function to print usage information
print_usage() {
    echo "Usage: $0 [-h] [-d <directory>] [-f <memory_dump>] [-o <output_file>]"
    echo "Options:"
    echo "  -h            Display this help message"
    echo "  -d <directory> Specify the directory containing YARA rule files"
    echo "  -f <memory_dump> Specify the memory dump file"
    echo "  -o <output_file> Specify the output file"
    echo
    echo "Note: Ensure the script is placed in the directory of the Volatility3 tool."
}

# Parse command-line options
while getopts ":hd:f:o:" opt; do
    case ${opt} in
        h )
            print_usage
            exit 0
            ;;
        d )
            if [ -d "$OPTARG" ]; then
                RULES_DIRS+=("$OPTARG")
            else
                echo "Error: Directory $OPTARG does not exist or is invalid." >&2
                exit 1
            fi
            ;;
        f )
            if [ -f "$OPTARG" ]; then
                MEMORY_DUMP="$OPTARG"
            else
                echo "Error: File $OPTARG does not exist or is invalid." >&2
                exit 1
            fi
            ;;
        o )
            OUTPUT_FILE="$OPTARG"
            ;;
        \? )
            echo "Invalid option: $OPTARG" 1>&2
            print_usage
            exit 1
            ;;
        : )
            echo "Option -$OPTARG requires an argument." 1>&2
            print_usage
            exit 1
            ;;
    esac
done
shift $((OPTIND -1))

# Check if memory dump file is provided
if [ -z "$MEMORY_DUMP" ]; then
    echo "Error: Memory dump file not specified."
    print_usage
    exit 1
fi

# Function to extract rule name from file path
get_rule_name() {
    echo "$1" | rev | cut -d'/' -f1 | rev
}

# Function to print section header
print_section_header() {
    echo "-----------------------------------------------------------"
    echo "Rule: $1"
    echo "-----------------------------------------------------------"
}

# Get the directory of the script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
# Check if vol.py exists in the script directory
if [ ! -f "$SCRIPT_DIR/vol.py" ]; then
    echo "Error: vol.py not found in the same directory as the script."
    exit 1
fi

# Initialize log file
touch "$LOG_FILE" || { echo "Error: Failed to create log file $LOG_FILE." >&2; exit 1; }

# Record start time
start_time=$(date +%s)

# Loop through each directory containing the YARA rule files
for RULES_DIR in "${RULES_DIRS[@]}"; do
    # Run yarascan for each YARA rule file in the directory
    for RULE_FILE in "$RULES_DIR"/*.yar; do
        if [ -f "$RULE_FILE" ]; then
            total_rules=$((total_rules + 1))
            echo "Running yarascan for file: $RULE_FILE"
            # Run yarascan and save the output to a temporary file
            python "$SCRIPT_DIR/vol.py" -f "$MEMORY_DUMP" yarascan.YaraScan --yara-file "$RULE_FILE" > temp.txt
            # Check if yarascan was successful and if it has matches with text under the headers
            if [ $? -eq 0 ] && grep -q "Offset.*Rule.*Component.*Value" temp.txt && grep -q -E "^[[:space:]]*0x[[:xdigit:]]+" temp.txt; then
                # Set the flag to true since a match is found
                match_found=true
                triggered_rules=$((triggered_rules + 1))
                # Add the triggered rule and its output to the triggered_rules_output variable
                triggered_rules_output+="\n\n$(get_rule_name "$RULE_FILE"):\n$(awk '!/Volatility 3 Framework 2.6.1/ && !/^$/ {print}' temp.txt)"
            fi
            # Remove the temporary file
            rm temp.txt
            # Show message after running each rule
            echo "Rule finished: $RULE_FILE"
        fi
    done
done

# Record end time
end_time=$(date +%s)

# Calculate total time taken
duration=$((end_time - start_time))

# Print time taken
echo "Time taken: $duration seconds" | tee -a "$LOG_FILE"

# Print output if OUTPUT_FILE is not specified
if [ -z "$OUTPUT_FILE" ]; then
    echo -e "\nTriggered Rules and Their Values:"
    echo -e "$triggered_rules_output"
fi

# Print summary
echo -e "\nSummary:"
echo "Total rules: $total_rules"
echo "Triggered rules: $triggered_rules" | tee -a "$LOG_FILE"
echo "Time taken: $duration seconds" | tee -a "$LOG_FILE"

# Check if any match is found
if ! $match_found; then
    echo "No matches found."
fi

