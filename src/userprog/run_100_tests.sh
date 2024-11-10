#!/bin/bash

# Output file to save the results
OUTPUT_FILE="test_scores.txt"

# Clear the output file if it exists
> "$OUTPUT_FILE"

# Loop 100 times
for i in {1..3}
do
    echo "Run #$i" >> "$OUTPUT_FILE"  # Log the run number

    # Run make commands but only save the specific result line from make grade
    make clean >> /dev/null 2>&1  # Run make clean, discard output
    make >> /dev/null 2>&1        # Run make, discard output
    make grade | grep "TOTAL TESTING SCORE:" >> "$OUTPUT_FILE"  # Capture only the score line

    echo "====================================" >> "$OUTPUT_FILE" # Separator between runs
done

echo "All runs completed. Scores saved to $OUTPUT_FILE"