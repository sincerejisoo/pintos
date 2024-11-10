#!/bin/bash

OUTPUT_FILE="sequential_test_scores.txt"
> "$OUTPUT_FILE" 

for i in {1..100}
do
    echo "Run #$i" >> "$OUTPUT_FILE"

    make clean > /dev/null 2>&1 
    make > /dev/null 2>&1  
    make grade | grep "TOTAL TESTING SCORE:" >> "$OUTPUT_FILE"  

    echo "Run #$i finished."  
    echo "====================================" >> "$OUTPUT_FILE" 
done

echo "All runs completed. Scores saved to $OUTPUT_FILE"