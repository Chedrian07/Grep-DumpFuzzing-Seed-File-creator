#!/bin/bash

################################################################################
# set-seed-Final.sh (Refined Version)
#
# This script creates a diverse and manageable number of seed files for fuzzing
# grep with AFL++. It generates a wide variety of regex patterns, including:
# - Simple and complex patterns
# - Edge cases: empty patterns, unbalanced groups, invalid ranges
# - Nested negation
# - Rare escape sequences and Unicode properties
# - Controlled pattern lengths to prevent timeouts
# - Binary and ASCII mixes
#
# Additionally:
# - Defines arrays for POSIX classes and special sequences.
# - Produces a robust `test_corpus.txt` for grep to search through.
# - Limits the maximum length of regex patterns to avoid timeouts.
#
# Usage:
#   ./set-seed-Final.sh
#   afl-fuzz -i grep_fuzz_seeds -o afl_output -- ./grep -E -f @@ test_corpus.txt
#
################################################################################

SEED_DIR="grep_fuzz_seeds"
mkdir -p "$SEED_DIR"
rm -f "$SEED_DIR"/*.txt

echo "Starting refined seed generation..."

# Define POSIX classes
posix_classes=("[:alnum:]" "[:alpha:]" "[:digit:]" "[:lower:]" "[:upper:]" "[:space:]" "[:cntrl:]" "[:graph:]" "[:print:]" "[:punct:]" "[:xdigit:]")

# Define special sequences
special_sequences=("\\p{Alpha}" "\\p{Digit}" "\\p{Space}" "\\p{Word}" "\\G" "\\K")

# Define maximum pattern length to prevent timeouts
MAX_PATTERN_LENGTH=1000  # Adjust as necessary

# Define categories and pattern counts
declare -A categories=(
    [basic_literals]=100
    [basic_metachar]=100
    [basic_charclass]=100
    [basic_quantifier]=100
    [basic_anchor]=50
    [basic_group]=50
    [basic_escape]=50
    [complex_long]=50
    [complex_nested]=50
    [complex_redos]=20
    [posix_combo]=50
    [posix_neg]=20
    [anchor_adv]=50
    [unicode_pcre]=30
    [random_bin]=50
    [conflict]=50
    [large_quant]=30
    [conditional]=10
    [synthetic]=50
    [huge_cat]=10  # Each huge_cat will have 200 patterns, total 2000
    [bininsert]=100
)

# Function to generate basic literal patterns
generate_basic_literals() {
    echo "Generating Basic Literal Patterns..."
    for i in $(seq 1 ${categories[basic_literals]}); do
        len=$(( (RANDOM % 20) + 1 ))
        word=$(head -c 100 /dev/urandom | tr -cd '[:alpha:]' | head -c $len)
        [ -z "$word" ] && word="literal"
        echo "$word" > "$SEED_DIR/literal_$i.txt"
    done
}

# Function to generate basic metachar patterns
generate_basic_metachar() {
    echo "Generating Basic Metachar Patterns..."
    metachar_options=("." "*" "?" "+" "{2,5}" "{0,}" "{1,10}")
    for i in $(seq 1 ${categories[basic_metachar]}); do
        base_len=$(( (RANDOM % 10) + 5 ))
        base_word=$(head -c 100 /dev/urandom | tr -cd '[:alpha:]' | head -c $base_len)
        [ -z "$base_word" ] && base_word="meta"
        choice=$((RANDOM % ${#metachar_options[@]}))
        patt="${base_word}${metachar_options[$choice]}"
        # Ensure pattern length does not exceed maximum
        if [ ${#patt} -le $MAX_PATTERN_LENGTH ]; then
            echo "$patt" > "$SEED_DIR/metachar_$i.txt"
        else
            echo "${patt:0:$MAX_PATTERN_LENGTH}" > "$SEED_DIR/metachar_$i.txt"
        fi
    done
}

# Function to generate basic character classes
generate_basic_charclass() {
    echo "Generating Basic Character Class Patterns..."
    for i in $(seq 1 ${categories[basic_charclass]}); do
        length=$(( (RANDOM % 20) + 5 ))
        chars=$(head -c 200 /dev/urandom | tr -cd '[:alnum:]' | head -c $length)
        [ -z "$chars" ] && chars="abc"
        # 50% chance to invert
        if (( RANDOM % 2 )); then
            patt="[^$chars]"
        else
            patt="[$chars]"
        fi
        # Add quantifier sometimes
        if (( RANDOM % 3 == 0 )); then
            patt="$patt+"
        fi
        # Ensure pattern length
        if [ ${#patt} -le $MAX_PATTERN_LENGTH ]; then
            echo "$patt" > "$SEED_DIR/charclass_$i.txt"
        else
            echo "${patt:0:$MAX_PATTERN_LENGTH}" > "$SEED_DIR/charclass_$i.txt"
        fi
    done
}

# Function to generate basic quantifier patterns
generate_basic_quantifier() {
    echo "Generating Basic Quantifier Patterns..."
    for i in $(seq 1 ${categories[basic_quantifier]}); do
        base="X"
        m=$(( (RANDOM % 10) + 1 ))  # To prevent very large quantifiers
        n=$((m + (RANDOM % 10) + 1 ))  # Ensure n >= m
        if (( RANDOM % 5 == 0 )); then
            patt="${base}{$m,}"  # {m,}
        else
            patt="${base}{$m,$n}"  # {m,n}
        fi
        # Ensure pattern length
        if [ ${#patt} -le $MAX_PATTERN_LENGTH ]; then
            echo "$patt" > "$SEED_DIR/quantifier_$i.txt"
        else
            echo "${patt:0:$MAX_PATTERN_LENGTH}" > "$SEED_DIR/quantifier_$i.txt"
        fi
    done
}

# Function to generate basic anchor patterns
generate_basic_anchor() {
    echo "Generating Basic Anchor Patterns..."
    for i in $(seq 1 ${categories[basic_anchor]}); do
        pattern=""
        # Maybe add start anchor
        if (( RANDOM % 2 )); then
            pattern="^"
        fi
        # Add a random word
        wlen=$(( (RANDOM % 10) + 3 ))
        word=$(head -c 100 /dev/urandom | tr -cd '[:alpha:]' | head -c $wlen)
        [ -z "$word" ] && word="anch"
        pattern="$pattern$word"
        # Maybe add end anchor
        if (( RANDOM % 2 )); then
            pattern="$pattern$"
        fi
        # Ensure pattern length
        if [ ${#pattern} -le $MAX_PATTERN_LENGTH ]; then
            echo "$pattern" > "$SEED_DIR/anchor_$i.txt"
        else
            echo "${pattern:0:$MAX_PATTERN_LENGTH}" > "$SEED_DIR/anchor_$i.txt"
        fi
    done
}

# Function to generate basic group patterns
generate_basic_group() {
    echo "Generating Basic Group Patterns..."
    for i in $(seq 1 ${categories[basic_group]}); do
        wlen=$(( (RANDOM % 15) + 5 ))
        word=$(head -c 200 /dev/urandom | tr -cd '[:alpha:]' | head -c $wlen)
        [ -z "$word" ] && word="grp"
        if (( RANDOM % 2 )); then
            patt="($word)"
        else
            patt="(?:$word)"
        fi
        # Maybe add nested group
        if (( RANDOM % 4 == 0 )); then
            wlen2=$(( (RANDOM % 10) + 3 ))
            word2=$(head -c 100 /dev/urandom | tr -cd '[:alpha:]' | head -c $wlen2)
            [ -z "$word2" ] && word2="inner"
            patt="($patt($word2))"
        fi
        # Ensure pattern length
        if [ ${#patt} -le $MAX_PATTERN_LENGTH ]; then
            echo "$patt" > "$SEED_DIR/group_$i.txt"
        else
            echo "${patt:0:$MAX_PATTERN_LENGTH}" > "$SEED_DIR/group_$i.txt"
        fi
    done
}

# Function to generate basic escape patterns
generate_basic_escape() {
    echo "Generating Basic Escape Patterns..."
    escapes=("\\d" "\\w" "\\s" "\\D" "\\W" "\\S" "\\t" "\\n")
    for i in $(seq 1 ${categories[basic_escape]}); do
        e=${escapes[$((RANDOM % ${#escapes[@]}))]}
        patt="A${e}B"
        # Ensure pattern length
        if [ ${#patt} -le $MAX_PATTERN_LENGTH ]; then
            echo "$patt" > "$SEED_DIR/escape_$i.txt"
        else
            echo "${patt:0:$MAX_PATTERN_LENGTH}" > "$SEED_DIR/escape_$i.txt"
        fi
    done
}

# Function to generate complex long patterns
generate_complex_long() {
    echo "Generating Complex/Overflow Long Patterns..."
    for i in $(seq 1 ${categories[complex_long]}); do
        length=$(( (RANDOM % 5000) + 1000 ))  # Limit to 6k to prevent excessive length
        # Generate a long string of 'a's, or random alphanumerics
        longp=$(head -c 10000 /dev/urandom | tr -cd 'a' | head -c $length)
        [ -z "$longp" ] && longp=$(printf 'a%.0s' $(seq 1 $length))
        echo "$longp" > "$SEED_DIR/long_overflow_$i.txt"
    done
}

# Function to generate complex nested group patterns
generate_complex_nested() {
    echo "Generating Complex/Overflow Deeply Nested Groups..."
    for i in $(seq 1 ${categories[complex_nested]}); do
        depth=$(( (RANDOM % 30) + 10 ))  # Reduce maximum depth to 40
        grp=""
        for ((d=1; d<=depth; d++)); do
            grp+="("
        done
        grp+="a"
        for ((d=1; d<=depth; d++)); do
            grp+=")"
        done
        echo "$grp" > "$SEED_DIR/deep_nested_$i.txt"
    done
}

# Function to generate ReDoS patterns
generate_complex_redos() {
    echo "Generating ReDoS Patterns..."
    for i in $(seq 1 ${categories[complex_redos]}); do
        # Create a pattern like (a|aa|aaa|aaaa)+$
        n=$(( (RANDOM % 10) + 5 ))
        alternations=""
        for ((x=1; x<=n; x++)); do
            alternations+="a"
            for ((y=1; y<=x; y++)); do
                alternations+="a"
            done
            if (( x < n )); then
                alternations+="|"
            fi
        done
        patt="(${alternations})+$"
        echo "$patt" > "$SEED_DIR/redos_$i.txt"
    done
}

# Function to generate POSIX combo patterns
generate_posix_combo() {
    echo "Generating POSIX Combo Patterns..."
    pcount=${#posix_classes[@]}
    for i in $(seq 1 ${categories[posix_combo]}); do
        c1=${posix_classes[$((RANDOM % pcount))]}
        c2=${posix_classes[$((RANDOM % pcount))]}
        c3=${posix_classes[$((RANDOM % pcount))]}
        choice=$((RANDOM % 3))
        if ((choice==0)); then
            patt="[${c1}${c2}]+"
        elif ((choice==1)); then
            patt="[${c1}${c2}${c3}]+"
        else
            # Maybe include quantifier
            patt="[${c1}${c2}]{2,4}"
        fi
        # Ensure pattern length
        if [ ${#patt} -le $MAX_PATTERN_LENGTH ]; then
            echo "$patt" > "$SEED_DIR/posix_combo_$i.txt"
        else
            echo "${patt:0:$MAX_PATTERN_LENGTH}" > "$SEED_DIR/posix_combo_$i.txt"
        fi
    done
}

# Function to generate POSIX negated class patterns
generate_posix_neg() {
    echo "Generating POSIX Negated Patterns..."
    pcount=${#posix_classes[@]}
    for i in $(seq 1 ${categories[posix_neg]}); do
        c1=${posix_classes[$((RANDOM % pcount))]}
        patt="[^${c1}]"
        # Maybe add quantifier
        if (( RANDOM % 3 == 0 )); then
            patt="$patt*"
        fi
        # Ensure pattern length
        if [ ${#patt} -le $MAX_PATTERN_LENGTH ]; then
            echo "$patt" > "$SEED_DIR/posix_neg_$i.txt"
        else
            echo "${patt:0:$MAX_PATTERN_LENGTH}" > "$SEED_DIR/posix_neg_$i.txt"
        fi
    done
}

# Function to generate advanced anchor patterns
generate_anchor_adv() {
    echo "Generating Advanced Anchor Patterns..."
    variants=("^" "\\A" "" "\\b" "\\B" "\\Z" "$")
    for i in $(seq 1 ${categories[anchor_adv]}); do
        plen=$(( (RANDOM % 5)+2 ))  # 2 to 6 anchors
        pat=""
        for ((x=1; x<=plen; x++)); do
            a=${variants[$((RANDOM % ${#variants[@]} ))]}
            pat+="$a"
            # Add a random character after anchor
            if (( RANDOM % 2 == 0 )); then
                pat+="A"
            fi
        done
        # Ensure pattern length
        if [ ${#pat} -le $MAX_PATTERN_LENGTH ]; then
            echo "$pat" > "$SEED_DIR/anchor_adv_$i.txt"
        else
            echo "${pat:0:$MAX_PATTERN_LENGTH}" > "$SEED_DIR/anchor_adv_$i.txt"
        fi
    done
}

# Function to generate Unicode/PCRE-like patterns
generate_unicode_pcre() {
    echo "Generating Unicode/PCRE-like Patterns..."
    for i in $(seq 1 ${categories[unicode_pcre]}); do
        up=${special_sequences[$((RANDOM % ${#special_sequences[@]} ))]}
        # Insert zero-width assertions: \G, \K
        zero_widths=("\\G" "\\K")
        zw=${zero_widths[$((RANDOM % 2))]}
        # Combine them with other characters
        patt="A${up}${zw}B"
        # Ensure pattern length
        if [ ${#patt} -le $MAX_PATTERN_LENGTH ]; then
            echo "$patt" > "$SEED_DIR/unicode_pcre_$i.txt"
        else
            echo "${patt:0:$MAX_PATTERN_LENGTH}" > "$SEED_DIR/unicode_pcre_$i.txt"
        fi
    done
}

# Function to generate random binary patterns
generate_random_bin() {
    echo "Generating Random Binary/ASCII Patterns..."
    for i in $(seq 1 ${categories[random_bin]}); do
        length=$(( (RANDOM % 200) + 50 ))  # 50 to 249 characters
        bin=$(head -c $length /dev/urandom | tr -cd '[:print:]' | head -c $((length/2)))
        [ -z "$bin" ] && bin="binfallback"
        # Ensure printable
        bin=$(echo "$bin" | tr -cd '[:print:]')
        echo "$bin" > "$SEED_DIR/binary_$i.txt"
    done
}

# Function to generate conflicting patterns
generate_conflict() {
    echo "Generating Conflicting Patterns..."
    for i in $(seq 1 ${categories[conflict]}); do
        stuff=""
        inserts=$((RANDOM%5+3))
        for ((x=1; x<=inserts; x++)); do
            case $((RANDOM%4)) in
              0) stuff+="a-z";;
              1) stuff+="Z-A";; # invalid range
              2) stuff+="[:digit:]";;
              3) stuff+="^";;
            esac
        done
        patt="[$stuff]"
        # Maybe add quantifier
        if (( RANDOM % 3 == 0 )); then
            patt="$patt+"
        fi
        # Ensure pattern length
        if [ ${#patt} -le $MAX_PATTERN_LENGTH ]; then
            echo "$patt" > "$SEED_DIR/conflict_$i.txt"
        else
            echo "${patt:0:$MAX_PATTERN_LENGTH}" > "$SEED_DIR/conflict_$i.txt"
        fi
    done
}

# Function to generate large quantifier patterns
generate_large_quant() {
    echo "Generating Large Quantifier Patterns..."
    for i in $(seq 1 ${categories[large_quant]}); do
        c='X'
        # Create large quantifier, but keep within max length
        big_m=$((RANDOM % 1000 + 100))
        big_n=$((big_m + RANDOM % 500 + 500))
        if (( RANDOM % 5 == 0 )); then
            patt="${c}{$big_m,}"
        else
            patt="${c}{$big_m,$big_n}"
        fi
        # Ensure pattern length
        if [ ${#patt} -le $MAX_PATTERN_LENGTH ]; then
            echo "$patt" > "$SEED_DIR/large_quant_$i.txt"
        else
            echo "${patt:0:$MAX_PATTERN_LENGTH}" > "$SEED_DIR/large_quant_$i.txt"
        fi
    done
}

# Function to generate conditional-like patterns
generate_conditional() {
    echo "Generating Conditional-like Patterns..."
    for i in $(seq 1 ${categories[conditional]}); do
        patt="(?(?=[a-z])abc|def)"
        echo "$patt" > "$SEED_DIR/conditional_$i.txt"
    done
}

# Function to generate synthetic patterns combining multiple features
generate_synthetic() {
    echo "Generating Synthetic Patterns..."
    pcount=${#posix_classes[@]}
    for i in $(seq 1 ${categories[synthetic]}); do
        # Start with an anchor
        start_anchors=("^" "\\A" "")
        end_anchors=("$" "\\Z" "")
        sa=${start_anchors[$((RANDOM%3))]}
        ea=${end_anchors[$((RANDOM%3))]}
    
        # Insert a group with posix class
        pcls=${posix_classes[$((RANDOM%pcount))]}
        grp="(${pcls}+)"
    
        # Insert a quantifier after group
        qlen=$((RANDOM%5+1))
        q="{${qlen},$((qlen + 5))}"
    
        # Maybe insert a special sequence inside
        if (( RANDOM % 2 == 0 )); then
            sq=${special_sequences[$((RANDOM%${#special_sequences[@]} ))]}
            grp="${grp}${sq}"
        fi
    
        # Combine all
        patt="${sa}${grp}${q}${ea}"
    
        # Ensure pattern length
        if [ ${#patt} -le $MAX_PATTERN_LENGTH ]; then
            echo "$patt" > "$SEED_DIR/synthetic_$i.txt"
        else
            echo "${patt:0:$MAX_PATTERN_LENGTH}" > "$SEED_DIR/synthetic_$i.txt"
        fi
    done
}

# Function to generate huge category patterns
generate_huge_cat() {
    echo "Generating Huge Category Patterns..."
    HUGE_CATEGORY_COUNT=10
    HUGE_PER_CAT=200
    posix_classes_count=${#posix_classes[@]}
    special_sequences_count=${#special_sequences[@]}
    for cat_i in $(seq 1 $HUGE_CATEGORY_COUNT); do
        for j in $(seq 1 $HUGE_PER_CAT); do
            # Random complex pattern
            # Start with a random anchor
            anc_set=("^" "\\A" "" "\\b" "\\B" "\\Z" "$")
            a1=${anc_set[$((RANDOM % ${#anc_set[@]} ))]}
            a2=${anc_set[$((RANDOM % ${#anc_set[@]} ))]}
    
            # Insert a class
            cls_variants=("a-z" "A-Z" "0-9" "[:alpha:]" "[:digit:]" "[:alnum:]")
            cv=${cls_variants[$(( RANDOM % ${#cls_variants[@]} ))]}
            class_patt="[$cv]"
    
            # Insert a quantifier
            qm=$(( RANDOM % 10 + 1 ))  # {1,6}
            qn=$(( qm + RANDOM % 20 + 5 ))  # {qm, qm+5}
            quant="{$qm,$qn}"
    
            # Insert a group around class
            grp_choice=$(( RANDOM % 2 ))
            if (( grp_choice == 0 )); then
                mainp="(${class_patt}${quant})"
            else
                mainp="(?:${class_patt}${quant})"
            fi
    
            # Add a metachar at end
            mchars=("." "+" "?" "*" "{2,}" "|")
            mch=${mchars[$(( RANDOM % ${#mchars[@]} ))]}
    
            # Combine all
            pattern="${a1}${mainp}${mch}${a2}"
    
            # Maybe insert a special sequence in middle
            if (( RANDOM % 3 == 0 )); then
                sq=${special_sequences[$(( RANDOM % ${#special_sequences[@]} ))]}
                # Insert it randomly
                pos=$(( RANDOM % (${#pattern} + 1) ))
                front=${pattern:0:$pos}
                back=${pattern:$pos}
                pattern="${front}${sq}${back}"
            fi
    
            # Ensure pattern length
            if [ ${#pattern} -le $MAX_PATTERN_LENGTH ]; then
                echo "$pattern" > "$SEED_DIR/huge_cat${cat_i}_$j.txt"
            else
                echo "${pattern:0:$MAX_PATTERN_LENGTH}" > "$SEED_DIR/huge_cat${cat_i}_$j.txt"
            fi
        done
    done
}

# Function to generate binary insertions in patterns
generate_bininsert() {
    echo "Generating Binary Insertions in Patterns..."
    for i in $(seq 1 ${categories[bininsert]}); do
        base="ABC"
        length=$(( (RANDOM % 50)+10 ))  # 10 to 59
        binjunk=$(head -c $length /dev/urandom | tr -cd '[:cntrl:]' | head -c $length)
        [ -z "$binjunk" ] && binjunk="\x00"
        # Convert binary junk to \xHH escapes
        hexbin=$(echo -n "$binjunk" | xxd -p | tr -d '\n')
        escbin=""
        while [ -n "$hexbin" ]; do
          h2=${hexbin:0:2}
          hexbin=${hexbin:2}
          escbin+="\\x$h2"
        done
        # Insert binary junk at random position
        pos=$(( RANDOM % (${#base} + 1) ))  # Position between 0 and length of base
        front=${base:0:$pos}
        back=${base:$pos}
        patt="${front}${escbin}${back}"
        # Ensure pattern length
        if [ ${#patt} -le $MAX_PATTERN_LENGTH ]; then
            echo -e "$patt" > "$SEED_DIR/bininsert_$i.txt"
        else
            echo -e "${patt:0:$MAX_PATTERN_LENGTH}" > "$SEED_DIR/bininsert_$i.txt"
        fi
    done
}

# Now, generate all patterns
generate_basic_literals
generate_basic_metachar
generate_basic_charclass
generate_basic_quantifier
generate_basic_anchor
generate_basic_group
generate_basic_escape
generate_complex_long
generate_complex_nested
generate_complex_redos
generate_posix_combo
generate_posix_neg
generate_anchor_adv
generate_unicode_pcre
generate_random_bin
generate_conflict
generate_large_quant
generate_conditional
generate_synthetic
generate_huge_cat
generate_bininsert

################################################################################
# Summarize and finalize
################################################################################
total_count=$(ls -1 "$SEED_DIR" | wc -l)
echo "Seed file generation completed. A total of $total_count seed files have been created."
echo "Check the '$SEED_DIR' directory for the generated seeds."
echo "Done."

################################################################################
# End of set-seed-Final.sh
################################################################################