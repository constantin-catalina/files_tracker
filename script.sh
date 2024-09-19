#!/bin/bash

filename=$1
destination_file="$2/$3"

#Atribuire permisiuni pentru a permite citirea
chmod a+r $filename

#Numărul de linii
num_lines=$(wc -l < "$filename")

# Numărul de cuvinte
num_words=$(wc -w < "$filename")

# Numărul de caractere
num_chars=$(wc -m < "$filename")

# Verificare fisier suspect
if [ "$num_lines" -lt 3 ] && [ "$num_words" -gt 1000 ] && [ "$num_chars" -gt 2000 ]; then
    wc_check=true
else
    wc_check=false
fi

# Căutarea de cuvinte cheie
if grep -q -E -i 'corrupted|dangerous|risk|attack|malware|malicious' "$filename"; then
    word_check=true;
else
    word_check=false;
fi

# Căutarea de caractere NON-ASCII
if grep -q -P -i "[^\x00-\xFF]" "$filename"; then
    ascii_check=true;
else
    ascii_check=false;
fi

#Eliminare permisiuni atribuite de citire
chmod a-r $filename

# Stabilire daca fisierul este corupt
if [ "$wc_check" = true ]; then
	if [ "$word_check" = true  ] || [ "$ascii_check" = true  ]; then
	    echo "$filename"
	else
	    echo "SAFE"
	fi
else
	echo "SAFE"
fi

exit 0
