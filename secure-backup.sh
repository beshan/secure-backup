#!/bin/bash

# This script was an early attempt to develop the secure-backup lib using bash script. 
# It's here for educational purposes and shouldn't be used as a reliable script.

set -e
set -u

function colorize() {
    RESET='\e[0m'
    BLACK='\e[0;30m'
    RED='\e[0;31m'
    GREEN='\e[0;32m'
    YELLOW='\e[0;33m'
    BLUE='\e[0;34m'
    WHITE='\e[0;37m'
    GRAY='\e[1;30m'

    local color
    typeset -n color=$1

    if (($# > 1)); then
        printf $color$2$RESET
    else
        printf $color
    fi
}

function throw() {
    printf "$(colorize RED Error): $1\n" >&2
    if (($# > 1)); then
        printf "$(colorize BLUE Hint): $2\n"
    fi
    exit 1
}

function decrypt_string() {
    local string=$1
    local passphrase=$2

    # encrypting the string and modifing base64 output by removing `=` char and replacing `/+` chars with `_-`
    string_len=$((${#string} % 4))
    if [[ $string_len == 2 ]]; then
        string="$string"'=='
    elif [[ $string_len == 3 ]]; then
        string="$string"'='
    fi

    echo "$string" | tr '_-' '/+' | openssl enc -d -aes-256-ctr -pbkdf2 -nopad -nosalt -a -A -k "$passphrase"
}

function encrypt_string() {
    local string=$1
    local passphrase=$2

    # decrypt the string and reversing base64 modification
    echo -n "$string" |
        openssl enc -e -aes-256-ctr -pbkdf2 -nopad -nosalt -a -A -k "$passphrase" |
        tr -d '=' |
        tr '/+' '_-'
}

function encrypt_file() {
    local file=$1
    local output=$2
    local passphrase=$3

    openssl enc -aes-256-ctr -pbkdf2 -nopad -nosalt -k "$passphrase" -in "$file" -out "$output"

    # gpg --output "$output" \
    #     --compress-algo zlib \
    #     --cipher-algo AES256 \
    #     --passphrase "$passphrase" \
    #     --pinentry-mode loopback \
    #     --symmetric \
    #     "$file"
}

function encrypt_path() {
    local path=$1
    local passphrase=$2

    # splitting the path by `/` delimiter and encrypting each directory's name
    readarray -d / -t directories < <(echo "$path")
    encrypted_path=''
    for ((n = 0; n < ${#directories[*]}; n++)); do
        encrypted_directory_name=$(encrypt_string "${directories[n]}" $passphrase)
        encrypted_path=$encrypted_path/$encrypted_directory_name
    done
    echo $encrypted_path
}

function calculate_checksum() {
    local file=$1
    shasum -b "$file" | cut -d " " -f 1
}

function generate_meta_file() {
    local source_file=$1
    local output=$2
    if (($# > 2)); then
        local passphrase=$3
    fi

    # calculating the original file's shasum and saving it into a meta file for implementing increamental backup
    # removing filename from shasum output
    local checksum=$(calculate_checksum "$source_file")

    local meta="$checksum"
    if [[ ! -z $passphrase ]]; then
        # encrypting the meta data
        local encrypted_meta=$(encrypt_string "$meta" "$passphrase")
        echo -n "$encrypted_meta" >"$output.meta"
    else
        echo -n "$meta" >"$output.meta"
    fi
}

function read_meta_file() {
    local path=$1
    if (($# > 1)); then
        local passphrase=$2
    fi

    if [[ ! -z $passphrase ]]; then
        # decrypting the meta data
        meta=$(decrypt_string $(cat "$path.meta") $passphrase)
        echo -n "$meta"
    else
        echo -n $(cat "$output_file.meta")
    fi
}

function backup() {
    local source_dir=$1
    local target_dir=$2
    local encryption=$3
    local passphrase=$4

    # incrementally taking a backup from the source directory into the target directory
    # encrypting all files and their path if the -encrypt option is set
    find "$source_dir" -type f | while read original_file; do
        # getting the relative path of the original file to the source directory
        relative_path="$(expr "$original_file" : "$source_dir\(.*\)")"

        if [[ $encryption == 1 ]]; then
            # encrypting the output path
            encrypted_relative_path=$(encrypt_path "$relative_path" $passphrase)
            output_file=$target_dir/$encrypted_relative_path

            mkdir -p "$(dirname "$output_file")"

            # checking if backup has already been performed for the current checksum of the original file.
            # implemnting incremantal backup
            already_backedup=0
            if [[ -f "$output_file.meta" ]]; then
                current_checksum=$(calculate_checksum "$original_file")
                last_checksum=$(read_meta_file "$output_file" "$passphrase")
                if [[ "$current_checksum" == "$last_checksum" ]]; then
                    already_backedup=1
                fi
            fi

            # taking the backup if it's not already performed for the current original file
            if [[ $already_backedup == 0 ]]; then
                # encrypting the output file
                encrypt_file "$original_file" "$output_file" $passphrase ||
                    (printf "[ $(colorize RED x) ] $original_file" && exit 1) # exiting immediately on error

                # generating an encrypted meta file
                generate_meta_file "$original_file" "$output_file" $passphrase
            fi
        else
            output_file=$target_dir/$relative_path

            mkdir -p "$(dirname "$output_file")"

            # implemnting incremantal backup
            already_backedup=0
            if [[ -f "$output_file.meta" ]]; then
                current_checksum=$(calculate_checksum "$original_file")
                last_checksum=$(read_meta_file "$output_file")
                if [[ "$current_checksum" == "$last_checksum" ]]; then
                    already_backedup=1
                fi
            fi

            # taking the backup if it's not already performed for the current original file
            if [[ $already_backedup == 0 ]]; then
                # copying the orginal file without encryption into the output file
                cp "$original_file" "$output_file"

                # generate a plain meta file
                generate_meta_file "$original_file" "$output_file"
            fi
        fi

        printf "[ $(colorize GREEN ✓) ] $relative_path\n"
    done
}

# echo ::: Copying changes :::
# rsync -av --exclude 'node_modules' --exclude '__pycache__' /media/behzad/Archive/Work/ ./Work

function main() {
    local source_dir=''
    local target_dir=''
    local restore=0
    local passphrase=''
    local encryption=1
    local confirmed=0

    while [ $# -gt 0 ]; do
        case $1 in
        -s | --source)
            shift
            source_dir=$1
            ;;
        -t | --target)
            shift
            target_dir=$1
            ;;
        -r | --restore)
            restore=1
            ;;
        -n | --no-encryption)
            encryption=0
            ;;
        -y)
            confirmed=1
            ;;
        *)
            throw "Unknown option $1"
            ;;
        esac
        shift
    done

    if [[ -z "$source_dir" ]]; then
        throw "Source directory is not provided" "Use the -s option to provide the source directory"
    elif [[ ! -d "$source_dir" ]]; then
        throw "The provided source directory does not exists"
    fi

    if [[ -z "$target_dir" ]]; then
        throw "Target directory is not provided" "Use the -t option to provide the target directory"
    elif [[ ! -d "$target_dir" ]]; then
        throw "The provided target directory does not exists"
    fi

    if [[ "$target_dir" -ef "$source_dir" ]]; then
        throw "Source and target dirctories are the same"
    fi

    if [[ $encryption == 1 ]]; then
        printf "$(colorize BLUE Passphrase): "
        local passphrase
        colorize GRAY
        read passphrase
        colorize RESET

        # encrypting the passphrase with its reversed value
        passphrase=$(encrypt_string "$passphrase" "$(echo $passphrase | rev)")
    fi

    if [[ $confirmed == 0 ]]; then
        if [[ $restore == 0 ]]; then
            printf "You are taking a $(colorize YELLOW backup) with the following config: \n"
        else
            printf "You are $(colorize YELLOW restoring) a backup with the following config: \n"
        fi
        printf "$(colorize GREEN from:) $source_dir \n"
        printf "$(colorize GREEN to:) $target_dir \n"
        printf "$(colorize GREEN encryption:)  $([[ $encryption == 1 ]] && echo Enabled || echo $(colorize RED Disabled)) \n"
        printf "Proceed? (Y/N) "

        local answer
        read answer
        case $answer in
        [yY])
            echo Taking the backup...
            ;;

        *)
            echo exiting...
            exit
            ;;
        esac
    fi

    if [[ $restore == 0 ]]; then
        backup "$source_dir" "$target_dir" $encryption "$passphrase"
    fi
}

[ "${BASH_SOURCE[0]}" = "$0" ] && main "$@"
