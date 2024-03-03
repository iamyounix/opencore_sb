#!/bin/bash

# Function to launch main.py
launch_main() {
    python3 lib/main.py
}

# Function to launch add.py
launch_add() {
    python3 lib/add.py
}

# Main menu
while true; do
    echo "Choose an option:"
    echo "1. Generate all keys, download and Signing OpenCore Package"
    echo "2. Signing Current systemd-boot"
    echo "3. Exit"
    read -p "Enter your choice: " choice

    case $choice in
        1) 
            launch_main
            ;;
        2) 
            launch_add
            ;;
        3) 
            exit
            ;;
        *) 
            echo "Invalid choice. Please enter 1, 2, or 3."
            ;;
    esac

    # Ask user if they want to return to main menu or exit
    read -p "Press 'm' to return to the main menu, 'q' to quit: " continue_choice

    case $continue_choice in
        [mM]) 
            continue
            ;;
        [qQ]) 
            exit
            ;;
        *) 
            echo "Invalid choice. Exiting."
            exit
            ;;
    esac
done

