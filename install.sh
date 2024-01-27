#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status.

# Function to safely execute a command with error handling
safe_run() {
    if ! "$@"; then
        echo "Error: Failed to execute: $*"
        exit 1
    fi
}

# Check if ept.py is in the same directory as this install.sh script
if [ ! -f "$(dirname "$0")/ept.py" ]; then
    echo "Error: Please run this script from the same directory as ept.py"
    exit 1
fi

# Check if /tools/ept/ exists in the home directory of the user; if not, create it
EPT_DIR="$HOME/tools/ept"
if [ ! -d "$EPT_DIR" ]; then
    safe_run mkdir -p "$EPT_DIR"
fi

# Function to move files maintaining the structure
move_files() {
    # Find all files and directories except the script itself and move them
    safe_run find . -mindepth 1 -maxdepth 1 ! -name "$(basename "$0")" -exec mv -t "$EPT_DIR" -- {} +
}

# Set executable permissions for .sh and .py files only
set_executable_permissions() {
    safe_run find . -type f \( -name "*.sh" -o -name "*.py" \) -exec chmod +x {} +
}

# Invoke the function to move files
move_files

# Invoke the function to set executable permissions
set_executable_permissions

# Ask the user if they use bash or zsh
echo "Do you use bash or zsh? (bash/zsh): "
read shell_type

# Create .zshrc_aliases or .bashrc_aliases if it doesn't exist and add alias
if [ "$shell_type" = "zsh" ]; then
    ZSHRC="$HOME/.zshrc"
    ALIAS_FILE="$HOME/.zshrc"
    safe_run touch "$ALIAS_FILE"
    echo "alias ept='python3 $EPT_DIR/ept.py'" >> "$ALIAS_FILE"
    if ! grep -q "source $ALIAS_FILE" "$ZSHRC"; then
        echo "source $ALIAS_FILE" >> "$ZSHRC"
    fi
elif [ "$shell_type" = "bash" ]; then
    ALIAS_FILE="$HOME/.bashrc"
    safe_run touch "$ALIAS_FILE"
    echo "alias ept='python3 $EPT_DIR/ept.py'" >> "$ALIAS_FILE"
else
    echo "Unsupported shell type. Please manually set the alias in your shell configuration file."
    exit 1
fi

# Inform the user to restart their shell or source their configuration file
if [ "$shell_type" = "zsh" ]; then
    echo "Installation complete. Please restart your terminal or run 'source ~/.zshrc'."
else
    echo "Installation complete. Please restart your terminal or source your $ALIAS_FILE."
fi