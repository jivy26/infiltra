#!/bin/bash

# Check if ept.py is in the same directory as this install.sh script
if [ ! -f "$(dirname "$0")/ept.py" ]; then
    echo "Error: Please run this script from the same directory as ept.py"
    exit 1
fi

# Check if /tools/ept/ exists in the home directory of the user; if not, create it
EPT_DIR="$HOME/tools/ept"
if [ ! -d "$EPT_DIR" ]; then
    mkdir -p "$EPT_DIR"
fi

# Function to move files maintaining the structure
move_files() {
    # Assuming the script is run from the directory where files are located
    # Find all files and directories except the script itself and move them
    find . -mindepth 1 -maxdepth 1 ! -name "$(basename "$0")" -exec mv -t "$EPT_DIR" -- {} +
}

# Set executable permissions for .sh and .py files only
set_executable_permissions() {
    find . -type f \( -name "*.sh" -o -name "*.py" \) -exec chmod +x {} +
}

# Invoke the function to move files
move_files

# Invoke the function to set executable permissions
set_executable_permissions

# Ask the user if they use bash or zsh
echo "Do you use bash or zsh? (bash/zsh): "
read shell_type

# Edit the appropriate shell configuration file to ensure the alias is set
if [ "$shell_type" = "bash" ]; then
    RC_FILE="$HOME/.bashrc_aliases"
elif [ "$shell_type" = "zsh" ]; then
    RC_FILE="$HOME/.zshrc_aliases"
else
    echo "Unsupported shell type. Please manually set the alias in your shell configuration file."
    exit 1
fi

# Add alias to the shell configuration file
echo "alias ept='python3 $EPT_DIR/ept.py'" >> "$RC_FILE"

# Source the shell configuration file if possible
if [ -f "$RC_FILE" ]; then
    source "$RC_FILE"
fi

# Inform the user to restart their shell or source their configuration file
echo "Installation complete. Please restart your terminal or source your $RC_FILE."