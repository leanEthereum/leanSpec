#!/bin/bash
#
# Intercepts legacy Python commands and suggests modern uv alternatives.
#
# This hook runs before Bash tool execution to guide Claude toward
# using uv-based commands instead of legacy pip/python commands.

# Read the tool input from stdin
INPUT=$(cat)

# Extract the command being executed
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

# If no command found, allow through
if [ -z "$COMMAND" ]; then
    exit 0
fi

# Function to block with a suggestion
block_with_suggestion() {
    local suggestion="$1"
    echo "BLOCKED: This repository uses uv for package management."
    echo ""
    echo "Suggested alternative: $suggestion"
    echo ""
    echo "See CLAUDE.md for the full development workflow."
    exit 2
}

# Allow diagnostic commands
if echo "$COMMAND" | grep -qE '^(which python|python --version|python3 --version)'; then
    exit 0
fi

# Allow commands that already use uv run
if echo "$COMMAND" | grep -qE '(^|&&|\|)\s*uv run'; then
    exit 0
fi

# Allow grep/find/etc. commands that just contain "python" as a search term
if echo "$COMMAND" | grep -qE '^(grep|rg|find|ls|cat|head|tail|awk|sed)\s'; then
    exit 0
fi

# Intercept pip install
if echo "$COMMAND" | grep -qE '(^|\s|&&|\|)(pip|pip3)\s+install\s'; then
    # Extract package name if present
    PKG=$(echo "$COMMAND" | grep -oE '(pip|pip3)\s+install\s+[^&|;]+' | sed 's/.*install\s*//' | awk '{print $1}')
    if [ -n "$PKG" ]; then
        block_with_suggestion "uv add $PKG"
    else
        block_with_suggestion "uv add <package>"
    fi
fi

# Intercept pip uninstall
if echo "$COMMAND" | grep -qE '(^|\s|&&|\|)(pip|pip3)\s+uninstall\s'; then
    PKG=$(echo "$COMMAND" | grep -oE '(pip|pip3)\s+uninstall\s+[^&|;]+' | sed 's/.*uninstall\s*//' | awk '{print $1}')
    if [ -n "$PKG" ]; then
        block_with_suggestion "uv remove $PKG"
    else
        block_with_suggestion "uv remove <package>"
    fi
fi

# Intercept pip freeze
if echo "$COMMAND" | grep -qE '(^|\s|&&|\|)(pip|pip3)\s+freeze'; then
    block_with_suggestion "uv export"
fi

# Intercept python -m pip
if echo "$COMMAND" | grep -qE '(^|\s|&&|\|)python3?\s+-m\s+pip'; then
    block_with_suggestion "uv add/remove/sync (depending on operation)"
fi

# Intercept bare python/python3 script execution
if echo "$COMMAND" | grep -qE '(^|\s|&&|\|)python3?\s+[^-].*\.py'; then
    # Extract the script path
    SCRIPT=$(echo "$COMMAND" | grep -oE 'python3?\s+[^&|;]+\.py' | sed 's/python3\?\s*//')
    if [ -n "$SCRIPT" ]; then
        block_with_suggestion "uv run python $SCRIPT"
    else
        block_with_suggestion "uv run python <script.py>"
    fi
fi

# Intercept bare python/python3 with module flag (except -m pip which is handled above)
if echo "$COMMAND" | grep -qE '(^|\s|&&|\|)python3?\s+-m\s+(?!pip)'; then
    MODULE=$(echo "$COMMAND" | grep -oE 'python3?\s+-m\s+\S+' | sed 's/python3\?\s*-m\s*//')
    if [ -n "$MODULE" ]; then
        block_with_suggestion "uv run python -m $MODULE"
    else
        block_with_suggestion "uv run python -m <module>"
    fi
fi

# Allow everything else
exit 0
