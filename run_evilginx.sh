#!/bin/bash

# Evilginx2 startup script with automatic recovery from panics

echo "Starting Evilginx2 with automatic recovery..."

# Function to run evilginx with recovery
run_with_recovery() {
    while true; do
        echo "[$(date)] Starting Evilginx2..."
        
        # Run evilginx2
        ./evilginx -c /root/.evilginx
        
        # Check exit code
        EXIT_CODE=$?
        
        if [ $EXIT_CODE -eq 0 ]; then
            echo "[$(date)] Evilginx2 exited normally"
            break
        else
            echo "[$(date)] Evilginx2 crashed with exit code $EXIT_CODE"
            echo "[$(date)] Restarting in 5 seconds..."
            sleep 5
        fi
    done
}

# Set up environment
cd /root/evilginx2

# Run with recovery
run_with_recovery
