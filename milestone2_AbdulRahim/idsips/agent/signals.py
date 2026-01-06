"""
Handle signals like Ctrl+C.
"""

import signal

# Global flag to stop the program
stop_flag = {"flag": False}

def signal_handler(signum, frame):
    # Set flag when signal received
    stop_flag["flag"] = True

def install_sigint_handler():
    # Install handler for SIGINT (Ctrl+C)
    signal.signal(signal.SIGINT, signal_handler)
    return stop_flag
