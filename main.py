#shree ganeshaya namaha

# Suppress cryptography deprecation warning - MUST BE FIRST
import warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)

# Importing required libraries
import os
import getpass
import ctypes
from scapy.all import sniff, RadioTap
import pydantic
import sqlite3
import dotenv
from rich.console import Console
import p_15.test as test
import p_15.snifer as snifer

console = Console()
# Used for building the dashboard in future features
import fastapi

# All functions are invoked and compiled here for further use
# Welcome and presentation message shown to the user
def main():
    console.print("[bold green]Welcome to the P_15..........(Network Sniffer and Analyzer Tool)[/bold green]")
    console.print("[bold yellow]Checking for root/administrator privileges...[/bold yellow]")    
    test.root_check()
    test.console.print("[bold yellow]Checking for network interfaces...[/bold yellow]")
    selected_interface = test.check_network_interface()
    if not selected_interface:
        return
    if test.check_test_runn(selected_interface) == True:
        console.print("[bold green]All checks passed. Proceeding with the script.[/bold green]")
        test.api_ai_keys_save()
        snifer.packet_sniffer(selected_interface)
    else:
        console.print("[bold red]One or more checks failed. Please check your network settings and try again.[/bold red]")
        console.print("[bold yellow] Please make sure your wifi card is up and running and supported [/bold yellow]")  
    
# Entry point for the application
if __name__ == "__main__":
    main()