# This file contains all checks performed before running the tool
import os
import getpass
import ctypes
import psutil
from scapy.all import get_if_list, sniff, RadioTap
import pydantic
import sqlite3
import dotenv
import psutil
from rich.console import Console
console = Console()
# Used for building the dashboard in future features
import fastapi


# Network interface check


def check_network_interface():
    # Fetch all interfaces and filter for 'eth' or 'en'
    net_stats = psutil.net_if_stats()
    eth_interfaces = [name for name in net_stats.keys() if name.startswith(('eth', 'en'))]
    
    if not eth_interfaces:
        console.print("[bold red]No ethernet interfaces found. Please check your network settings.[/bold red]")
        console.print("[bold yellow]Please make sure your ethernet card is up and running and supported[/bold yellow]")
        return None
    
    console.print("[bold green]Available Ethernet interfaces:[/bold green]")
    for interface in eth_interfaces:
        status_color = "green" if net_stats[interface].isup else "red"
        status_text = "UP" if net_stats[interface].isup else "DOWN"
        console.print(f"[bold yellow]{interface}[/bold yellow] - [{status_color}]{status_text}[/{status_color}]")
    
    Usr_choose_interface = input("Please select the ethernet interface you want to use for sniffing: ").strip()
    
    if Usr_choose_interface not in eth_interfaces:
        console.print("[bold red]Invalid interface selected. Please select a valid ethernet interface and try again.[/bold red]")
        return check_network_interface()
    
    if net_stats[Usr_choose_interface].isup:
        console.print(f"[bold green]Ethernet interface {Usr_choose_interface} is up and running.[/bold green]")
        return Usr_choose_interface
    else:
        console.print(f"[bold red]Ethernet interface {Usr_choose_interface} is down. Please check your network settings.[/bold red]")
        return check_network_interface()


def root_check():#
    if os.name == 'posix':
        if os.geteuid() != 0:
            console.print("[bold red]Please run the script as root or with sudo privileges.[/bold red]")
        else:
            console.print("[bold green]Root privileges confirmed. Proceeding with the script.[/bold green]")
            console.print("[bold yellow] Moveing forward with the setup [/bold yellow]")
    elif os.name == 'nt':
        if not ctypes.windll.shell32.IsUserAnAdmin():
            console.print("[bold red]Please run the script as Administrator.[/bold red]")
        else:
            console.print("[bold green]Administrator privileges confirmed. Proceeding with the script.[/bold green]")
            console.print("[bold yellow] Moveing forward with the setup [/bold yellow]")
    else:
        console.print("[bold red]Unsupported operating system. This script is designed for Linux and Windows only.[/bold red]")
        pass

 
# Confirm the selected ethernet interface is available
def check_test_runn(iface):
    console.print("[bold yellow]Checking for test run...[/bold yellow]")
    pkts = sniff(iface=iface, count=1, timeout=2)
    if pkts and len(pkts) > 0:
        console.print("[bold green]Test run successful. Packets are being captured.[/bold green]")
        return True
    else:
        console.print("[bold red]Test run failed. No packets captured. Please check your network settings and try again.[/bold red]")
        console.print("[bold yellow] Please make sure your wifi card is up and running and supported [/bold yellow]")
        return False
    
# Collect AI API keys upfront to avoid interruption later
def api_ai_keys_save():
    """Collect and save API keys for the supported AI providers."""
    env_file = os.path.join(os.path.dirname(__file__), ".env")
    providers = {
        "OpenAI": "OPENAI_API_KEY",
        "Gemini": "GEMINI_API_KEY",
        "Anthropic": "ANTHROPIC_API_KEY",
        "Hugging Face": "HF_TOKEN",
    }
    saved_keys = {}

    console.print("[bold yellow]Enter API keys below. Leave a prompt blank to skip it.[/bold yellow]")
    for provider, env_name in providers.items():
        api_key = getpass.getpass(f"Enter your {provider} API key: ")
        if api_key:
            dotenv.set_key(env_file, env_name, api_key)
            saved_keys[env_name] = api_key

    console.print(f"[bold green]Saved {len(saved_keys)} AI API key(s) to .env.[/bold green]")
    return saved_keys
