#!/usr/bin/env python3
"""
Metasploit Manager - Security Testing Tool
Created by @apt_start_latifi / iddox
Website: https://www.iddox.tech/
Discord: https://discord.gg/KcuMUUAP5T
Mail : latifimods@gmail.com

WARNING: This tool is for educational and testing purposes only!
Use only in isolated environments with proper authorization.
"""

import sys
import os
from modules.colors import Colors
from modules.check_system import CheckSystem
from modules.metasploit_db import MetasploitDatabase
from modules.create_payload import CreatePayload
from modules.manage_payload import ManagePayload
from modules.file_analysis import FileAnalyzer
from modules.credits import Credits
from modules.exit_handler import ExitHandler

class MetasploitManager:
    def __init__(self):
        self.colors = Colors()
        self.check_system = CheckSystem()
        self.metasploit_db = MetasploitDatabase()
        self.create_payload = CreatePayload()
        self.manage_payload = ManagePayload()
        self.file_analyzer = FileAnalyzer()
        self.credits = Credits()
        self.exit_handler = ExitHandler()
        
    def display_banner(self):
        """Display the main banner with MetaDox ASCII art"""
        ascii_art = f"""
{self.colors.CYAN}   ▄▄▄▄███▄▄▄▄      ▄████████     ███        ▄████████ ████████▄   ▄██████▄  ▀████    ▐████▀ 
 ▄██▀▀▀███▀▀▀██▄   ███    ███ ▀█████████▄   ███    ███ ███   ▀███ ███    ███   ███▌   ████▀  
 ███   ███   ███   ███    █▀     ▀███▀▀██   ███    ███ ███    ███ ███    ███    ███  ▐███    
 ███   ███   ███  ▄███▄▄▄         ███   ▀   ███    ███ ███    ███ ███    ███    ▀███▄███▀    
 ███   ███   ███ ▀▀███▀▀▀         ███     ▀███████████ ███    ███ ███    ███    ████▀██▄     
 ███   ███   ███   ███    █▄      ███       ███    ███ ███    ███ ███    ███   ▐███  ▀███    
 ███   ███   ███   ███    ███     ███       ███    ███ ███   ▄███ ███    ███  ▄███     ███▄  
  ▀█   ███   █▀    ██████████    ▄████▀     ███    █▀  ████████▀   ▀██████▀  ████       ███▄ {self.colors.RESET}"""

        banner = f"""
{ascii_art}
{self.colors.GREEN}Created by: {self.colors.YELLOW}@apt_start_latifi / iddox{self.colors.RESET}
{self.colors.GREEN}Website: {self.colors.BLUE}https://www.iddox.tech/{self.colors.RESET}
{self.colors.GREEN}Discord: {self.colors.BLUE}https://discord.gg/KcuMUUAP5T{self.colors.RESET}

{self.colors.RED}⚠️  WARNING: Educational and testing purposes only!{self.colors.RESET}
{self.colors.RED}⚠️  Use only in isolated environments with proper authorization!{self.colors.RESET}
{self.colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                   {self.colors.YELLOW}Security Testing Framework{self.colors.CYAN}                 ║
║                    {self.colors.RED}Educational Use Only{self.colors.CYAN}                      ║
╚══════════════════════════════════════════════════════════════╝{self.colors.RESET}

"""
        print(banner)
    
    def display_menu(self):
        """Display the main menu with improved design"""
        menu = f"""
{self.colors.BRIGHT_RED}╔══════════════════════════════════════════════════════════════╗
║                        {self.colors.BRIGHT_YELLOW}🔧 MAIN MENU 🔧{self.colors.BRIGHT_RED}                       ║
╠══════════════════════════════════════════════════════════════╣
║  {self.colors.BRIGHT_GREEN}1.{self.colors.RESET} {self.colors.BRIGHT_YELLOW}🔍 Check System{self.colors.RESET}                                          ║
║  {self.colors.BRIGHT_GREEN}2.{self.colors.RESET} {self.colors.BRIGHT_MAGENTA}🗄️  Check Metasploit Database{self.colors.RESET}                             ║
║  {self.colors.BRIGHT_GREEN}3.{self.colors.RESET} {self.colors.BRIGHT_CYAN}⚡ Create Payload{self.colors.RESET}                                        ║
║  {self.colors.BRIGHT_GREEN}4.{self.colors.RESET} {self.colors.BRIGHT_BLUE}📋 Manage Payload{self.colors.RESET}                                        ║
║  {self.colors.BRIGHT_GREEN}5.{self.colors.RESET} {self.colors.BRIGHT_GREEN}🔬 Analyse File for Payloads{self.colors.RESET}                             ║
║  {self.colors.BRIGHT_GREEN}6.{self.colors.RESET} {self.colors.BRIGHT_WHITE}ℹ️  Credits{self.colors.RESET}                                               ║
║  {self.colors.BRIGHT_GREEN}7.{self.colors.RESET} {self.colors.BRIGHT_RED}🚪 Exit{self.colors.RESET}                                                  ║
╚══════════════════════════════════════════════════════════════╝{self.colors.RESET}
"""
        print(menu)
    
    def get_user_choice(self):
        """Get user input for menu choice"""
        while True:
            try:
                choice = input(f"{self.colors.BRIGHT_YELLOW}🎯 Enter your choice (1-7): {self.colors.RESET}")
                if choice in ['1', '2', '3', '4', '5', '6', '7']:
                    return int(choice)
                else:
                    print(f"{self.colors.BRIGHT_RED}❌ Invalid choice! Please enter a number between 1-7.{self.colors.RESET}")
            except KeyboardInterrupt:
                print(f"\n{self.colors.BRIGHT_YELLOW}⚠️  Operation cancelled by user.{self.colors.RESET}")
                self.exit_handler.clean_exit(force=True)
            except Exception as e:
                print(f"{self.colors.BRIGHT_RED}💥 Error: {e}{self.colors.RESET}")
    
    def handle_menu_choice(self, choice):
        """Handle the selected menu choice"""
        if choice == 1:
            self.check_system.run()
        elif choice == 2:
            self.metasploit_db.run()
        elif choice == 3:
            self.create_payload.run()
        elif choice == 4:
            self.manage_payload.run()
        elif choice == 5:
            self.file_analyzer.run()
        elif choice == 6:
            self.credits.show()
        elif choice == 7:
            self.exit_handler.clean_exit()
    
    def run(self):
        """Main application loop"""
        try:
            while True:
                self.display_banner()
                self.display_menu()
                choice = self.get_user_choice()
                self.handle_menu_choice(choice)
                
                if choice != 7:  # Don't pause if user chose exit
                    input(f"\n{self.colors.BRIGHT_CYAN}⏎ Press Enter to continue...{self.colors.RESET}")
                    os.system('clear' if os.name == 'posix' else 'cls')
        except KeyboardInterrupt:
            print(f"\n{self.colors.BRIGHT_YELLOW}⚠️  Application interrupted by user.{self.colors.RESET}")
            self.exit_handler.clean_exit(force=True)
        except Exception as e:
            print(f"{self.colors.BRIGHT_RED}💥 Fatal error: {e}{self.colors.RESET}")
            self.exit_handler.clean_exit(force=True)

if __name__ == "__main__":
    app = MetasploitManager()
    app.run()
