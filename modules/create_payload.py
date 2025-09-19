"""
Create Payload Module - Generate various types of payloads using Metasploit
"""

import os
import subprocess
from .colors import Colors
from .exit_handler import ExitHandler
from .payloads.windows_payloads import WindowsPayloads
from .payloads.linux_payloads import LinuxPayloads
from .payloads.macos_payloads import MacOSPayloads
from .payloads.android_payloads import AndroidPayloads
from .payloads.java_payloads import JavaPayloads
from .payloads.web_payloads import WebPayloads

class CreatePayload:
    def __init__(self):
        self.colors = Colors()
        self.exit_handler = ExitHandler()
        self.windows_payloads = WindowsPayloads()
        self.linux_payloads = LinuxPayloads()
        self.macos_payloads = MacOSPayloads()
        self.android_payloads = AndroidPayloads()
        self.java_payloads = JavaPayloads()
        self.web_payloads = WebPayloads()
        self.payload_categories = {
            'windows': {
                'name': 'Windows',
                'description': 'Generate Windows payloads (EXE, DLL, PowerShell)',
                'formats': ['exe', 'dll', 'ps1'],
                'payloads': {
                    'meterpreter': {
                        'name': 'Meterpreter',
                        'description': 'Advanced payload with post-exploitation capabilities',
                        'types': {
                            'reverse_tcp': 'Meterpreter TCP Reverse - Connect back via TCP',
                            'reverse_https': 'Meterpreter HTTPS Reverse - Connect back via HTTPS',
                            'reverse_http': 'Meterpreter HTTP Reverse - Connect back via HTTP',
                            'bind_tcp': 'Meterpreter TCP Bind - Listen for connection'
                        }
                    },
                    'shell': {
                        'name': 'Command Shell',
                        'description': 'Basic command shell payload',
                        'types': {
                            'reverse_tcp': 'Shell TCP Reverse - Connect back via TCP',
                            'reverse_https': 'Shell HTTPS Reverse - Connect back via HTTPS',
                            'bind_tcp': 'Shell TCP Bind - Listen for connection'
                        }
                    }
                }
            },
            'linux': {
                'name': 'Linux',
                'description': 'Generate Linux payloads (ELF, Shellcode)',
                'formats': ['elf', 'raw'],
                'payloads': {
                    'meterpreter': {
                        'name': 'Meterpreter',
                        'description': 'Advanced payload with post-exploitation capabilities',
                        'types': {
                            'reverse_tcp': 'Meterpreter TCP Reverse - Connect back via TCP',
                            'reverse_https': 'Meterpreter HTTPS Reverse - Connect back via HTTPS',
                            'bind_tcp': 'Meterpreter TCP Bind - Listen for connection'
                        }
                    },
                    'shell': {
                        'name': 'Command Shell',
                        'description': 'Basic command shell payload',
                        'types': {
                            'reverse_tcp': 'Shell TCP Reverse - Connect back via TCP',
                            'bind_tcp': 'Shell TCP Bind - Listen for connection'
                        }
                    }
                }
            },
            'macos': {
                'name': 'macOS',
                'description': 'Generate macOS payloads (MACHO)',
                'formats': ['macho'],
                'payloads': {
                    'meterpreter': {
                        'name': 'Meterpreter',
                        'description': 'Advanced payload with post-exploitation capabilities',
                        'types': {
                            'reverse_tcp': 'Meterpreter TCP Reverse - Connect back via TCP',
                            'reverse_https': 'Meterpreter HTTPS Reverse - Connect back via HTTPS'
                        }
                    },
                    'shell': {
                        'name': 'Command Shell',
                        'description': 'Basic command shell payload',
                        'types': {
                            'reverse_tcp': 'Shell TCP Reverse - Connect back via TCP'
                        }
                    }
                }
            },
            'android': {
                'name': 'Android',
                'description': 'Generate Android payloads (APK)',
                'formats': ['apk'],
                'payloads': {
                    'meterpreter': {
                        'name': 'Meterpreter',
                        'description': 'Advanced payload with post-exploitation capabilities',
                        'types': {
                            'reverse_tcp': 'Meterpreter TCP Reverse - Connect back via TCP',
                            'reverse_https': 'Meterpreter HTTPS Reverse - Connect back via HTTPS',
                            'reverse_http': 'Meterpreter HTTP Reverse - Connect back via HTTP'
                        }
                    },
                    'shell': {
                        'name': 'Command Shell',
                        'description': 'Basic command shell payload',
                        'types': {
                            'reverse_tcp': 'Shell TCP Reverse - Connect back via TCP',
                            'reverse_https': 'Shell HTTPS Reverse - Connect back via HTTPS'
                        }
                    }
                }
            },
            'java': {
                'name': 'Java',
                'description': 'Generate Java payloads (JAR)',
                'formats': ['jar'],
                'payloads': {
                    'meterpreter': {
                        'name': 'Meterpreter',
                        'description': 'Advanced payload with post-exploitation capabilities',
                        'types': {
                            'reverse_tcp': 'Meterpreter TCP Reverse - Connect back via TCP',
                            'reverse_https': 'Meterpreter HTTPS Reverse - Connect back via HTTPS'
                        }
                    },
                    'shell': {
                        'name': 'Command Shell',
                        'description': 'Basic command shell payload',
                        'types': {
                            'reverse_tcp': 'Shell TCP Reverse - Connect back via TCP'
                        }
                    }
                }
            },
            'web': {
                'name': 'Web',
                'description': 'Generate Web payloads (ASPX, JSP, PHP)',
                'formats': ['aspx', 'jsp', 'php'],
                'payloads': {
                    'meterpreter': {
                        'name': 'Meterpreter',
                        'description': 'Advanced payload with post-exploitation capabilities',
                        'types': {
                            'reverse_tcp': 'Meterpreter TCP Reverse - Connect back via TCP',
                            'reverse_https': 'Meterpreter HTTPS Reverse - Connect back via HTTPS'
                        }
                    },
                    'shell': {
                        'name': 'Command Shell',
                        'description': 'Basic command shell payload',
                        'types': {
                            'reverse_tcp': 'Shell TCP Reverse - Connect back via TCP'
                        }
                    }
                }
            }
        }
    
    def display_banner(self):
        """Display the Create Payload banner"""
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
{self.colors.GREEN}Mail: {self.colors.BLUE}latifimods@gmail.com{self.colors.RESET}

{self.colors.RED}⚠️  WARNING: Educational and testing purposes only!{self.colors.RESET}
{self.colors.RED}⚠️  Use only in isolated environments with proper authorization!{self.colors.RESET}
{self.colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                   {self.colors.YELLOW}Payload Generation Framework{self.colors.CYAN}               ║
║                    {self.colors.RED}Educational Use Only{self.colors.CYAN}                      ║
╚══════════════════════════════════════════════════════════════╝{self.colors.RESET}
"""
        print(banner)
    
    def display_main_menu(self):
        """Display the main payload creation menu"""
        menu = f"""
{self.colors.BRIGHT_RED}╔══════════════════════════════════════════════════════════════╗
║                    {self.colors.BRIGHT_YELLOW}⚡ CREATE PAYLOAD ⚡{self.colors.BRIGHT_RED}                      ║
╠══════════════════════════════════════════════════════════════╣
║  {self.colors.BRIGHT_GREEN}1.{self.colors.RESET} {self.colors.BRIGHT_YELLOW}🪟 Windows (EXE/DLL/PowerShell){self.colors.RESET}                          ║
║  {self.colors.BRIGHT_GREEN}2.{self.colors.RESET} {self.colors.BRIGHT_MAGENTA}🐧 Linux (ELF, Shellcode){self.colors.RESET}                                ║
║  {self.colors.BRIGHT_GREEN}3.{self.colors.RESET} {self.colors.BRIGHT_CYAN}🍎 macOS (MACHO){self.colors.RESET}                                         ║
║  {self.colors.BRIGHT_GREEN}4.{self.colors.RESET} {self.colors.BRIGHT_BLUE}📱 Android (APK){self.colors.RESET}                                         ║ 
║  {self.colors.BRIGHT_GREEN}5.{self.colors.RESET} {self.colors.BRIGHT_GREEN}☕ Java (JAR){self.colors.RESET}                                            ║
║  {self.colors.BRIGHT_GREEN}6.{self.colors.RESET} {self.colors.BRIGHT_WHITE}🌐 Web (ASPX, JSP, PHP){self.colors.RESET}                                  ║
║  {self.colors.BRIGHT_GREEN}7.{self.colors.RESET} {self.colors.BRIGHT_RED}🔧 Other{self.colors.RESET}                                                 ║
║  {self.colors.BRIGHT_GREEN}8.{self.colors.RESET} {self.colors.BRIGHT_RED}🚪 Back to Main Menu{self.colors.RESET}                                     ║
╚══════════════════════════════════════════════════════════════╝{self.colors.RESET}
"""
        print(menu)
    
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
                print(f"\n{self.colors.BRIGHT_YELLOW}⚠️  Operation cancelled by user.{self.colors.RESET}")
                self.exit_handler.clean_exit(force=True)
            except Exception as e:
                print(f"{self.colors.BRIGHT_RED}💥 Error: {e}{self.colors.RESET}")
    
    def run(self):
        """Main payload creation function"""
        try:
            print(f"{self.colors.BRIGHT_CYAN}🚀 Starting Payload Creation Manager...{self.colors.RESET}")
            
            while True:
                self.display_banner()
                self.display_main_menu()
                
                choice = self.get_user_choice(8)
                
                if choice == 1:
                    self.handle_windows_payloads()
                elif choice == 2:
                    self.handle_linux_payloads()
                elif choice == 3:
                    self.handle_macos_payloads()
                elif choice == 4:
                    self.handle_android_payloads()
                elif choice == 5:
                    self.handle_java_payloads()
                elif choice == 6:
                    self.handle_web_payloads()
                elif choice == 7:
                    self.handle_other_payloads()
                elif choice == 8:
                    print(f"\n{self.colors.BRIGHT_CYAN}🚪 Returning to main menu...{self.colors.RESET}")
                    break
                
                # Pause before next iteration
                if choice != 8:
                    input(f"\n{self.colors.BRIGHT_CYAN}⏎ Press Enter to continue...{self.colors.RESET}")
                    os.system('clear' if os.name == 'posix' else 'cls')
            
            print(f"\n{self.colors.BRIGHT_GREEN}🏁 Payload creation completed!{self.colors.RESET}")
        except KeyboardInterrupt:
            print(f"\n{self.colors.BRIGHT_YELLOW}⚠️  Application interrupted by user.{self.colors.RESET}")
            self.exit_handler.clean_exit(force=True)
        except Exception as e:
            print(f"{self.colors.BRIGHT_RED}💥 Fatal error in payload creation: {e}{self.colors.RESET}")
            self.exit_handler.clean_exit(force=True)
    
    def handle_windows_payloads(self):
        """Handle Windows payload creation"""
        self.windows_payloads.run()
    
    def handle_linux_payloads(self):
        """Handle Linux payload creation"""
        self.linux_payloads.run()
    
    def handle_macos_payloads(self):
        """Handle macOS payload creation"""
        self.macos_payloads.run()
    
    def handle_android_payloads(self):
        """Handle Android payload creation"""
        self.android_payloads.run()
    
    def handle_java_payloads(self):
        """Handle Java payload creation"""
        self.java_payloads.run()
    
    def handle_web_payloads(self):
        """Handle Web payload creation"""
        self.web_payloads.run()
    
    def handle_other_payloads(self):
        """Handle Other payload creation"""
        print(f"\n{self.colors.BRIGHT_RED}🔧 Other Payload Creation{self.colors.RESET}")
        print(f"{self.colors.BRIGHT_CYAN}Description: {self.colors.BRIGHT_WHITE}Custom and specialized payloads{self.colors.RESET}")
        print(f"\n{self.colors.BRIGHT_GREEN}✅ Other payload creation module loaded!{self.colors.RESET}")
        print(f"{self.colors.BRIGHT_YELLOW}💡 This will be implemented in the next step...{self.colors.RESET}")
