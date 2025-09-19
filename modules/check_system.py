"""
System Check Module - Detects OS and checks dependencies
"""

import platform
import subprocess
import shutil
import os
from .colors import Colors

class CheckSystem:
    def __init__(self):
        self.colors = Colors()
        self.system_info = {}
        self.dependencies = {
            'metasploit': ['msfconsole', 'msfvenom', 'msfdb'],
            'python': ['python3', 'pip3'],
            'nmap': ['nmap'],
            'wireshark': ['wireshark', 'tshark'],
            'john': ['john'],
            'hashcat': ['hashcat'],
            'aircrack': ['aircrack-ng'],
            'burpsuite': ['burpsuite'],
            'sqlmap': ['sqlmap'],
            'nikto': ['nikto']
        }
    
    def detect_os(self):
        """Detect the operating system"""
        try:
            system = platform.system().lower()
            distro = "Unknown"
            
            if system == "linux":
                # Try to detect specific Linux distribution
                try:
                    with open('/etc/os-release', 'r') as f:
                        for line in f:
                            if line.startswith('PRETTY_NAME='):
                                distro = line.split('=')[1].strip().strip('"')
                                break
                            elif line.startswith('ID='):
                                distro_id = line.split('=')[1].strip().strip('"')
                                if distro_id in ['parrot', 'kali', 'ubuntu', 'debian', 'arch', 'fedora', 'centos']:
                                    distro = distro_id.title()
                except:
                    distro = "Linux"
            elif system == "darwin":
                distro = "macOS"
            elif system == "windows":
                distro = "Windows"
            
            self.system_info = {
                'system': system,
                'distro': distro,
                'version': platform.version(),
                'architecture': platform.machine(),
                'python_version': platform.python_version()
            }
            
            return True
        except Exception as e:
            print(f"{self.colors.error('Error detecting OS:')} {e}")
            return False
    
    def check_dependency(self, dependency_name, commands):
        """Check if a dependency is installed"""
        results = {}
        
        for command in commands:
            if shutil.which(command):
                results[command] = True
            else:
                results[command] = False
        
        return results
    
    def check_all_dependencies(self):
        """Check all security tool dependencies"""
        dependency_results = {}
        
        for tool, commands in self.dependencies.items():
            dependency_results[tool] = self.check_dependency(tool, commands)
        
        return dependency_results
    
    def display_system_info(self):
        """Display system information"""
        print(f"\n{self.colors.BRIGHT_RED}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                        {self.colors.BRIGHT_YELLOW}🖥️  SYSTEM INFORMATION 🖥️{self.colors.BRIGHT_RED}               ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{self.colors.RESET}")
        
        print(f"{self.colors.BRIGHT_YELLOW}🖥️  Operating System:{self.colors.RESET} {self.colors.BRIGHT_RED}{self.system_info['distro']}{self.colors.RESET}")
        print(f"{self.colors.BRIGHT_MAGENTA}⚙️  System Type:{self.colors.RESET} {self.colors.BRIGHT_RED}{self.system_info['system']}{self.colors.RESET}")
        print(f"{self.colors.BRIGHT_CYAN}🏗️  Architecture:{self.colors.RESET} {self.colors.BRIGHT_RED}{self.system_info['architecture']}{self.colors.RESET}")
        print(f"{self.colors.BRIGHT_GREEN}🐍 Python Version:{self.colors.RESET} {self.colors.BRIGHT_RED}{self.system_info['python_version']}{self.colors.RESET}")
        
        if self.system_info['system'] == 'linux':
            print(f"{self.colors.BRIGHT_BLUE}🔧 Kernel Version:{self.colors.RESET} {self.colors.BRIGHT_RED}{self.system_info['version']}{self.colors.RESET}")
    
    def display_dependency_results(self, dependency_results):
        """Display dependency check results"""
        print(f"\n{self.colors.BRIGHT_RED}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                      {self.colors.BRIGHT_YELLOW}🔍 DEPENDENCY CHECK 🔍{self.colors.BRIGHT_RED}                  ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{self.colors.RESET}")
        
        # Define colors for each tool category
        tool_colors = {
            'metasploit': self.colors.BRIGHT_YELLOW,
            'python': self.colors.BRIGHT_MAGENTA,
            'nmap': self.colors.BRIGHT_CYAN,
            'wireshark': self.colors.BRIGHT_BLUE,
            'john': self.colors.BRIGHT_GREEN,
            'hashcat': self.colors.BRIGHT_WHITE,
            'aircrack': self.colors.BRIGHT_MAGENTA,
            'burpsuite': self.colors.BRIGHT_YELLOW,
            'sqlmap': self.colors.BRIGHT_MAGENTA,
            'nikto': self.colors.BRIGHT_CYAN
        }
        
        # Convert to list for easier handling
        tools_list = list(dependency_results.items())
        
        # Display tools in pairs (2 per row)
        for i in range(0, len(tools_list), 2):
            # First tool in the row
            tool1, commands1 = tools_list[i]
            tool_color1 = tool_colors.get(tool1, self.colors.BRIGHT_WHITE)
            
            # Check if there's a second tool for this row
            if i + 1 < len(tools_list):
                tool2, commands2 = tools_list[i + 1]
                tool_color2 = tool_colors.get(tool2, self.colors.BRIGHT_WHITE)
                
                # Display both tools side by side with proper alignment
                print(f"\n{tool_color1}🔧 {tool1.upper():<12}{self.colors.RESET}                  {tool_color2}🔧 {tool2.upper():<12}{self.colors.RESET}")
                
                # Display commands for both tools
                max_commands = max(len(commands1), len(commands2))
                for j in range(max_commands):
                    # First tool command
                    if j < len(commands1):
                        cmd1, installed1 = list(commands1.items())[j]
                        status1 = f"{self.colors.BRIGHT_GREEN}✅ INSTALLED{self.colors.RESET}" if installed1 else f"{self.colors.BRIGHT_RED}❌ NOT FOUND{self.colors.RESET}"
                        line1 = f"  {self.colors.BRIGHT_RED}{cmd1:<15}{self.colors.RESET} {status1}"
                    else:
                        line1 = "  " + " " * 30
                    
                    # Second tool command
                    if j < len(commands2):
                        cmd2, installed2 = list(commands2.items())[j]
                        status2 = f"{self.colors.BRIGHT_GREEN}✅ INSTALLED{self.colors.RESET}" if installed2 else f"{self.colors.BRIGHT_RED}❌ NOT FOUND{self.colors.RESET}"
                        line2 = f"  {self.colors.BRIGHT_RED}{cmd2:<15}{self.colors.RESET} {status2}"
                    else:
                        line2 = "  " + " " * 30
                    
                    print(f"{line1}    {line2}")
                
                # Summary for both tools
                all_installed1 = all(commands1.values())
                all_installed2 = all(commands2.values())
                
                summary1 = f"{self.colors.BRIGHT_GREEN}🎉 All {tool1} components available{self.colors.RESET}" if all_installed1 else f"{self.colors.BRIGHT_RED}⚠️  Some {tool1} components missing{self.colors.RESET}"
                summary2 = f"{self.colors.BRIGHT_GREEN}🎉 All {tool2} components available{self.colors.RESET}" if all_installed2 else f"{self.colors.BRIGHT_RED}⚠️  Some {tool2} components missing{self.colors.RESET}"
                
                print(f"  {summary1}    {summary2}")
            else:
                # Only one tool left (odd number)
                print(f"\n{tool_color1}🔧 {tool1.upper()}:{self.colors.RESET}")
                
                all_installed1 = True
                for command, is_installed in commands1.items():
                    if is_installed:
                        status = f"{self.colors.BRIGHT_GREEN}✅ INSTALLED{self.colors.RESET}"
                    else:
                        status = f"{self.colors.BRIGHT_RED}❌ NOT FOUND{self.colors.RESET}"
                    print(f"  {self.colors.BRIGHT_RED}{command:<15}{self.colors.RESET} {status}")
                    if not is_installed:
                        all_installed1 = False
                
                if all_installed1:
                    print(f"  {self.colors.BRIGHT_GREEN}🎉 All {tool1} components are available{self.colors.RESET}")
                else:
                    print(f"  {self.colors.BRIGHT_RED}⚠️  Some {tool1} components are missing{self.colors.RESET}")
    
    def get_installation_commands(self, dependency_results):
        """Get installation commands for missing dependencies"""
        print(f"\n{self.colors.BRIGHT_RED}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    {self.colors.BRIGHT_YELLOW}📦 INSTALLATION COMMANDS 📦{self.colors.BRIGHT_RED}                  ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{self.colors.RESET}")
        
        distro = self.system_info['distro'].lower()
        
        installation_commands = {
            'parrot': {
                'metasploit': 'sudo apt update && sudo apt install metasploit-framework',
                'nmap': 'sudo apt install nmap',
                'wireshark': 'sudo apt install wireshark',
                'john': 'sudo apt install john',
                'hashcat': 'sudo apt install hashcat',
                'aircrack': 'sudo apt install aircrack-ng',
                'burpsuite': 'sudo apt install burpsuite',
                'sqlmap': 'sudo apt install sqlmap',
                'nikto': 'sudo apt install nikto'
            },
            'kali': {
                'metasploit': 'sudo apt update && sudo apt install metasploit-framework',
                'nmap': 'sudo apt install nmap',
                'wireshark': 'sudo apt install wireshark',
                'john': 'sudo apt install john',
                'hashcat': 'sudo apt install hashcat',
                'aircrack': 'sudo apt install aircrack-ng',
                'burpsuite': 'sudo apt install burpsuite',
                'sqlmap': 'sudo apt install sqlmap',
                'nikto': 'sudo apt install nikto'
            },
            'ubuntu': {
                'metasploit': 'curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sudo bash',
                'nmap': 'sudo apt install nmap',
                'wireshark': 'sudo apt install wireshark',
                'john': 'sudo apt install john',
                'hashcat': 'sudo apt install hashcat',
                'aircrack': 'sudo apt install aircrack-ng',
                'sqlmap': 'sudo apt install sqlmap',
                'nikto': 'sudo apt install nikto'
            },
            'debian': {
                'metasploit': 'curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sudo bash',
                'nmap': 'sudo apt install nmap',
                'wireshark': 'sudo apt install wireshark',
                'john': 'sudo apt install john',
                'hashcat': 'sudo apt install hashcat',
                'aircrack': 'sudo apt install aircrack-ng',
                'sqlmap': 'sudo apt install sqlmap',
                'nikto': 'sudo apt install nikto'
            },
            'arch': {
                'metasploit': 'sudo pacman -S metasploit',
                'nmap': 'sudo pacman -S nmap',
                'wireshark': 'sudo pacman -S wireshark-cli',
                'john': 'sudo pacman -S john',
                'hashcat': 'sudo pacman -S hashcat',
                'aircrack': 'sudo pacman -S aircrack-ng',
                'sqlmap': 'sudo pacman -S sqlmap',
                'nikto': 'sudo pacman -S nikto'
            }
        }
        
        # Find the best match for the current distribution
        commands = None
        for distro_key in installation_commands:
            if distro_key in distro:
                commands = installation_commands[distro_key]
                break
        
        if not commands:
            print(f"{self.colors.BRIGHT_YELLOW}⚠️  Installation commands not available for {self.system_info['distro']}{self.colors.RESET}")
            print(f"{self.colors.info('Please check your distribution')}'s package manager documentation.{self.colors.RESET}")
            return
        
        print(f"{self.colors.info('📋 Installation commands for')} {self.colors.BRIGHT_WHITE}{self.system_info['distro']}{self.colors.RESET}:")
        print()
        
        for tool, commands_result in dependency_results.items():
            missing_commands = [cmd for cmd, installed in commands_result.items() if not installed]
            if missing_commands and tool in commands:
                print(f"{self.colors.BRIGHT_WHITE}{self.colors.BOLD}🔧 {tool.upper()}:{self.colors.RESET}")
                print(f"  {self.colors.BRIGHT_CYAN}{commands[tool]}{self.colors.RESET}")
                print()
    
    def run(self):
        """Main system check function"""
        print(f"{self.colors.BRIGHT_CYAN}🚀 Starting system check...{self.colors.RESET}")
        
        # Detect OS
        if not self.detect_os():
            print(f"{self.colors.error('❌ Failed to detect operating system!')}")
            return
        
        # Display system information
        self.display_system_info()
        
        # Check dependencies
        print(f"\n{self.colors.info('🔍 Checking security tool dependencies...')}")
        dependency_results = self.check_all_dependencies()
        
        # Display results
        self.display_dependency_results(dependency_results)
        
        # Show installation commands if needed
        missing_tools = []
        for tool, commands in dependency_results.items():
            if not all(commands.values()):
                missing_tools.append(tool)
        
        if missing_tools:
            self.get_installation_commands(dependency_results)
            print(f"\n{self.colors.warning('⚠️  Some security tools are missing!')}")
            print(f"{self.colors.info('💡 Use the commands above to install missing dependencies.')}")
        else:
            print(f"\n{self.colors.success('🎉 All security tools are properly installed!')}")
            print(f"{self.colors.info('✅ Your system is ready for security testing.')}")
        
        print(f"\n{self.colors.BRIGHT_CYAN}🏁 System check completed!{self.colors.RESET}")
