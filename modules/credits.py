"""
Credits Module - Display author information and disclaimers
"""

from .colors import Colors

class Credits:
    def __init__(self):
        self.colors = Colors()
    
    def show(self):
        """Display credits and disclaimer information"""
        print(f"\n{self.colors.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                          {self.colors.YELLOW}CREDITS{self.colors.CYAN}                             ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{self.colors.RESET}")
        
        print(f"\n{self.colors.BOLD}{self.colors.GREEN}Created by:{self.colors.RESET}")
        print(f"  {self.colors.YELLOW}@apt_start_latifi / iddox{self.colors.RESET}")
        
        print(f"\n{self.colors.BOLD}{self.colors.GREEN}Contact Information:{self.colors.RESET}")
        print(f"  {self.colors.BLUE}Website:{self.colors.RESET} https://www.iddox.tech/")
        print(f"  {self.colors.BLUE}Discord:{self.colors.RESET} https://discord.gg/KcuMUUAP5T")
        
        print(f"\n{self.colors.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                        {self.colors.RED}IMPORTANT DISCLAIMER{self.colors.CYAN}                  ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{self.colors.RESET}")
        
        print(f"\n{self.colors.RED}⚠️  {self.colors.BOLD}WARNING - EDUCATIONAL USE ONLY{self.colors.RESET}")
        print(f"\n{self.colors.YELLOW}This tool is designed exclusively for:{self.colors.RESET}")
        print(f"  • {self.colors.WHITE}Educational purposes{self.colors.RESET}")
        print(f"  • {self.colors.WHITE}Security testing in authorized environments{self.colors.RESET}")
        print(f"  • {self.colors.WHITE}Learning penetration testing techniques{self.colors.RESET}")
        print(f"  • {self.colors.WHITE}Research and development{self.colors.RESET}")
        
        print(f"\n{self.colors.RED}🚫 {self.colors.BOLD}PROHIBITED USES:{self.colors.RESET}")
        print(f"  • {self.colors.WHITE}Unauthorized access to systems{self.colors.RESET}")
        print(f"  • {self.colors.WHITE}Malicious activities{self.colors.RESET}")
        print(f"  • {self.colors.WHITE}Attacking systems without permission{self.colors.RESET}")
        print(f"  • {self.colors.WHITE}Any illegal activities{self.colors.RESET}")
        
        print(f"\n{self.colors.GREEN}✅ {self.colors.BOLD}REQUIRED CONDITIONS:{self.colors.RESET}")
        print(f"  • {self.colors.WHITE}Use only in isolated test environments{self.colors.RESET}")
        print(f"  • {self.colors.WHITE}Obtain proper authorization before testing{self.colors.RESET}")
        print(f"  • {self.colors.WHITE}Follow responsible disclosure practices{self.colors.RESET}")
        print(f"  • {self.colors.WHITE}Comply with local laws and regulations{self.colors.RESET}")
        
        print(f"\n{self.colors.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                        {self.colors.YELLOW}LEGAL NOTICE{self.colors.CYAN}                          ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{self.colors.RESET}")
        
        print(f"\n{self.colors.WHITE}The authors and contributors of this tool are not responsible for{self.colors.RESET}")
        print(f"{self.colors.WHITE}any misuse or damage caused by this software. Users assume full{self.colors.RESET}")
        print(f"{self.colors.WHITE}responsibility for their actions and must ensure they have proper{self.colors.RESET}")
        print(f"{self.colors.WHITE}authorization before using this tool on any system.{self.colors.RESET}")
        
        print(f"\n{self.colors.GREEN}Thank you for using Metasploit Manager responsibly!{self.colors.RESET}")
        
        print(f"\n{self.colors.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                        {self.colors.YELLOW}VERSION INFO{self.colors.CYAN}                          ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{self.colors.RESET}")
        
        print(f"\n{self.colors.GREEN}Version:{self.colors.RESET} 1.0.0")
        print(f"{self.colors.GREEN}Build:{self.colors.RESET} Development")
        print(f"{self.colors.GREEN}Python:{self.colors.RESET} 3.x")
        print(f"{self.colors.GREEN}License:{self.colors.RESET} Educational Use Only")
        
        print(f"\n{self.colors.BLUE}For updates and support, visit: https://www.iddox.tech/{self.colors.RESET}")
