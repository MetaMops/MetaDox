"""
File Analyzer - Main module for analyzing files for embedded payloads
Clean and stable implementation
"""

import os
from pathlib import Path
from ..colors import Colors
from ..exit_handler import ExitHandler

class FileAnalyzer:
    def __init__(self):
        self.colors = Colors()
        self.exit_handler = ExitHandler()
        
        # File type handlers
        self.handlers = {
            '.py': self._handle_python_file,
            '.exe': self._handle_exe_file,
            '.dll': self._handle_exe_file,
            '.aspx': self._handle_aspx_file,
            '.jsp': self._handle_jsp_file,
            '.php': self._handle_php_file,
            '.apk': self._handle_apk_file,
            '.bin': self._handle_bin_file,
            '.elf': self._handle_elf_file,
                   '.jar': self._handle_jar_file,
                   '.macho': self._handle_macho_file
        }
    
    def run(self):
        """Main entry point for file analysis"""
        try:
            # Clear screen and show main banner
            self.clear_screen()
            self.show_main_banner()
            self.show_submenu()
            
            while True:
                try:
                    choice = input(f"\n{self.colors.CYAN}Enter your choice (0 to exit): {self.colors.RESET}")
                    choice = int(choice)
                    break
                except ValueError:
                    print(f"{self.colors.RED}❌ Please enter a valid number!{self.colors.RESET}")
                    continue
                except KeyboardInterrupt:
                    print(f"\n{self.colors.YELLOW}⚠️  Operation cancelled by user.{self.colors.RESET}")
                    self.exit_handler.clean_exit(force=True)
            
            if choice == 0:
                print(f"{self.colors.YELLOW}👋 Exiting file analysis...{self.colors.RESET}")
                return
            elif choice == 1:
                self.check_files()
            elif choice == 2:
                self.check_links()
            else:
                print(f"{self.colors.RED}❌ Invalid choice!{self.colors.RESET}")
                
        except KeyboardInterrupt:
            print(f"\n{self.colors.YELLOW}⚠️  Application interrupted by user.{self.colors.RESET}")
            self.exit_handler.clean_exit(force=True)
        except Exception as e:
            print(f"{self.colors.RED}❌ Error in file analysis: {e}{self.colors.RESET}")
            import traceback
            traceback.print_exc()
            self.exit_handler.clean_exit(force=True)
    
    def clear_screen(self):
        """Clear the screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def show_main_banner(self):
        """Display the main MetaDox banner (same as main menu)"""
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
    
    def show_banner(self):
        """Display the file analysis banner"""
        banner = f"""
{self.colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                          🔬 FILE ANALYSIS SYSTEM 🔬                          ║
║                                                                              ║
║                    Analyze files and links for embedded payloads            ║
╚══════════════════════════════════════════════════════════════════════════════╝{self.colors.RESET}
"""
        print(banner)
    
    def show_submenu(self):
        """Display the submenu"""
        print(f"{self.colors.GREEN}📋 Analysis Options:{self.colors.RESET}")
        print(f"{self.colors.WHITE}1.{self.colors.RESET} {self.colors.MAGENTA}📁 Check Files{self.colors.RESET}    - Analyze files in checkfiles/ directory")
        print(f"{self.colors.WHITE}2.{self.colors.RESET} {self.colors.BRIGHT_MAGENTA}🔗 Check Links{self.colors.RESET}    - Analyze URLs for payloads")
        print(f"{self.colors.WHITE}0.{self.colors.RESET} {self.colors.YELLOW}🚪 Exit{self.colors.RESET}        - Return to main menu")
    
    def check_files(self):
        """Check files in checkfiles directory"""
        while True:
            # Clear screen and show main banner
            self.clear_screen()
            self.show_main_banner()
            
            print(f"\n{self.colors.MAGENTA}📁 CHECK FILES MODE{self.colors.RESET}")
            
            # Check if checkfiles directory exists
            checkfiles_dir = "checkfiles"
            if not os.path.exists(checkfiles_dir):
                print(f"{self.colors.RED}❌ Directory '{checkfiles_dir}' not found!{self.colors.RESET}")
                input(f"\n{self.colors.CYAN}Press Enter to continue...{self.colors.RESET}")
                return
            
            # Get files from checkfiles directory
            files = [f for f in os.listdir(checkfiles_dir) if os.path.isfile(os.path.join(checkfiles_dir, f))]
            
            if not files:
                print(f"{self.colors.RED}❌ No files found in '{checkfiles_dir}' directory!{self.colors.RESET}")
                input(f"\n{self.colors.CYAN}Press Enter to continue...{self.colors.RESET}")
                return
            
            # Show file selection menu
            if not self.show_file_menu(files):
                break  # User chose to exit
    
    def show_file_menu(self, files):
        """Show file selection menu and handle file analysis"""
        print(f"\n{self.colors.CYAN}📁 Files in checkfiles/ directory:{self.colors.RESET}")
        
        for i, file in enumerate(files, 1):
            file_path = Path(file)
            ext = file_path.suffix.lower()
            
            # Define colors for each file type
            file_colors = {
                '.py': self.colors.RED,
                '.exe': self.colors.YELLOW,
                '.dll': self.colors.MAGENTA,
                '.aspx': self.colors.BRIGHT_YELLOW,  # Orange-like color
                '.jsp': self.colors.BRIGHT_MAGENTA,
                '.php': self.colors.BLUE,
                '.apk': self.colors.GREEN,
                '.bin': self.colors.CYAN,
                '.elf': self.colors.BRIGHT_GREEN,  # Dark green
                '.jar': self.colors.YELLOW,
                '.macho': self.colors.BRIGHT_BLUE
            }
            
            if ext in self.handlers:
                color = file_colors.get(ext, self.colors.WHITE)
                print(f"{self.colors.WHITE}{i:2d}.{self.colors.RESET} {color}{file}{self.colors.RESET} {self.colors.BRIGHT_BLACK}({ext.upper()}){self.colors.RESET}")
            else:
                print(f"{self.colors.WHITE}{i:2d}.{self.colors.RESET} {self.colors.BRIGHT_BLACK}{file}{self.colors.RESET} {self.colors.BRIGHT_BLACK}(Unknown){self.colors.RESET}")
        
        print(f"{self.colors.WHITE} 0.{self.colors.RESET} {self.colors.YELLOW}🚪 Back to Analysis Menu{self.colors.RESET}")
        
        try:
            choice = input(f"\n{self.colors.CYAN}Enter file number to analyze (0 to go back): {self.colors.RESET}")
            choice = int(choice)
            
            if choice == 0:
                return False  # Go back to analysis menu
            
            if 1 <= choice <= len(files):
                selected_file = files[choice - 1]
                file_path = os.path.join("checkfiles", selected_file)
                
                # Analyze the file
                self.analyze_file(file_path)
                
                # Show analysis summary and wait for Enter
                print(f"\n{self.colors.CYAN}📊 Analysis completed for: {selected_file}{self.colors.RESET}")
                input(f"\n{self.colors.CYAN}Press Enter to continue...{self.colors.RESET}")
                return True  # Continue in file menu
            else:
                print(f"{self.colors.RED}❌ Invalid choice!{self.colors.RESET}")
                input(f"\n{self.colors.CYAN}Press Enter to continue...{self.colors.RESET}")
                return True  # Continue in file menu
                
        except (ValueError, KeyboardInterrupt):
            print(f"\n{self.colors.YELLOW}👋 Returning to analysis menu...{self.colors.RESET}")
            return False  # Go back to analysis menu
        except Exception as e:
            print(f"{self.colors.RED}❌ Error: {e}{self.colors.RESET}")
            input(f"\n{self.colors.CYAN}Press Enter to continue...{self.colors.RESET}")
            return True  # Continue in file menu
    
    def check_links(self):
        """Check links for payloads"""
        # Clear screen and show main banner
        self.clear_screen()
        self.show_main_banner()
        
        print(f"\n{self.colors.BRIGHT_MAGENTA}🔗 CHECK LINKS MODE{self.colors.RESET}")
        print(f"{self.colors.YELLOW}⚠️  Link analysis not yet implemented{self.colors.RESET}")
        print(f"{self.colors.BLUE}📝 This feature will be added in the next update{self.colors.RESET}")
        
        input(f"\n{self.colors.CYAN}Press Enter to continue...{self.colors.RESET}")
    
    def analyze_file(self, file_path):
        """Analyze a file for payloads"""
        try:
            print(f"\n{self.colors.CYAN}🔍 Analyzing file: {os.path.basename(file_path)}{self.colors.RESET}")
            
            # Get file extension
            ext = Path(file_path).suffix.lower()
            
            # Check if we have a handler for this file type
            if ext in self.handlers:
                handler = self.handlers[ext]
                handler(file_path)
            else:
                print(f"{self.colors.YELLOW}⚠️  No handler available for file type: {ext}{self.colors.RESET}")
                print(f"{self.colors.BLUE}📝 Supported types: {', '.join(self.handlers.keys())}{self.colors.RESET}")
                
        except Exception as e:
            print(f"{self.colors.RED}❌ Error analyzing file: {e}{self.colors.RESET}")
    
    def _handle_python_file(self, file_path):
        """Handle Python file analysis"""
        from .analyzers.python_analyzer import PythonAnalyzer
        analyzer = PythonAnalyzer()
        result = analyzer.analyze(file_path)
        analyzer.display_result(result, file_path)
    
    def _handle_exe_file(self, file_path):
        """Handle EXE file analysis"""
        from .analyzers.exe_analyzer import ExeAnalyzer
        analyzer = ExeAnalyzer()
        result = analyzer.analyze(file_path)
        analyzer.display_result(result, file_path)
    
    def _handle_php_file(self, file_path):
        """Handle PHP file analysis"""
        try:
            from .analyzers.php_analyzer import PhpAnalyzer
            analyzer = PhpAnalyzer()
            result = analyzer.analyze(file_path)
            return analyzer.display_result(result, file_path)
        except Exception as e:
            print(f"{self.colors.RED}❌ Error analyzing PHP file: {e}{self.colors.RESET}")
            return None

    def _handle_jsp_file(self, file_path):
        """Handle JSP file analysis"""
        try:
            from .analyzers.jsp_analyzer import JspAnalyzer
            analyzer = JspAnalyzer()
            result = analyzer.analyze(file_path)
            return analyzer.display_result(result, file_path)
        except Exception as e:
            print(f"{self.colors.RED}❌ Error analyzing JSP file: {e}{self.colors.RESET}")
            return None

    def _handle_aspx_file(self, file_path):
        """Handle ASPX file analysis"""
        try:
            from .analyzers.aspx_analyzer import AspxAnalyzer
            analyzer = AspxAnalyzer()
            result = analyzer.analyze(file_path)
            return analyzer.display_result(result, file_path)
        except Exception as e:
            print(f"{self.colors.RED}❌ Error analyzing ASPX file: {e}{self.colors.RESET}")
            return None

    def _handle_apk_file(self, file_path):
        """Handle APK file analysis"""
        try:
            from .analyzers.apk_analyzer import ApkAnalyzer
            analyzer = ApkAnalyzer()
            result = analyzer.analyze(file_path)
            return analyzer.display_result(result, file_path)
        except Exception as e:
            print(f"{self.colors.RED}❌ Error analyzing APK file: {e}{self.colors.RESET}")
            return None

    def _handle_bin_file(self, file_path):
        """Handle BIN file analysis"""
        try:
            from .analyzers.bin_analyzer import BinAnalyzer
            analyzer = BinAnalyzer()
            result = analyzer.analyze(file_path)
            return analyzer.display_result(result, file_path)
        except Exception as e:
            print(f"{self.colors.RED}❌ Error analyzing BIN file: {e}{self.colors.RESET}")
            return None

    def _handle_elf_file(self, file_path):
        """Handle ELF file analysis"""
        try:
            from .analyzers.elf_analyzer import ElfAnalyzer
            analyzer = ElfAnalyzer()
            result = analyzer.analyze(file_path)
            return analyzer.display_result(result, file_path)
        except Exception as e:
            print(f"{self.colors.RED}❌ Error analyzing ELF file: {e}{self.colors.RESET}")
            return None

    def _handle_jar_file(self, file_path):
        """Handle JAR file analysis"""
        try:
            from .analyzers.jar_analyzer import JarAnalyzer
            analyzer = JarAnalyzer()
            result = analyzer.analyze(file_path)
            return analyzer.display_result(result, file_path)
        except Exception as e:
            print(f"{self.colors.RED}❌ Error analyzing JAR file: {e}{self.colors.RESET}")
            return None

    def _handle_macho_file(self, file_path):
        """Handle Mach-O file analysis"""
        try:
            from .analyzers.macho_analyzer import MachoAnalyzer
            analyzer = MachoAnalyzer()
            result = analyzer.analyze(file_path)
            return analyzer.display_result(result, file_path)
        except Exception as e:
            print(f"{self.colors.RED}❌ Error analyzing Mach-O file: {e}{self.colors.RESET}")
            return None

    def _handle_placeholder(self, file_path):
        """Handle placeholder for unimplemented file types"""
        ext = Path(file_path).suffix.lower()
        print(f"{self.colors.YELLOW}⚠️  {ext.upper()} analyzer not yet implemented{self.colors.RESET}")
        print(f"{self.colors.BLUE}📝 This analyzer will be added in the next update{self.colors.RESET}")
