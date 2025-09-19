"""

Metasploit Database Module - Initialize and check Metasploit database
"""

import subprocess
import os
from .colors import Colors

class MetasploitDatabase:
    def __init__(self):
        self.colors = Colors()
    
    def check_database_status(self):
        """Check if Metasploit database is running"""
        try:
            # Check if PostgreSQL is running
            result = subprocess.run(['systemctl', 'is-active', 'postgresql'], 
                                  capture_output=True, text=True, timeout=10)
            postgres_status = result.stdout.strip() == 'active'
            
            # Check if Metasploit database is initialized
            result = subprocess.run(['msfdb', 'status'], 
                                  capture_output=True, text=True, timeout=10)
            
            # Improved database status detection
            output_lower = result.stdout.lower()
            db_status = False
            
            # Check for various indicators that database is initialized
            if any(indicator in output_lower for indicator in [
                'initialized', 'configured', 'database already started', 
                'already configured', 'skipping initialization', 'database.yml exists',
                'postgresql', 'connected', 'loaded', 'active'
            ]):
                db_status = True
            
            # Also check for error indicators that might mean database is not properly set up
            if any(error_indicator in output_lower for error_indicator in [
                'not initialized', 'not configured', 'database not found',
                'connection failed', 'authentication failed'
            ]):
                db_status = False
            
            # Extract relevant information
            db_info = ""
            if result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    line_lower = line.lower()
                    if any(keyword in line_lower for keyword in [
                        'loaded', 'active', 'initialized', 'configured', 
                        'postgresql', 'connected', 'database'
                    ]):
                        db_info += line.strip() + "\n"
            
            return {
                'postgresql': postgres_status,
                'database': db_status,
                'output': db_info.strip() if db_info else "No detailed information available",
                'raw_output': result.stdout
            }
        except Exception as e:
            return {
                'postgresql': False,
                'database': False,
                'error': str(e)
            }
    
    def initialize_database(self, force=False):
        """Initialize Metasploit database"""
        try:
            if force:
                print(f"{self.colors.info('Force initializing Metasploit database...')}")
                # First delete existing database
                subprocess.run(['msfdb', 'delete'], 
                             capture_output=True, text=True, timeout=15)
            else:
                print(f"{self.colors.info('Initializing Metasploit database...')}")
            
            # Run msfdb init
            result = subprocess.run(['msfdb', 'init'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'output': result.stdout,
                    'message': 'Database initialized successfully!' if not force else 'Database force initialized successfully!'
                }
            else:
                return {
                    'success': False,
                    'output': result.stderr,
                    'message': 'Failed to initialize database'
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': 'Error during database initialization'
            }
    
    def start_database(self):
        """Start Metasploit database services"""
        try:
            print(f"{self.colors.info('Starting database services...')}")
            
            # Start PostgreSQL
            result = subprocess.run(['sudo', 'systemctl', 'start', 'postgresql'], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'message': 'Database services started successfully!'
                }
            else:
                return {
                    'success': False,
                    'message': 'Failed to start database services',
                    'error': result.stderr
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': 'Error starting database services'
            }
    
    def display_database_status(self, status):
        """Display database status information"""
        print(f"\n{self.colors.BRIGHT_RED}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    {self.colors.BRIGHT_YELLOW}🗄️  METASPLOIT DATABASE STATUS 🗄️{self.colors.BRIGHT_RED}           ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{self.colors.RESET}")
        
        # PostgreSQL Status
        if status['postgresql']:
            postgres_status = f"{self.colors.BRIGHT_GREEN}✅ RUNNING{self.colors.RESET}"
        else:
            postgres_status = f"{self.colors.BRIGHT_RED}❌ STOPPED{self.colors.RESET}"
        print(f"\n{self.colors.BRIGHT_RED}🐘 PostgreSQL Service:{self.colors.RESET}")
        print(f"  Status: {postgres_status}")
        
        # Database Status
        if status['database']:
            db_status = f"{self.colors.BRIGHT_GREEN}✅ INITIALIZED{self.colors.RESET}"
        else:
            db_status = f"{self.colors.BRIGHT_RED}❌ NOT INITIALIZED{self.colors.RESET}"
        print(f"\n{self.colors.BRIGHT_GREEN}💾 Metasploit Database:{self.colors.RESET}")
        print(f"  Status: {db_status}")
        
        # Show output if available
        if 'output' in status and status['output']:
            print(f"\n{self.colors.BRIGHT_YELLOW}📋 Database Information:{self.colors.RESET}")
            print(f"  {self.colors.BRIGHT_CYAN}{status['output']}{self.colors.RESET}")
        
        # Show error if available
        if 'error' in status and status['error']:
            print(f"\n{self.colors.BRIGHT_RED}💥 Error: {status['error']}{self.colors.RESET}")
    
    def display_initialization_result(self, result):
        """Display database initialization result"""
        if result['success']:
            print(f"\n{self.colors.BRIGHT_GREEN}✅ {result['message']}{self.colors.RESET}")
            if 'output' in result and result['output']:
                print(f"\n{self.colors.BRIGHT_WHITE}{self.colors.BOLD}📋 Initialization Output:{self.colors.RESET}")
                print(f"  {self.colors.BRIGHT_CYAN}{result['output']}{self.colors.RESET}")
        else:
            print(f"\n{self.colors.BRIGHT_RED}❌ {result['message']}{self.colors.RESET}")
            if 'error' in result and result['error']:
                print(f"\n{self.colors.BRIGHT_RED}💥 Error: {result['error']}{self.colors.RESET}")
            if 'output' in result and result['output']:
                print(f"\n{self.colors.BRIGHT_YELLOW}📄 Output: {result['output']}{self.colors.RESET}")
    
    def get_user_choice(self):
        """Get user choice for database operations"""
        while True:
            try:
                print(f"\n{self.colors.BRIGHT_RED}╔══════════════════════════════════════════════════════════════╗")
                print(f"║                    {self.colors.BRIGHT_YELLOW}🔧 DATABASE OPERATIONS 🔧{self.colors.BRIGHT_RED}                   ║")
                print(f"╚══════════════════════════════════════════════════════════════╝{self.colors.RESET}")
                print(f"  {self.colors.BRIGHT_GREEN}1.{self.colors.RESET} {self.colors.BRIGHT_YELLOW}🚀 Initialize Database{self.colors.RESET}")
                print(f"  {self.colors.BRIGHT_GREEN}2.{self.colors.RESET} {self.colors.BRIGHT_MAGENTA}🔄 Force Reinitialize Database{self.colors.RESET}")
                print(f"  {self.colors.BRIGHT_GREEN}3.{self.colors.RESET} {self.colors.BRIGHT_CYAN}▶️  Start Database Services{self.colors.RESET}")
                print(f"  {self.colors.BRIGHT_GREEN}4.{self.colors.RESET} {self.colors.BRIGHT_BLUE}🔍 Check Status Again{self.colors.RESET}")
                print(f"  {self.colors.BRIGHT_GREEN}5.{self.colors.RESET} {self.colors.BRIGHT_RED}🚪 Back to Main Menu{self.colors.RESET}")
                
                choice = input(f"\n{self.colors.BRIGHT_YELLOW}🎯 Enter your choice (1-5): {self.colors.RESET}")
                if choice in ['1', '2', '3', '4', '5']:
                    return int(choice)
                else:
                    print(f"{self.colors.BRIGHT_RED}❌ Invalid choice! Please enter a number between 1-5.{self.colors.RESET}")
            except KeyboardInterrupt:
                print(f"\n{self.colors.BRIGHT_YELLOW}⚠️  Operation cancelled by user.{self.colors.RESET}")
                return 5
            except Exception as e:
                print(f"{self.colors.BRIGHT_RED}💥 Error: {e}{self.colors.RESET}")
    
    def run(self):
        """Main database management function"""
        print(f"{self.colors.BRIGHT_CYAN}🚀 Starting Metasploit Database Manager...{self.colors.RESET}")
        
        while True:
            # Check current status
            status = self.check_database_status()
            self.display_database_status(status)
            
            # Get user choice
            choice = self.get_user_choice()
            
            if choice == 1:
                # Initialize database
                if status['database']:
                    print(f"\n{self.colors.BRIGHT_YELLOW}⚠️  Database is already initialized!{self.colors.RESET}")
                    print(f"{self.colors.BRIGHT_CYAN}💡 Use option 2 to force reinitialize if needed.{self.colors.RESET}")
                else:
                    result = self.initialize_database()
                    self.display_initialization_result(result)
            
            elif choice == 2:
                # Force reinitialize database
                print(f"\n{self.colors.BRIGHT_RED}⚠️  WARNING: This will delete and recreate the database!{self.colors.RESET}")
                confirm = input(f"{self.colors.BRIGHT_YELLOW}Are you sure? (y/N): {self.colors.RESET}")
                if confirm.lower() in ['y', 'yes']:
                    result = self.initialize_database(force=True)
                    self.display_initialization_result(result)
                else:
                    print(f"{self.colors.BRIGHT_CYAN}❌ Operation cancelled.{self.colors.RESET}")
            
            elif choice == 3:
                # Start database services
                if status['postgresql']:
                    print(f"\n{self.colors.BRIGHT_YELLOW}⚠️  PostgreSQL is already running!{self.colors.RESET}")
                else:
                    result = self.start_database()
                    if result['success']:
                        print(f"\n{self.colors.BRIGHT_GREEN}✅ {result['message']}{self.colors.RESET}")
                    else:
                        print(f"\n{self.colors.BRIGHT_RED}❌ {result['message']}{self.colors.RESET}")
                        if 'error' in result:
                            print(f"{self.colors.BRIGHT_RED}💥 Error: {result['error']}{self.colors.RESET}")
            
            elif choice == 4:
                # Check status again
                print(f"\n{self.colors.info('🔄 Refreshing database status...')}")
                continue
            
            elif choice == 5:
                # Back to main menu
                print(f"\n{self.colors.BRIGHT_CYAN}🚪 Returning to main menu...{self.colors.RESET}")
                break
            
            # Pause before next iteration
            if choice != 5:
                input(f"\n{self.colors.BRIGHT_CYAN}⏎ Press Enter to continue...{self.colors.RESET}")
                os.system('clear' if os.name == 'posix' else 'cls')
        
        print(f"\n{self.colors.BRIGHT_GREEN}🏁 Database management completed!{self.colors.RESET}")
