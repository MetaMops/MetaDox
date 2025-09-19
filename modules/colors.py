"""
Color definitions for terminal output
"""

class Colors:
    """ANSI color codes for terminal output"""
    
    # Regular colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'
    
    # Text styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    STRIKETHROUGH = '\033[9m'
    
    # Reset
    RESET = '\033[0m'
    
    def colorize(self, text, color):
        """Apply color to text"""
        return f"{color}{text}{self.RESET}"
    
    def success(self, text):
        """Green text for success messages"""
        return self.colorize(text, self.GREEN)
    
    def error(self, text):
        """Red text for error messages"""
        return self.colorize(text, self.RED)
    
    def warning(self, text):
        """Yellow text for warning messages"""
        return self.colorize(text, self.YELLOW)
    
    def info(self, text):
        """Cyan text for info messages"""
        return self.colorize(text, self.CYAN)
    
    def highlight(self, text):
        """Bright white text for highlighting"""
        return self.colorize(text, self.BRIGHT_WHITE)
    
    def menu_item(self, text):
        """Cyan text for menu items"""
        return self.colorize(text, self.CYAN)
    
    def menu_number(self, text):
        """Bright green text for menu numbers"""
        return self.colorize(text, self.BRIGHT_GREEN)
    
    def menu_title(self, text):
        """Bright yellow text for menu titles"""
        return self.colorize(text, self.BRIGHT_YELLOW)
    
    def status_ok(self, text):
        """Green text for OK status"""
        return self.colorize(text, self.BRIGHT_GREEN)
    
    def status_error(self, text):
        """Red text for error status"""
        return self.colorize(text, self.BRIGHT_RED)
    
    def status_warning(self, text):
        """Yellow text for warning status"""
        return self.colorize(text, self.BRIGHT_YELLOW)
    
    def status_info(self, text):
        """Blue text for info status"""
        return self.colorize(text, self.BRIGHT_BLUE)
    
    def accent(self, text):
        """Magenta text for accents"""
        return self.colorize(text, self.MAGENTA)
    
    def special(self, text):
        """Bright cyan text for special elements"""
        return self.colorize(text, self.BRIGHT_CYAN)
