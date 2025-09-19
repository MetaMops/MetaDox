#!/usr/bin/env python3
"""
Color Utilities für Metadox
Bietet farbige Ausgabe für bessere Benutzerfreundlichkeit
"""

import os
import sys
import platform


class Colors:
    """Farb-Konstanten für Terminal-Ausgabe"""
    
    # Standard-Farben
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Helle Farben
    LIGHT_RED = '\033[1;91m'
    LIGHT_GREEN = '\033[1;92m'
    LIGHT_YELLOW = '\033[1;93m'
    LIGHT_BLUE = '\033[1;94m'
    LIGHT_MAGENTA = '\033[1;95m'
    LIGHT_CYAN = '\033[1;96m'
    LIGHT_WHITE = '\033[1;97m'
    
    # Hintergrund-Farben
    BG_RED = '\033[101m'
    BG_GREEN = '\033[102m'
    BG_YELLOW = '\033[103m'
    BG_BLUE = '\033[104m'
    BG_MAGENTA = '\033[105m'
    BG_CYAN = '\033[106m'
    BG_WHITE = '\033[107m'
    
    # Stile
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    
    # Reset
    RESET = '\033[0m'
    END = '\033[0m'


class ColorPrinter:
    """Klasse für farbige Ausgabe"""
    
    def __init__(self):
        self.colors_enabled = self._check_color_support()
    
    def _check_color_support(self) -> bool:
        """Prüft ob Farben unterstützt werden"""
        # Windows: Aktiviere ANSI-Escape-Codes
        if platform.system() == 'Windows':
            try:
                # Aktiviere ANSI-Escape-Codes in Windows
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                return True
            except:
                return False
        
        # Prüfe ob Terminal Farben unterstützt
        if os.getenv('TERM') == 'dumb':
            return False
        
        # Prüfe ob NO_COLOR gesetzt ist
        if os.getenv('NO_COLOR'):
            return False
        
        # Prüfe ob FORCE_COLOR gesetzt ist
        if os.getenv('FORCE_COLOR'):
            return True
        
        # Standard: Farben aktivieren
        return True
    
    def colorize(self, text: str, color: str) -> str:
        """Färbt Text ein"""
        if not self.colors_enabled:
            return text
        return f"{color}{text}{Colors.RESET}"
    
    def print_colored(self, text: str, color: str = Colors.WHITE, end: str = '\n'):
        """Druckt farbigen Text"""
        print(self.colorize(text, color), end=end)
    
    def print_banner(self, text: str, color: str = Colors.LIGHT_BLUE, width: int = 60):
        """Druckt einen farbigen Banner"""
        if not self.colors_enabled:
            print("=" * width)
            print(text)
            print("=" * width)
            return
        
        # Erstelle Banner mit Farben
        border = self.colorize("═" * width, color)
        title = self.colorize(text.center(width), color)
        
        print(border)
        print(title)
        print(border)
    
    def print_menu_header(self, title: str, color: str = Colors.LIGHT_BLUE):
        """Druckt einen Menü-Header"""
        self.print_banner(f" {title} ", color, 50)
    
    def print_success(self, text: str):
        """Druckt Erfolgsmeldung"""
        self.print_colored(f"✅ {text}", Colors.LIGHT_GREEN)
    
    def print_error(self, text: str):
        """Druckt Fehlermeldung"""
        self.print_colored(f"❌ {text}", Colors.LIGHT_RED)
    
    def print_warning(self, text: str):
        """Druckt Warnung"""
        self.print_colored(f"⚠️  {text}", Colors.LIGHT_YELLOW)
    
    def print_info(self, text: str):
        """Druckt Info"""
        self.print_colored(f"ℹ️  {text}", Colors.LIGHT_CYAN)
    
    def print_menu_item(self, number: str, text: str, color: str = Colors.WHITE):
        """Druckt Menü-Item"""
        colored_number = self.colorize(number, Colors.LIGHT_BLUE)
        colored_text = self.colorize(text, color)
        print(f"{colored_number}. {colored_text}")
    
    def print_separator(self, char: str = "=", color: str = Colors.BLUE, width: int = 50):
        """Druckt Trennlinie"""
        separator = char * width
        self.print_colored(separator, color)
    
    def print_box(self, text: str, color: str = Colors.LIGHT_BLUE, width: int = 50):
        """Druckt Text in einer Box"""
        if not self.colors_enabled:
            print("┌" + "─" * (width - 2) + "┐")
            print("│" + text.center(width - 2) + "│")
            print("└" + "─" * (width - 2) + "┘")
            return
        
        # Unicode-Box-Zeichen mit Farben
        top = self.colorize("┌" + "─" * (width - 2) + "┐", color)
        middle = self.colorize("│" + text.center(width - 2) + "│", color)
        bottom = self.colorize("└" + "─" * (width - 2) + "┘", color)
        
        print(top)
        print(middle)
        print(bottom)


def get_metadox_banner() -> str:
    """Gibt das Metadox ASCII-Banner zurück"""
    banner = """
 __  __    ___    _____    ___     ___     ___   __  __  
|  \\/  |  | __|  |_   _|  /   \\   |   \\   / _ \\  \\ \\/ /  
| |\\/| |  | _|     | |    | - |   | |) | | (_) |  >  <   
|_|__|_|  |___|   _|_|_   |_|_|   |___/   \\___/  /_/\\_\\  
_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"|_|\"\"\"\"\"| 
\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-'\"`-0-0-' 

    Metasploit Management & Automation Tool
    Discord: @apt_start_latifi
    GitHub: https://github.com/MetaMops
    """
    return banner


# Globale Instanz
printer = ColorPrinter()
