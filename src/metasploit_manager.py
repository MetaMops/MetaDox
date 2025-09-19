#!/usr/bin/env python3
"""
Metasploit Manager für Metadox
Erkennt und installiert Metasploit Framework automatisch
"""

import os
import sys
import subprocess
import shutil
import platform
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import json
import time


class MetasploitManager:
    """Klasse zur Verwaltung von Metasploit Framework"""
    
    def __init__(self, system_detector):
        self.system_detector = system_detector
        # Stelle sicher, dass System erkannt wurde
        if not self.system_detector.detected_os:
            self.system_detector.detect_system()
        self.metasploit_paths = {
            'linux': [
                '/opt/metasploit-framework',
                '/usr/share/metasploit-framework',
                '/usr/local/metasploit-framework',
                '/home/kali/metasploit-framework'
            ],
            'windows': [
                '/opt/metasploit-framework',  # WSL path
                'C:\\metasploit-framework',
                'C:\\Program Files\\Metasploit',
                'C:\\tools\\metasploit-framework',
                'C:\\Program Files (x86)\\Metasploit',
                'C:\\metasploit',
                'C:\\ProgramData\\chocolatey\\lib\\metasploit\\tools\\metasploit-framework'
            ],
            'darwin': [
                '/opt/metasploit-framework',
                '/usr/local/metasploit-framework',
                '/Applications/Metasploit.app'
            ]
        }
        self.metasploit_info = {}
        self.installation_status = 'unknown'
        self.wsl_enabled = False
        self.wsl_distribution = None
        
    def detect_metasploit(self) -> Dict[str, any]:
        """
        Erkennt ob Metasploit installiert ist und sammelt Informationen
        
        Returns:
            Dict mit Metasploit-Informationen
        """
        print("🔍 Suche nach Metasploit Framework...")
        
        os_type = self.system_detector.get_os_type()
        self.metasploit_info = {
            'installed': False,
            'path': None,
            'version': None,
            'msfconsole_path': None,
            'msfvenom_path': None,
            'msfdb_path': None,
            'os_type': os_type,
            'wsl_enabled': False,
            'wsl_distribution': None
        }
        
        # Windows: Prüfe zuerst WSL
        if os_type == 'windows':
            if self._check_wsl_availability():
                print("🐧 WSL gefunden - suche Metasploit in WSL...")
                if self._search_wsl_metasploit():
                    self.metasploit_info['installed'] = True
                    self.metasploit_info['wsl_enabled'] = True
                    self.metasploit_info['wsl_distribution'] = self.wsl_distribution
                    self.installation_status = 'installed'
                    return self.metasploit_info
        
        # Standard-Suche (Linux, macOS, Windows ohne WSL)
        # Suche in Standard-Pfaden
        for path in self.metasploit_paths.get(os_type, []):
            if os.path.exists(path):
                if self._validate_metasploit_installation(path):
                    self.metasploit_info['installed'] = True
                    self.metasploit_info['path'] = path
                    self._get_metasploit_version(path)
                    break
        
        # Suche über PATH
        if not self.metasploit_info['installed']:
            self._search_in_path()
        
        # Suche über which/where
        if not self.metasploit_info['installed']:
            self._search_with_which()
        
        self.installation_status = 'installed' if self.metasploit_info['installed'] else 'not_installed'
        return self.metasploit_info
    
    
    def _validate_metasploit_installation(self, path: str) -> bool:
        """Validiert eine Metasploit-Installation"""
        required_files = ['msfconsole', 'msfvenom', 'msfdb']
        required_dirs = ['modules', 'tools', 'scripts']
        
        os_type = self.system_detector.get_os_type()
        
        # Prüfe mindestens 2 der 3 Hauptdateien
        found_files = 0
        for file in required_files:
            file_path = os.path.join(path, file)
            if os_type == 'windows':
                file_path += '.bat'
            if os.path.exists(file_path):
                found_files += 1
        
        if found_files < 2:
            return False
        
        # Prüfe mindestens 2 der 3 Hauptverzeichnisse
        found_dirs = 0
        for dir_name in required_dirs:
            dir_path = os.path.join(path, dir_name)
            if os.path.isdir(dir_path):
                found_dirs += 1
        
        if found_dirs < 2:
            return False
        
        return True
    
    def _search_windows_path(self):
        """Spezielle Windows PATH-Suche für MSI Installation"""
        try:
            # Suche nach msfconsole im PATH
            result = subprocess.run(['where', 'msfconsole'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                msfconsole_path = result.stdout.strip().split('\n')[0]
                print(f"✅ Metasploit gefunden im PATH: {msfconsole_path}")
                
                # Ermittle das Verzeichnis
                path = os.path.dirname(msfconsole_path)
                
                self.metasploit_info['installed'] = True
                self.metasploit_info['path'] = path
                self.metasploit_info['msfconsole_path'] = msfconsole_path
                
                # Suche nach msfvenom und msfdb
                try:
                    msfvenom_result = subprocess.run(['where', 'msfvenom'], 
                                                   capture_output=True, text=True, timeout=10)
                    if msfvenom_result.returncode == 0:
                        self.metasploit_info['msfvenom_path'] = msfvenom_result.stdout.strip().split('\n')[0]
                except:
                    pass
                
                try:
                    msfdb_result = subprocess.run(['where', 'msfdb'], 
                                                 capture_output=True, text=True, timeout=10)
                    if msfdb_result.returncode == 0:
                        self.metasploit_info['msfdb_path'] = msfdb_result.stdout.strip().split('\n')[0]
                except:
                    pass
                
                # Versuche Version zu ermitteln
                self._get_metasploit_version(path)
                
        except Exception as e:
            print(f"Windows PATH-Suche fehlgeschlagen: {e}")
    
    def _get_metasploit_version(self, path: str):
        """Ermittelt die Metasploit-Version"""
        try:
            # Verwende bereits gefundene Pfade wenn verfügbar
            msfconsole_path = self.metasploit_info.get('msfconsole_path')
            
            if not msfconsole_path:
                msfconsole_path = os.path.join(path, 'msfconsole')
                if self.system_detector.is_windows():
                    msfconsole_path += '.bat'
            
            if os.path.exists(msfconsole_path):
                if not self.metasploit_info.get('msfconsole_path'):
                    self.metasploit_info['msfconsole_path'] = msfconsole_path
                
                # Versuche Version zu ermitteln
                try:
                    result = subprocess.run([msfconsole_path, '--version'], 
                                          capture_output=True, text=True, timeout=30)
                    if result.returncode == 0 and result.stdout:
                        version_line = result.stdout.split('\n')[0]
                        if version_line and 'Framework Version' in version_line:
                            version = version_line.split('Framework Version')[1].strip()
                            self.metasploit_info['version'] = version
                except Exception as e:
                    print(f"Version-Ermittlung fehlgeschlagen: {e}")
            
            # msfvenom Pfad
            if not self.metasploit_info.get('msfvenom_path'):
                msfvenom_path = os.path.join(path, 'msfvenom')
                if self.system_detector.is_windows():
                    msfvenom_path += '.bat'
                if os.path.exists(msfvenom_path):
                    self.metasploit_info['msfvenom_path'] = msfvenom_path
            
            # msfdb Pfad
            if not self.metasploit_info.get('msfdb_path'):
                msfdb_path = os.path.join(path, 'msfdb')
                if self.system_detector.is_windows():
                    msfdb_path += '.bat'
                if os.path.exists(msfdb_path):
                    self.metasploit_info['msfdb_path'] = msfdb_path
                
        except Exception as e:
            print(f"Fehler bei Versionsermittlung: {e}")
    
    def _search_in_path(self):
        """Sucht Metasploit im PATH"""
        try:
            msfconsole = shutil.which('msfconsole')
            if msfconsole:
                path = os.path.dirname(msfconsole)
                if self._validate_metasploit_installation(path):
                    self.metasploit_info['installed'] = True
                    self.metasploit_info['path'] = path
                    self.metasploit_info['msfconsole_path'] = msfconsole
                    self._get_metasploit_version(path)
        except Exception as e:
            print(f"Fehler bei PATH-Suche: {e}")
    
    def _search_with_which(self):
        """Sucht Metasploit mit which/where Kommando"""
        try:
            if self.system_detector.is_windows():
                # Windows: Verwende verbesserte Suche
                self._search_windows_enhanced()
            else:
                cmd = ['which', 'msfconsole']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    msfconsole_path = result.stdout.strip().split('\n')[0]
                    path = os.path.dirname(msfconsole_path)
                    if self._validate_metasploit_installation(path):
                        self.metasploit_info['installed'] = True
                        self.metasploit_info['path'] = path
                        self.metasploit_info['msfconsole_path'] = msfconsole_path
                        self._get_metasploit_version(path)
        except Exception as e:
            print(f"Fehler bei which/where-Suche: {e}")
    
    def _search_windows_enhanced(self):
        """Verbesserte Windows-spezifische Metasploit-Suche"""
        print("🔍 Erweiterte Windows-Metasploit-Suche...")
        
        # Methode 1: PATH-Suche mit where
        for cmd in ['msfconsole', 'msfvenom', 'msfdb']:
            try:
                result = subprocess.run(['where', cmd], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    cmd_path = result.stdout.strip().split('\n')[0]
                    print(f"✅ {cmd} gefunden: {cmd_path}")
                    
                    if cmd == 'msfconsole':
                        self.metasploit_info['msfconsole_path'] = cmd_path
                        # Bestimme Metasploit-Pfad
                        if cmd_path.endswith('.bat'):
                            metasploit_dir = os.path.dirname(cmd_path)
                            if os.path.basename(metasploit_dir) in ['bin', 'scripts']:
                                metasploit_dir = os.path.dirname(metasploit_dir)
                            self.metasploit_info['path'] = metasploit_dir
                        else:
                            self.metasploit_info['path'] = os.path.dirname(cmd_path)
                        self.metasploit_info['installed'] = True
                        
                    elif cmd == 'msfvenom':
                        self.metasploit_info['msfvenom_path'] = cmd_path
                    elif cmd == 'msfdb':
                        self.metasploit_info['msfdb_path'] = cmd_path
                        
            except Exception as e:
                print(f"⚠️  Fehler bei PATH-Suche für {cmd}: {e}")
                continue
        
        # Methode 2: Registry-Suche
        if not self.metasploit_info['installed']:
            self._search_windows_registry()
        
        # Methode 3: Erweiterte Verzeichnis-Suche
        if not self.metasploit_info['installed']:
            self._search_windows_directories()
    
    def _search_windows_registry(self):
        """Sucht Metasploit in Windows Registry"""
        try:
            print("🔍 Suche in Windows Registry...")
            result = subprocess.run([
                'reg', 'query', 
                'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
                '/s', '/f', 'Metasploit'
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'InstallLocation' in line:
                        # Extrahiere Pfad aus Registry-Eintrag
                        parts = line.split('REG_SZ')
                        if len(parts) > 1:
                            path = parts[1].strip()
                            if os.path.exists(os.path.join(path, 'msfconsole.bat')):
                                print(f"✅ Metasploit in Registry gefunden: {path}")
                                self.metasploit_info['path'] = path
                                self.metasploit_info['installed'] = True
                                self.metasploit_info['msfconsole_path'] = os.path.join(path, 'msfconsole.bat')
                                self.metasploit_info['msfvenom_path'] = os.path.join(path, 'msfvenom.bat')
                                self.metasploit_info['msfdb_path'] = os.path.join(path, 'msfdb.bat')
                                break
        except Exception as e:
            print(f"⚠️  Registry-Suche fehlgeschlagen: {e}")
    
    def _search_windows_directories(self):
        """Erweiterte Verzeichnis-Suche für Windows"""
        print("🔍 Erweiterte Verzeichnis-Suche...")
        
        search_paths = [
            'C:\\metasploit-framework',
            'C:\\Program Files\\Metasploit',
            'C:\\Program Files\\Metasploit Framework',
            'C:\\Program Files (x86)\\Metasploit',
            'C:\\Program Files (x86)\\Metasploit Framework',
            'C:\\tools\\metasploit-framework',
            'C:\\metasploit',
            'C:\\ProgramData\\chocolatey\\lib\\metasploit\\tools\\metasploit-framework',
            'C:\\Users\\%USERNAME%\\Desktop\\metasploit-framework',
            'C:\\Users\\%USERNAME%\\Downloads\\metasploit-framework'
        ]
        
        for path in search_paths:
            # Ersetze %USERNAME% mit tatsächlichem Benutzernamen
            expanded_path = os.path.expandvars(path)
            
            if os.path.exists(expanded_path):
                print(f"🔍 Prüfe Verzeichnis: {expanded_path}")
                if self._validate_metasploit_installation(expanded_path):
                    print(f"✅ Metasploit gefunden: {expanded_path}")
                    self.metasploit_info['installed'] = True
                    self.metasploit_info['path'] = expanded_path
                    self._get_metasploit_version(expanded_path)
                    break
    
    def _check_wsl_availability(self) -> bool:
        """Prüft ob WSL verfügbar ist"""
        try:
            # Prüfe ob WSL-Befehl existiert
            result = subprocess.run(['wsl', '--status'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("✅ WSL ist verfügbar und aktiviert")
                return True
            else:
                # Prüfe ob WSL installiert aber nicht aktiviert ist
                if "Das Windows-Subsystem für Linux wurde nicht aktiviert" in result.stderr:
                    print("⚠️  WSL installiert aber nicht aktiviert")
                    print("💡 Bitte führen Sie 'install_windows.bat' als Administrator aus und starten Sie neu")
                    return False
                else:
                    print("⚠️  WSL nicht verfügbar")
                    return False
        except FileNotFoundError:
            print("⚠️  WSL-Befehl nicht gefunden - WSL nicht installiert")
            print("💡 Bitte führen Sie 'install_windows.bat' als Administrator aus")
            return False
        except Exception as e:
            print(f"⚠️  WSL-Prüfung fehlgeschlagen: {e}")
            return False
    
    def _search_wsl_metasploit(self) -> bool:
        """Sucht Metasploit in WSL"""
        try:
            # Liste verfügbare WSL-Distributionen
            result = subprocess.run(['wsl', '-l', '-v'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return False
            
            # Suche Ubuntu oder andere Linux-Distributionen
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Ubuntu' in line or 'Debian' in line or 'Kali' in line:
                    # Extrahiere Distribution-Name
                    parts = line.split()
                    if parts:
                        dist_name = parts[0]
                        self.wsl_distribution = dist_name
                        
                        # Suche Metasploit in dieser Distribution
                        print(f"🔍 Suche Metasploit in WSL-Distribution: {dist_name}")
                        
                        # Teste msfconsole in WSL
                        test_result = subprocess.run([
                            'wsl', '-d', dist_name, '-e', 'bash', '-c', 
                            'which msfconsole'
                        ], capture_output=True, text=True, timeout=10)
                        
                        if test_result.returncode == 0:
                            msfconsole_path = test_result.stdout.strip()
                            print(f"✅ Metasploit gefunden in WSL: {msfconsole_path}")
                            
                            # Sammle Metasploit-Informationen aus WSL
                            self._collect_wsl_metasploit_info(dist_name)
                            return True
            
            return False
            
        except Exception as e:
            print(f"⚠️  WSL-Metasploit-Suche fehlgeschlagen: {e}")
            return False
    
    def _collect_wsl_metasploit_info(self, dist_name: str):
        """Sammelt Metasploit-Informationen aus WSL"""
        try:
            # msfconsole Pfad
            result = subprocess.run([
                'wsl', '-d', dist_name, '-e', 'bash', '-c', 'which msfconsole'
            ], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.metasploit_info['msfconsole_path'] = result.stdout.strip()
                self.metasploit_info['path'] = '/opt/metasploit-framework'  # Standard WSL Pfad
            
            # msfvenom Pfad
            result = subprocess.run([
                'wsl', '-d', dist_name, '-e', 'bash', '-c', 'which msfvenom'
            ], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.metasploit_info['msfvenom_path'] = result.stdout.strip()
            
            # msfdb Pfad
            result = subprocess.run([
                'wsl', '-d', dist_name, '-e', 'bash', '-c', 'which msfdb'
            ], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.metasploit_info['msfdb_path'] = result.stdout.strip()
            
            # Version
            result = subprocess.run([
                'wsl', '-d', dist_name, '-e', 'bash', '-c', 'msfconsole --version'
            ], capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                version_line = result.stdout.strip().split('\n')[0]
                if 'Framework Version:' in version_line:
                    self.metasploit_info['version'] = version_line.split('Framework Version:')[1].strip()
                else:
                    self.metasploit_info['version'] = version_line
            
            print(f"✅ WSL-Metasploit-Informationen gesammelt für {dist_name}")
            
        except Exception as e:
            print(f"⚠️  Fehler beim Sammeln von WSL-Metasploit-Informationen: {e}")
    
    def run_wsl_command(self, command: str) -> subprocess.CompletedProcess:
        """Führt einen Befehl in WSL aus"""
        if not self.metasploit_info.get('wsl_enabled') or not self.wsl_distribution:
            raise RuntimeError("WSL nicht verfügbar oder nicht konfiguriert")
        
        return subprocess.run([
            'wsl', '-d', self.wsl_distribution, '-e', 'bash', '-c', command
        ], capture_output=True, text=True, timeout=60)
    
    def install_metasploit(self) -> bool:
        """
        Installiert Metasploit Framework automatisch
        
        Returns:
            True wenn Installation erfolgreich
        """
        if self.metasploit_info['installed']:
            print("✅ Metasploit ist bereits installiert!")
            return True
        
        print("🚀 Starte automatische Metasploit-Installation...")
        
        os_type = self.system_detector.get_os_type()
        
        try:
            if os_type == 'linux':
                return self._install_metasploit_linux()
            elif os_type == 'windows':
                return self._install_metasploit_windows()
            elif os_type == 'darwin':
                return self._install_metasploit_macos()
            else:
                print(f"❌ Unsupported OS: {os_type}")
                return False
                
        except Exception as e:
            print(f"❌ Fehler bei Installation: {e}")
            return False
    
    def _install_metasploit_linux(self) -> bool:
        """Installiert Metasploit auf Linux"""
        package_manager = self.system_detector.get_package_manager()
        distro = self.system_detector.system_info.get('distro', '')
        
        print(f"📦 Installiere Metasploit für {distro} mit {package_manager}...")
        
        try:
            if package_manager == 'apt':
                # Ubuntu/Debian
                commands = [
                    ['sudo', 'apt', 'update'],
                    ['sudo', 'apt', 'install', '-y', 'curl', 'postgresql', 'postgresql-contrib'],
                    ['curl', 'https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb', '-o', '/tmp/msfinstall'],
                    ['chmod', '+x', '/tmp/msfinstall'],
                    ['sudo', '/tmp/msfinstall']
                ]
            elif package_manager == 'yum':
                # CentOS/RHEL/Fedora
                commands = [
                    ['sudo', 'yum', 'update', '-y'],
                    ['sudo', 'yum', 'install', '-y', 'curl', 'postgresql-server', 'postgresql-contrib'],
                    ['curl', 'https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb', '-o', '/tmp/msfinstall'],
                    ['chmod', '+x', '/tmp/msfinstall'],
                    ['sudo', '/tmp/msfinstall']
                ]
            elif package_manager == 'pacman':
                # Arch Linux
                commands = [
                    ['sudo', 'pacman', '-Syu', '--noconfirm'],
                    ['sudo', 'pacman', '-S', '--noconfirm', 'metasploit', 'postgresql']
                ]
            else:
                print("❌ Unsupported package manager")
                return False
            
            # Führe Installationskommandos aus
            for cmd in commands:
                print(f"🔄 Führe aus: {' '.join(cmd)}")
                result = subprocess.run(cmd, timeout=300)
                if result.returncode != 0:
                    print(f"❌ Fehler bei: {' '.join(cmd)}")
                    return False
            
            # Warte kurz und prüfe Installation
            time.sleep(5)
            return self.detect_metasploit()['installed']
            
        except Exception as e:
            print(f"❌ Fehler bei Linux-Installation: {e}")
            return False
    
    def _install_metasploit_windows(self) -> bool:
        """Installiert Metasploit auf Windows via WSL"""
        print("🐧 Installiere Metasploit für Windows via WSL...")
        
        try:
            # Prüfe ob WSL verfügbar ist
            if not self._check_wsl_availability():
                print("❌ WSL nicht verfügbar. Bitte installieren Sie WSL und Ubuntu zuerst.")
                print("💡 Führen Sie 'install_windows.bat' als Administrator aus")
                return False
            
            # Finde WSL-Distribution
            result = subprocess.run(['wsl', '-l', '-v'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                print("❌ Fehler beim Auflisten der WSL-Distributionen")
                return False
            
            # Suche Ubuntu-Distribution
            wsl_distribution = None
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Ubuntu' in line:
                    parts = line.split()
                    if parts:
                        wsl_distribution = parts[0]
                        break
            
            if not wsl_distribution:
                print("❌ Keine Ubuntu-Distribution gefunden")
                print("💡 Bitte installieren Sie Ubuntu aus dem Microsoft Store")
                return False
            
            print(f"✅ Ubuntu-Distribution gefunden: {wsl_distribution}")
            
            # Installiere Metasploit in WSL Ubuntu
            return self._install_metasploit_in_wsl(wsl_distribution)
                
        except Exception as e:
            print(f"❌ Fehler bei WSL-Metasploit-Installation: {e}")
            return False
    
    def _install_metasploit_in_wsl(self, distribution: str) -> bool:
        """Installiert Metasploit in WSL Ubuntu"""
        print(f"🐧 Installiere Metasploit in WSL {distribution}...")
        
        try:
            # Update Ubuntu packages
            print("🔄 Aktualisiere Ubuntu-Pakete...")
            update_cmd = ['wsl', '-d', distribution, '-e', 'bash', '-c', 
                         'sudo apt update && sudo apt upgrade -y']
            result = subprocess.run(update_cmd, timeout=300)
            
            if result.returncode != 0:
                print("❌ Fehler beim Aktualisieren der Ubuntu-Pakete")
                return False
            
            # Installiere Metasploit dependencies
            print("🔄 Installiere Metasploit-Abhängigkeiten...")
            deps_cmd = ['wsl', '-d', distribution, '-e', 'bash', '-c',
                       'sudo apt install -y build-essential libssl-dev libffi-dev ruby-dev ruby-bundler git postgresql postgresql-contrib']
            result = subprocess.run(deps_cmd, timeout=300)
            
            if result.returncode != 0:
                print("❌ Fehler beim Installieren der Abhängigkeiten")
                return False
            
            # Installiere Metasploit via offiziellen Installer
            print("🔄 Installiere Metasploit Framework...")
            install_cmd = ['wsl', '-d', distribution, '-e', 'bash', '-c',
                          'curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sudo bash']
            result = subprocess.run(install_cmd, timeout=600)
            
            if result.returncode != 0:
                print("⚠️  Offizieller Installer fehlgeschlagen, versuche alternative Methode...")
                
                # Alternative: Installiere von Source
                print("🔄 Installiere Metasploit von Source...")
                source_cmd = ['wsl', '-d', distribution, '-e', 'bash', '-c',
                             'cd /opt && sudo git clone https://github.com/rapid7/metasploit-framework.git && cd /opt/metasploit-framework && sudo gem install bundler && sudo bundle install']
                result = subprocess.run(source_cmd, timeout=900)
                
                if result.returncode != 0:
                    print("❌ Fehler bei der Installation von Source")
                    return False
                
                # Erstelle Symlinks
                print("🔄 Erstelle Symlinks...")
                symlink_cmd = ['wsl', '-d', distribution, '-e', 'bash', '-c',
                              'sudo ln -sf /opt/metasploit-framework/msfconsole /usr/local/bin/msfconsole && sudo ln -sf /opt/metasploit-framework/msfvenom /usr/local/bin/msfvenom && sudo ln -sf /opt/metasploit-framework/msfdb /usr/local/bin/msfdb']
                subprocess.run(symlink_cmd, timeout=60)
            
            # Initialisiere Metasploit-Datenbank
            print("🔄 Initialisiere Metasploit-Datenbank...")
            db_cmd = ['wsl', '-d', distribution, '-e', 'bash', '-c',
                     'sudo service postgresql start && sudo -u postgres createuser -s $USER && msfdb init']
            result = subprocess.run(db_cmd, timeout=120)
            
            if result.returncode != 0:
                print("⚠️  Datenbank-Initialisierung fehlgeschlagen, aber Installation möglicherweise erfolgreich")
            
            # Teste Installation
            print("🔄 Teste Metasploit-Installation...")
            test_cmd = ['wsl', '-d', distribution, '-e', 'bash', '-c', 'msfconsole --version']
            result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print("✅ Metasploit erfolgreich in WSL installiert!")
                print(f"📄 Version: {result.stdout.strip()}")
                
                # Aktualisiere Metasploit-Info
                self.wsl_distribution = distribution
                self.metasploit_info['wsl_enabled'] = True
                self.metasploit_info['wsl_distribution'] = distribution
                self.metasploit_info['installed'] = True
                self.metasploit_info['path'] = '/opt/metasploit-framework'
                
                return True
            else:
                print("❌ Metasploit-Installation fehlgeschlagen")
                return False
                
        except Exception as e:
            print(f"❌ Fehler bei WSL-Metasploit-Installation: {e}")
            return False
    
    def _install_metasploit_macos(self) -> bool:
        """Installiert Metasploit auf macOS"""
        print("📦 Installiere Metasploit für macOS...")
        
        try:
            # Prüfe ob Homebrew installiert ist
            brew_check = subprocess.run(['brew', '--version'], 
                                      capture_output=True, text=True, timeout=10)
            
            if brew_check.returncode != 0:
                print("🔄 Installiere Homebrew...")
                install_brew = subprocess.run([
                    '/bin/bash', '-c', 
                    '$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)'
                ], timeout=300)
                
                if install_brew.returncode != 0:
                    print("❌ Fehler bei Homebrew-Installation")
                    return False
            
            # Installiere Metasploit
            print("🔄 Installiere Metasploit Framework...")
            result = subprocess.run(['brew', 'install', 'metasploit'], timeout=600)
            
            if result.returncode == 0:
                time.sleep(5)
                return self.detect_metasploit()['installed']
            else:
                print("❌ Fehler bei Metasploit-Installation")
                return False
                
        except Exception as e:
            print(f"❌ Fehler bei macOS-Installation: {e}")
            return False
    
    def get_installation_status(self) -> str:
        """Gibt den Installationsstatus zurück"""
        return self.installation_status
    
    def print_metasploit_info(self):
        """Gibt Metasploit-Informationen aus"""
        print("=" * 50)
        print("METASPLOIT FRAMEWORK STATUS")
        print("=" * 50)
        
        if self.metasploit_info['installed']:
            print("✅ Status: INSTALLIERT")
            print(f"📍 Pfad: {self.metasploit_info['path']}")
            if self.metasploit_info['version']:
                print(f"🔢 Version: {self.metasploit_info['version']}")
            if self.metasploit_info['msfconsole_path']:
                print(f"🖥️  msfconsole: {self.metasploit_info['msfconsole_path']}")
            if self.metasploit_info['msfvenom_path']:
                print(f"⚡ msfvenom: {self.metasploit_info['msfvenom_path']}")
        else:
            print("❌ Status: NICHT INSTALLIERT")
            print("💡 Verwende install_metasploit() für automatische Installation")
        
        print("=" * 50)


def main():
    """Test-Funktion"""
    from system_detector import SystemDetector
    
    detector = SystemDetector()
    detector.detect_system()
    
    manager = MetasploitManager(detector)
    manager.detect_metasploit()
    manager.print_metasploit_info()


if __name__ == "__main__":
    main()
