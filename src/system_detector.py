#!/usr/bin/env python3
"""
System Detection Module for Metadox
Erkennt das Betriebssystem und dessen Version
"""

import platform
import subprocess
import sys
import os
from typing import Dict, Tuple, Optional


class SystemDetector:
    """Klasse zur Erkennung des Betriebssystems und dessen Eigenschaften"""
    
    def __init__(self):
        self.system_info = {}
        self.detected_os = None
        self.os_version = None
        self.architecture = None
        
    def detect_system(self) -> Dict[str, str]:
        """
        Erkennt das aktuelle Betriebssystem und sammelt relevante Informationen
        
        Returns:
            Dict mit Systeminformationen
        """
        try:
            # Grundlegende Systeminformationen
            self.detected_os = platform.system().lower()
            self.os_version = platform.release()
            self.architecture = platform.machine()
            
            self.system_info = {
                'os': self.detected_os,
                'version': self.os_version,
                'architecture': self.architecture,
                'platform': platform.platform(),
                'python_version': sys.version,
                'hostname': platform.node()
            }
            
            # Spezifische OS-Erkennung
            if self.detected_os == 'linux':
                self._detect_linux_distro()
            elif self.detected_os == 'darwin':
                self._detect_macos_version()
            elif self.detected_os == 'windows':
                self._detect_windows_version()
                
            return self.system_info
            
        except Exception as e:
            print(f"Fehler bei der Systemerkennung: {e}")
            return {}
    
    def _detect_linux_distro(self):
        """Erkennt Linux-Distribution"""
        try:
            # Versuche /etc/os-release zu lesen
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('ID='):
                            distro_id = line.split('=')[1].strip().strip('"')
                            self.system_info['distro'] = distro_id
                        elif line.startswith('VERSION_ID='):
                            version_id = line.split('=')[1].strip().strip('"')
                            self.system_info['distro_version'] = version_id
                            
            # Fallback: lsb_release
            try:
                result = subprocess.run(['lsb_release', '-a'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'Distributor ID:' in line:
                            distro = line.split(':')[1].strip()
                            self.system_info['distro'] = distro.lower()
                        elif 'Release:' in line:
                            release = line.split(':')[1].strip()
                            self.system_info['distro_version'] = release
            except:
                pass
                
        except Exception as e:
            print(f"Fehler bei Linux-Distribution-Erkennung: {e}")
    
    def _detect_macos_version(self):
        """Erkennt macOS Version"""
        try:
            result = subprocess.run(['sw_vers'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'ProductName:' in line:
                        product = line.split(':')[1].strip()
                        self.system_info['macos_product'] = product
                    elif 'ProductVersion:' in line:
                        version = line.split(':')[1].strip()
                        self.system_info['macos_version'] = version
        except Exception as e:
            print(f"Fehler bei macOS-Version-Erkennung: {e}")
    
    def _detect_windows_version(self):
        """Erkennt Windows Version"""
        try:
            # Try PowerShell method first (more reliable)
            try:
                result = subprocess.run([
                    'powershell', '-Command', 
                    'Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, TotalPhysicalMemory'
                ], capture_output=True, text=True, timeout=10, encoding='utf-8')
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'WindowsProductName' in line:
                            product = line.split(':')[1].strip()
                            self.system_info['windows_edition'] = product
                        elif 'WindowsVersion' in line:
                            version = line.split(':')[1].strip()
                            self.system_info['windows_version'] = version
                        elif 'TotalPhysicalMemory' in line:
                            memory = line.split(':')[1].strip()
                            self.system_info['total_memory'] = memory
            except:
                pass
            
            # Fallback to systeminfo
            try:
                result = subprocess.run(['systeminfo'], capture_output=True, text=True, timeout=15, encoding='cp1252')
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'OS Name:' in line:
                            os_name = line.split(':', 1)[1].strip()
                            self.system_info['windows_edition'] = os_name
                        elif 'OS Version:' in line:
                            os_version = line.split(':', 1)[1].strip()
                            self.system_info['windows_version'] = os_version
                        elif 'Total Physical Memory:' in line:
                            memory = line.split(':', 1)[1].strip()
                            self.system_info['total_memory'] = memory
                        elif 'System Type:' in line:
                            system_type = line.split(':', 1)[1].strip()
                            self.system_info['system_type'] = system_type
            except:
                pass
            
            # Detect Windows version number
            if 'windows_version' in self.system_info:
                version_str = self.system_info['windows_version']
                if '10.0' in version_str:
                    self.system_info['windows_major_version'] = '10'
                elif '6.3' in version_str:
                    self.system_info['windows_major_version'] = '8.1'
                elif '6.2' in version_str:
                    self.system_info['windows_major_version'] = '8'
                elif '6.1' in version_str:
                    self.system_info['windows_major_version'] = '7'
                    
        except Exception as e:
            print(f"Fehler bei Windows-Version-Erkennung: {e}")
    
    def get_os_type(self) -> str:
        """Gibt den OS-Typ zurück"""
        return self.detected_os
    
    def is_linux(self) -> bool:
        """Prüft ob Linux"""
        return self.detected_os == 'linux'
    
    def is_windows(self) -> bool:
        """Prüft ob Windows"""
        return self.detected_os == 'windows'
    
    def is_macos(self) -> bool:
        """Prüft ob macOS"""
        return self.detected_os == 'darwin'
    
    def get_package_manager(self) -> Optional[str]:
        """Gibt den passenden Package Manager zurück"""
        if self.is_linux():
            distro = self.system_info.get('distro', '')
            if distro in ['ubuntu', 'debian']:
                return 'apt'
            elif distro in ['centos', 'rhel', 'fedora']:
                return 'yum'
            elif distro in ['arch', 'manjaro']:
                return 'pacman'
            elif distro in ['opensuse', 'sles']:
                return 'zypper'
        elif self.is_macos():
            return 'brew'
        elif self.is_windows():
            return 'chocolatey'
        
        return None
    
    def print_system_info(self):
        """Gibt Systeminformationen aus"""
        print("=" * 50)
        print("SYSTEM ERKENNUNG")
        print("=" * 50)
        for key, value in self.system_info.items():
            print(f"{key.upper()}: {value}")
        print("=" * 50)


def main():
    """Test-Funktion"""
    detector = SystemDetector()
    system_info = detector.detect_system()
    detector.print_system_info()
    
    print(f"\nPackage Manager: {detector.get_package_manager()}")
    print(f"OS Type: {detector.get_os_type()}")


if __name__ == "__main__":
    main()
