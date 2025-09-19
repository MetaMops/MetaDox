"""
Python Payload Analyzer - Dedicated analyzer for Python payloads
"""

import os
import re
import hashlib
import base64
from ...colors import Colors

class PythonAnalyzer:
    def __init__(self):
        self.colors = Colors()
        
        # Metasploit-specific patterns
        self.metasploit_patterns = [
            'meterpreter', 'reverse_tcp', 'bind_tcp', 'reverse_https',
            'reverse_http', 'reverse_udp', 'bind_udp', 'payload',
            'shell', 'cmd', 'powershell', 'cmd.exe'
        ]
        
        # Shellcode patterns
        self.shellcode_patterns = [
            r'buf\s*=\s*b["\']',  # Shellcode buffer
            r'buf\s*\+=\s*b["\']',  # Shellcode concatenation
            r'\\x[0-9a-fA-F]{2}',  # Hex patterns
            r'0x[0-9a-fA-F]+',  # Hex numbers
        ]
        
        # Network patterns
        self.network_patterns = [
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',  # IP addresses
            r'\b(?:[0-9]{4,5})\b',  # Port numbers
        ]
        
        # Suspicious imports
        self.suspicious_imports = [
            'socket', 'subprocess', 'os', 'sys', 'ctypes', 'struct',
            'base64', 'zlib', 'pickle', 'marshal', 'codecs', 'urllib',
            'requests', 'httplib', 'ftplib', 'smtplib', 'telnetlib'
        ]
        
        # Suspicious functions
        self.suspicious_functions = [
            'exec', 'eval', 'compile', 'execfile', 'reload', '__import__',
            'getattr', 'setattr', 'delattr', 'hasattr', 'vars', 'locals',
            'globals', 'dir', 'callable', 'isinstance', 'issubclass'
        ]
    
    def analyze(self, file_path):
        """Main analysis function for Python files"""
        try:
            result = {
                'infected': False,
                'confidence': 0,
                'indicators': [],
                'details': [],
                'file_type': 'Python Script',
                'payload_type': 'Unknown'
            }
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Analyze payload type
            payload_type = self._detect_payload_type(content)
            result['payload_type'] = payload_type
            
            # Analyze shellcode patterns
            shellcode_result = self._analyze_shellcode(content)
            result['indicators'].extend(shellcode_result['indicators'])
            result['confidence'] += shellcode_result['confidence']
            
            # Analyze Metasploit patterns
            metasploit_result = self._analyze_metasploit(content)
            result['indicators'].extend(metasploit_result['indicators'])
            result['confidence'] += metasploit_result['confidence']
            
            # Analyze network patterns
            network_result = self._analyze_network(content)
            result['indicators'].extend(network_result['indicators'])
            result['confidence'] += network_result['confidence']
            
            # Analyze imports
            import_result = self._analyze_imports(content)
            result['indicators'].extend(import_result['indicators'])
            result['confidence'] += import_result['confidence']
            
            # Analyze functions
            function_result = self._analyze_functions(content)
            result['indicators'].extend(function_result['indicators'])
            result['confidence'] += function_result['confidence']
            
            # Analyze binary/encoded content
            binary_result = self._analyze_binary_content(file_path, content)
            result['indicators'].extend(binary_result['indicators'])
            result['confidence'] += binary_result['confidence']
            
            # Determine if infected
            result['infected'] = result['confidence'] >= 30
            result['confidence'] = min(result['confidence'], 100)
            
            return result
            
        except Exception as e:
            return {
                'infected': False,
                'confidence': 0,
                'indicators': [f"Analysis error: {str(e)}"],
                'details': [],
                'file_type': 'Python Script',
                'payload_type': 'Unknown'
            }
    
    def _detect_payload_type(self, content):
        """Detect the type of payload"""
        content_lower = content.lower()
        
        if 'meterpreter' in content_lower:
            if 'reverse_tcp' in content_lower:
                return 'Meterpreter Reverse TCP'
            elif 'bind_tcp' in content_lower:
                return 'Meterpreter Bind TCP'
            elif 'reverse_https' in content_lower:
                return 'Meterpreter Reverse HTTPS'
            elif 'reverse_http' in content_lower:
                return 'Meterpreter Reverse HTTP'
            else:
                return 'Meterpreter'
        elif 'shell' in content_lower:
            return 'Shell'
        elif 'cmd' in content_lower:
            return 'Command'
        else:
            return 'Unknown'
    
    def _analyze_shellcode(self, content):
        """Analyze shellcode patterns"""
        result = {'indicators': [], 'confidence': 0}
        
        # Check for shellcode buffer
        if 'buf =' in content and 'b"\\x' in content:
            result['indicators'].append("Shellcode buffer detected")
            result['confidence'] += 40
        
        # Check for byte concatenation
        if 'buf +=' in content and 'b"\\x' in content:
            result['indicators'].append("Byte concatenation pattern detected")
            result['confidence'] += 30
        
        # Check for hex patterns
        hex_patterns = re.findall(r'\\x[0-9a-fA-F]{2}', content)
        if len(hex_patterns) > 10:
            result['indicators'].append(f"Multiple hex patterns detected ({len(hex_patterns)})")
            result['confidence'] += 25
        
        return result
    
    def _analyze_metasploit(self, content):
        """Analyze Metasploit-specific patterns"""
        result = {'indicators': [], 'confidence': 0}
        
        for pattern in self.metasploit_patterns:
            if pattern in content.lower():
                result['indicators'].append(f"Metasploit pattern: {pattern}")
                result['confidence'] += 25
        
        return result
    
    def _analyze_network(self, content):
        """Analyze network patterns"""
        result = {'indicators': [], 'confidence': 0}
        
        # Check for IP addresses
        ip_patterns = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)
        if ip_patterns:
            result['indicators'].append(f"IP addresses detected: {', '.join(ip_patterns)}")
            result['confidence'] += 20
        
        # Check for port numbers
        port_patterns = re.findall(r'\b(?:[0-9]{4,5})\b', content)
        if port_patterns:
            result['indicators'].append(f"Port numbers detected: {', '.join(port_patterns)}")
            result['confidence'] += 15
        
        return result
    
    def _analyze_imports(self, content):
        """Analyze suspicious imports"""
        result = {'indicators': [], 'confidence': 0}
        
        for imp in self.suspicious_imports:
            if f'import {imp}' in content or f'from {imp}' in content:
                result['indicators'].append(f"Suspicious import: {imp}")
                result['confidence'] += 10
        
        return result
    
    def _analyze_functions(self, content):
        """Analyze suspicious functions"""
        result = {'indicators': [], 'confidence': 0}
        
        for func in self.suspicious_functions:
            if func in content:
                result['indicators'].append(f"Suspicious function: {func}")
                result['confidence'] += 15
        
        return result
    
    def _analyze_binary_content(self, file_path, content):
        """Intelligent binary/encoded content analysis for Python files"""
        result = {'indicators': [], 'confidence': 0}
        
        try:
            # Read binary content
            with open(file_path, 'rb') as f:
                binary_content = f.read()
            
            # Check for legitimate Python bytecode/compiled files
            if file_path.endswith('.pyc') or file_path.endswith('.pyo'):
                # It's a legitimate Python bytecode file
                return result
            
            # Check for legitimate encoding patterns (not payloads)
            legitimate_patterns = [
                'import base64',
                'import zlib',
                'import gzip',
                'import json',
                'import pickle',
                'import marshal',
                'import codecs',
                'import binascii',
                'import hashlib',
                'import hmac',
                'import ssl',
                'import cryptography',
                'import pycryptodome',
            ]
            
            has_legitimate_imports = any(pattern in content for pattern in legitimate_patterns)
            
            # Check for Base64 content
            base64_patterns = re.findall(r'["\']([A-Za-z0-9+/=]{20,})["\']', content)
            if base64_patterns:
                # Analyze Base64 content
                for b64_string in base64_patterns[:3]:  # Check first 3 instances
                    try:
                        decoded = base64.b64decode(b64_string).decode('utf-8', errors='ignore')
                        
                        # Check if decoded content contains payload signatures
                        payload_signatures = [
                            'meterpreter', 'reverse_tcp', 'bind_tcp', 'payload',
                            'shell', 'cmd', 'powershell', 'CreateProcess',
                            'WinExec', 'VirtualAlloc', 'CreateThread',
                            'kernel32.dll', 'ws2_32.dll', 'wininet.dll'
                        ]
                        
                        found_signatures = [sig for sig in payload_signatures if sig in decoded.lower()]
                        
                        if found_signatures:
                            result['indicators'].append(f"Base64 payload signatures: {', '.join(found_signatures[:3])}")
                            result['confidence'] += 40
                        elif not has_legitimate_imports:
                            # Base64 without legitimate imports might be suspicious
                            result['indicators'].append("Base64 content without legitimate imports")
                            result['confidence'] += 15
                            
                    except Exception:
                        # Invalid Base64, might be obfuscated
                        if not has_legitimate_imports:
                            result['indicators'].append("Invalid Base64 content detected")
                            result['confidence'] += 10
            
            # Check for hex patterns
            hex_patterns = re.findall(r'["\']([0-9a-fA-F]{20,})["\']', content)
            if hex_patterns:
                for hex_string in hex_patterns[:2]:  # Check first 2 instances
                    try:
                        decoded = bytes.fromhex(hex_string).decode('utf-8', errors='ignore')
                        
                        # Check for payload signatures in hex-decoded content
                        payload_signatures = [
                            'meterpreter', 'reverse_tcp', 'bind_tcp', 'payload',
                            'shell', 'cmd', 'powershell', 'CreateProcess',
                            'WinExec', 'VirtualAlloc', 'CreateThread'
                        ]
                        
                        found_signatures = [sig for sig in payload_signatures if sig in decoded.lower()]
                        
                        if found_signatures:
                            result['indicators'].append(f"Hex payload signatures: {', '.join(found_signatures[:3])}")
                            result['confidence'] += 45
                            
                    except Exception:
                        # Invalid hex, might be obfuscated
                        if not has_legitimate_imports:
                            result['indicators'].append("Invalid hex content detected")
                            result['confidence'] += 10
            
            # Check for binary content in the file
            printable_chars = sum(1 for c in binary_content if 32 <= c <= 126 or c in [9, 10, 13])
            total_chars = len(binary_content)
            printable_ratio = printable_chars / total_chars if total_chars > 0 else 0
            
            # If less than 80% printable characters, might be binary/encrypted
            if printable_ratio < 0.8:
                # Check if it's a legitimate binary file
                if not has_legitimate_imports:
                    result['indicators'].append("Binary/encrypted content without legitimate imports")
                    result['confidence'] += 25
                
                # Check for payload signatures in binary content
                payload_signatures = [
                    b'meterpreter', b'reverse_tcp', b'bind_tcp', b'payload',
                    b'shell', b'cmd.exe', b'powershell', b'CreateProcess',
                    b'WinExec', b'VirtualAlloc', b'CreateThread'
                ]
                
                found_signatures = []
                for sig in payload_signatures:
                    if sig in binary_content:
                        found_signatures.append(sig.decode('utf-8', errors='ignore'))
                
                if found_signatures:
                    result['indicators'].append(f"Binary payload signatures: {', '.join(found_signatures[:3])}")
                    result['confidence'] += 50
            
            # Check for obfuscation patterns
            obfuscation_patterns = [
                r'exec\s*\(\s*["\']',  # exec with string
                r'eval\s*\(\s*["\']',  # eval with string
                r'compile\s*\(\s*["\']',  # compile with string
                r'__import__\s*\(\s*["\']',  # __import__ with string
                r'getattr\s*\(\s*["\']',  # getattr with string
                r'setattr\s*\(\s*["\']',  # setattr with string
            ]
            
            obfuscation_count = 0
            for pattern in obfuscation_patterns:
                if re.search(pattern, content):
                    obfuscation_count += 1
            
            if obfuscation_count > 2:
                result['indicators'].append(f"Multiple obfuscation patterns detected ({obfuscation_count})")
                result['confidence'] += 30
            
        except Exception as e:
            result['indicators'].append(f"Binary analysis error: {str(e)}")
        
        return result
    
    def display_result(self, result, file_path):
        """Display analysis result"""
        print(f"\n{self.colors.CYAN}🔍 Python Payload Analysis: {os.path.basename(file_path)}{self.colors.RESET}")
        print(f"   Payload Type: {result['payload_type']}")
        
        if result['infected']:
            print(f"{self.colors.RED}🚨 RESULT: INFECTED{self.colors.RESET}")
        else:
            print(f"{self.colors.GREEN}✅ RESULT: CLEAR{self.colors.RESET}")
        
        print(f"   Confidence: {result['confidence']}%")
        
        if result['indicators']:
            print(f"\n{self.colors.YELLOW}⚠️  Suspicious Indicators:{self.colors.RESET}")
            for indicator in result['indicators']:
                print(f"   • {indicator}")
        else:
            print(f"\n{self.colors.GREEN}✅ No suspicious indicators found{self.colors.RESET}")
        
        return result