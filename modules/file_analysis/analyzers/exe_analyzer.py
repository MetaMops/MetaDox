"""
EXE Payload Analyzer - Dedicated analyzer for Windows executables
"""

import os
import subprocess
import re
from ...colors import Colors

class ExeAnalyzer:
    def __init__(self):
        self.colors = Colors()
        
        # Suspicious imports
        self.suspicious_imports = [
            'kernel32.dll', 'ws2_32.dll', 'wininet.dll', 'urlmon.dll',
            'CreateProcess', 'WinExec', 'URLDownloadToFile', 'InternetOpen',
            'InternetReadFile', 'socket', 'connect', 'send', 'recv',
            'VirtualAlloc', 'CreateThread', 'WriteProcessMemory'
        ]
        
        # Suspicious strings
        self.suspicious_strings = [
            'meterpreter', 'reverse_tcp', 'bind_tcp', 'payload',
            'shell', 'cmd', 'powershell', 'cmd.exe', 'cmd /c',
            'wget', 'curl', 'nc', 'netcat', 'bash', 'sh'
        ]
        
        # Metasploit patterns
        self.metasploit_patterns = [
            'meterpreter', 'reverse_tcp', 'bind_tcp', 'reverse_https',
            'reverse_http', 'reverse_udp', 'bind_udp'
        ]
    
    def analyze(self, file_path):
        """Main analysis function for EXE files"""
        try:
            result = {
                'infected': False,
                'confidence': 0,
                'indicators': [],
                'details': [],
                'file_type': 'Windows Executable',
                'payload_type': 'Unknown'
            }
            
            # Analyze PE structure
            pe_result = self._analyze_pe_structure(file_path)
            result['indicators'].extend(pe_result['indicators'])
            result['confidence'] += pe_result['confidence']
            
            # Analyze imports
            import_result = self._analyze_imports(file_path)
            result['indicators'].extend(import_result['indicators'])
            result['confidence'] += import_result['confidence']
            
            # Analyze strings
            string_result = self._analyze_strings(file_path)
            result['indicators'].extend(string_result['indicators'])
            result['confidence'] += string_result['confidence']
            
            # Analyze binary content for payloads
            binary_result = self._analyze_binary_content(file_path)
            result['indicators'].extend(binary_result['indicators'])
            result['confidence'] += binary_result['confidence']
            
            # Detect payload type
            payload_type = self._detect_payload_type(string_result['content'])
            result['payload_type'] = payload_type
            
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
                'file_type': 'Windows Executable',
                'payload_type': 'Unknown'
            }
    
    def _analyze_pe_structure(self, file_path):
        """Analyze PE file structure"""
        result = {'indicators': [], 'confidence': 0}
        
        try:
            # Use objdump to check sections
            objdump_result = subprocess.run(['objdump', '-h', file_path], 
                                          capture_output=True, text=True, timeout=10)
            if objdump_result.returncode == 0:
                output = objdump_result.stdout
                
                # Check for suspicious sections
                if '.text' not in output:
                    result['indicators'].append("Missing .text section")
                    result['confidence'] += 20
                
                if '.data' not in output:
                    result['indicators'].append("Missing .data section")
                    result['confidence'] += 15
                
                if '.rsrc' in output:
                    result['indicators'].append("Resource section found (.rsrc)")
                    result['confidence'] += 10
                
                if '.rdata' in output:
                    result['indicators'].append("Read-only data section found (.rdata)")
                    result['confidence'] += 5
                    
        except Exception as e:
            result['indicators'].append(f"PE structure analysis error: {str(e)}")
        
        return result
    
    def _analyze_imports(self, file_path):
        """Analyze PE imports"""
        result = {'indicators': [], 'confidence': 0}
        
        try:
            # Use objdump to check imports
            objdump_result = subprocess.run(['objdump', '-p', file_path], 
                                          capture_output=True, text=True, timeout=10)
            if objdump_result.returncode == 0:
                output = objdump_result.stdout
                
                # Check for suspicious imports
                found_imports = []
                for imp in self.suspicious_imports:
                    if imp in output:
                        found_imports.append(imp)
                
                if found_imports:
                    result['indicators'].append(f"Suspicious imports: {', '.join(found_imports[:5])}")
                    result['confidence'] += min(len(found_imports) * 15, 60)
                    
        except Exception as e:
            result['indicators'].append(f"Import analysis error: {str(e)}")
        
        return result
    
    def _analyze_strings(self, file_path):
        """Analyze strings in the executable"""
        result = {'indicators': [], 'confidence': 0, 'content': ''}
        
        try:
            # Use strings command to extract strings
            strings_result = subprocess.run(['strings', file_path], 
                                          capture_output=True, text=True, timeout=30)
            if strings_result.returncode == 0:
                content = strings_result.stdout
                result['content'] = content
                
                # Check for suspicious strings
                found_strings = []
                for s in self.suspicious_strings:
                    if s in content.lower():
                        found_strings.append(s)
                
                if found_strings:
                    result['indicators'].append(f"Suspicious strings: {', '.join(found_strings[:5])}")
                    result['confidence'] += min(len(found_strings) * 20, 80)
                
                # Check for Metasploit patterns
                metasploit_found = []
                for pattern in self.metasploit_patterns:
                    if pattern in content.lower():
                        metasploit_found.append(pattern)
                
                if metasploit_found:
                    result['indicators'].append(f"Metasploit patterns: {', '.join(metasploit_found)}")
                    result['confidence'] += 30
                    
        except Exception as e:
            result['indicators'].append(f"String analysis error: {str(e)}")
        
        return result
    
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
    
    def _analyze_binary_content(self, file_path):
        """Intelligent binary content analysis for EXE files"""
        result = {'indicators': [], 'confidence': 0}
        
        try:
            with open(file_path, 'rb') as f:
                binary_content = f.read()
            
            # Check for legitimate encryption/compression signatures
            legitimate_signatures = [
                b'PK\x03\x04',  # ZIP/compressed files
                b'PK\x05\x06',  # ZIP empty archive
                b'PK\x07\x08',  # ZIP spanned archive
                b'\x1f\x8b\x08',  # GZIP
                b'BZh',  # BZIP2
                b'\xfd7zXZ\x00',  # XZ
                b'7z\xbc\xaf\x27\x1c',  # 7-Zip
                b'Rar!\x1a\x07\x00',  # RAR
                b'Rar!\x1a\x07\x01\x00',  # RAR v5
            ]
            
            # Check if it's a legitimate compressed/encrypted file
            is_legitimate = False
            for sig in legitimate_signatures:
                if binary_content.startswith(sig):
                    is_legitimate = True
                    break
            
            if is_legitimate:
                # It's a legitimate compressed file, don't flag as suspicious
                return result
            
            # Check for suspicious patterns in binary content
            suspicious_patterns = [
                b'meterpreter',
                b'reverse_tcp',
                b'bind_tcp',
                b'payload',
                b'shell',
                b'cmd.exe',
                b'powershell',
                b'CreateProcess',
                b'WinExec',
                b'URLDownloadToFile',
                b'VirtualAlloc',
                b'CreateThread',
                b'WriteProcessMemory',
                b'kernel32.dll',
                b'ws2_32.dll',
                b'wininet.dll',
            ]
            
            found_patterns = []
            for pattern in suspicious_patterns:
                if pattern in binary_content:
                    found_patterns.append(pattern.decode('utf-8', errors='ignore'))
            
            if found_patterns:
                result['indicators'].append(f"Binary payload signatures: {', '.join(found_patterns[:3])}")
                result['confidence'] += min(len(found_patterns) * 25, 75)
            
            # Check for high entropy (encrypted/packed content)
            entropy = self._calculate_entropy(binary_content)
            if entropy > 7.5:  # High entropy indicates encryption/packing
                result['indicators'].append(f"High entropy detected ({entropy:.2f}) - possible encryption/packing")
                result['confidence'] += 20
            
            # Check for PE header manipulation
            if binary_content.startswith(b'MZ'):
                # Check for suspicious PE characteristics
                if b'.text' in binary_content and b'.data' in binary_content:
                    # Normal PE structure
                    pass
                else:
                    result['indicators'].append("Suspicious PE structure")
                    result['confidence'] += 15
            
        except Exception as e:
            result['indicators'].append(f"Binary analysis error: {str(e)}")
        
        return result
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of binary data"""
        if not data:
            return 0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        import math
        entropy = 0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def display_result(self, result, file_path):
        """Display analysis result"""
        print(f"\n{self.colors.CYAN}🔍 EXE Payload Analysis: {os.path.basename(file_path)}{self.colors.RESET}")
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