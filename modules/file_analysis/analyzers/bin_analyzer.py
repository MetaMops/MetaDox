"""
BIN Analyzer - Comprehensive analysis for binary payloads
Professional-grade detection with multiple analysis layers
"""

import os
import re
import hashlib
import subprocess
import struct
from ...colors import Colors

class BinAnalyzer:
    def __init__(self):
        self.colors = Colors()
        
        # Binary payload signatures
        self.payload_signatures = [
            # Metasploit signatures
            b'meterpreter',
            b'reverse_tcp',
            b'bind_tcp',
            b'reverse_https',
            b'reverse_http',
            b'reverse_udp',
            b'bind_udp',
            b'payload',
            b'shell',
            b'cmd.exe',
            b'powershell',
            b'msfvenom',
            b'msfconsole',
            
            # Windows API signatures
            b'CreateProcess',
            b'WinExec',
            b'URLDownloadToFile',
            b'VirtualAlloc',
            b'CreateThread',
            b'WriteProcessMemory',
            b'ReadProcessMemory',
            b'OpenProcess',
            b'TerminateProcess',
            b'kernel32.dll',
            b'ws2_32.dll',
            b'wininet.dll',
            b'urlmon.dll',
            b'advapi32.dll',
            b'ntdll.dll',
            
            # Linux/Unix signatures
            b'/bin/sh',
            b'/bin/bash',
            b'/usr/bin/python',
            b'/usr/bin/perl',
            b'execve',
            b'fork',
            b'waitpid',
            b'socket',
            b'connect',
            b'bind',
            b'listen',
            b'accept',
            b'send',
            b'recv',
            b'libc.so',
            b'libpthread.so',
            
            # Network signatures
            b'HTTP/1.1',
            b'GET /',
            b'POST /',
            b'User-Agent:',
            b'Host:',
            b'Connection:',
            b'Content-Type:',
            b'Content-Length:',
        ]
        
        # High-confidence payload patterns
        self.high_confidence_patterns = [
            b'meterpreter',
            b'reverse_tcp',
            b'CreateProcess',
            b'VirtualAlloc',
            b'CreateThread',
            b'execve',
            b'socket',
            b'connect',
        ]
        
        # Shellcode patterns
        self.shellcode_patterns = [
            b'\x90\x90\x90\x90',  # NOP sled
            b'\x31\xc0',  # xor eax, eax
            b'\x31\xdb',  # xor ebx, ebx
            b'\x31\xc9',  # xor ecx, ecx
            b'\x31\xd2',  # xor edx, edx
            b'\x50',  # push eax
            b'\x51',  # push ecx
            b'\x52',  # push edx
            b'\x53',  # push ebx
            b'\x54',  # push esp
            b'\x55',  # push ebp
            b'\x56',  # push esi
            b'\x57',  # push edi
            b'\x58',  # pop eax
            b'\x59',  # pop ecx
            b'\x5a',  # pop edx
            b'\x5b',  # pop ebx
            b'\x5c',  # pop esp
            b'\x5d',  # pop ebp
            b'\x5e',  # pop esi
            b'\x5f',  # pop edi
        ]
        
        # File format signatures
        self.file_format_signatures = {
            b'MZ': 'PE/EXE',
            b'\x7fELF': 'ELF',
            b'\xfe\xed\xfa': 'Mach-O (32-bit)',
            b'\xfe\xed\xfa\xce': 'Mach-O (32-bit)',
            b'\xfe\xed\xfa\xcf': 'Mach-O (64-bit)',
            b'\xce\xfa\xed\xfe': 'Mach-O (32-bit, big-endian)',
            b'\xcf\xfa\xed\xfe': 'Mach-O (64-bit, big-endian)',
            b'PK\x03\x04': 'ZIP',
            b'PK\x05\x06': 'ZIP (empty)',
            b'PK\x07\x08': 'ZIP (spanned)',
            b'\x1f\x8b\x08': 'GZIP',
            b'BZh': 'BZIP2',
            b'\xfd7zXZ\x00': 'XZ',
            b'7z\xbc\xaf\x27\x1c': '7-Zip',
            b'Rar!\x1a\x07\x00': 'RAR',
            b'Rar!\x1a\x07\x01\x00': 'RAR v5',
        }

    def analyze(self, file_path):
        """Comprehensive binary file analysis"""
        try:
            result = {
                'infected': False,
                'confidence': 0,
                'payload_type': 'Unknown',
                'indicators': [],
                'analysis_details': {},
                'file_info': self._get_file_info(file_path)
            }
            
            # Read binary content
            with open(file_path, 'rb') as f:
                binary_content = f.read()
            
            # Analysis layers
            result['analysis_details']['file_size'] = len(binary_content)
            
            # 1. File Format Detection
            format_analysis = self._analyze_file_format(binary_content)
            result['analysis_details']['format_analysis'] = format_analysis
            
            # 2. High-Confidence Pattern Detection
            high_confidence_score = self._detect_high_confidence_patterns(binary_content)
            result['analysis_details']['high_confidence_score'] = high_confidence_score
            
            # 3. Payload Signature Detection
            payload_score = self._detect_payload_signatures(binary_content)
            result['analysis_details']['payload_score'] = payload_score
            
            # 4. Shellcode Detection
            shellcode_score = self._detect_shellcode(binary_content)
            result['analysis_details']['shellcode_score'] = shellcode_score
            
            # 5. Entropy Analysis
            entropy_analysis = self._analyze_entropy(binary_content)
            result['analysis_details']['entropy_analysis'] = entropy_analysis
            
            # 6. String Analysis
            string_analysis = self._analyze_strings(binary_content)
            result['analysis_details']['string_analysis'] = string_analysis
            
            # 7. Network Pattern Detection
            network_score = self._detect_network_patterns(binary_content)
            result['analysis_details']['network_score'] = network_score
            
            # Calculate overall confidence
            total_score = (high_confidence_score * 0.3 + 
                          payload_score * 0.25 + 
                          shellcode_score * 0.2 + 
                          entropy_analysis['score'] * 0.1 + 
                          network_score * 0.15)
            
            result['confidence'] = min(100, total_score)
            
            # Determine if infected
            if result['confidence'] >= 20:
                result['infected'] = True
                result['payload_type'] = self._determine_payload_type(binary_content)
            
            # Collect indicators
            result['indicators'] = self._collect_indicators(result['analysis_details'])
            
            return result
            
        except Exception as e:
            return {
                'infected': False,
                'confidence': 0,
                'payload_type': 'Analysis Error',
                'indicators': [f'Analysis failed: {str(e)}'],
                'analysis_details': {'error': str(e)},
                'file_info': {'error': str(e)}
            }

    def _get_file_info(self, file_path):
        """Get basic file information"""
        try:
            stat = os.stat(file_path)
            with open(file_path, 'rb') as f:
                content = f.read()
            
            return {
                'name': os.path.basename(file_path),
                'path': file_path,
                'size': stat.st_size,
                'md5': hashlib.md5(content).hexdigest(),
                'sha256': hashlib.sha256(content).hexdigest(),
                'extension': '.bin'
            }
        except Exception as e:
            return {'error': str(e)}

    def _analyze_file_format(self, binary_content):
        """Analyze file format"""
        analysis = {'format': 'Unknown', 'score': 0}
        
        # Check for known file format signatures
        for signature, format_name in self.file_format_signatures.items():
            if binary_content.startswith(signature):
                analysis['format'] = format_name
                analysis['score'] = 10
                break
        
        return analysis

    def _detect_high_confidence_patterns(self, binary_content):
        """Detect high-confidence payload patterns"""
        score = 0
        found_patterns = []
        
        for pattern in self.high_confidence_patterns:
            if pattern in binary_content:
                found_patterns.append(pattern.decode('utf-8', errors='ignore'))
                score += 40
        
        return min(100, score)

    def _detect_payload_signatures(self, binary_content):
        """Detect payload signatures"""
        score = 0
        found_signatures = []
        
        for signature in self.payload_signatures:
            if signature in binary_content:
                found_signatures.append(signature.decode('utf-8', errors='ignore'))
                score += 15
        
        return min(100, score)

    def _detect_shellcode(self, binary_content):
        """Detect shellcode patterns"""
        score = 0
        found_patterns = []
        
        for pattern in self.shellcode_patterns:
            if pattern in binary_content:
                found_patterns.append(pattern.hex())
                score += 20
        
        return min(100, score)

    def _analyze_entropy(self, binary_content):
        """Analyze entropy of binary content"""
        analysis = {'entropy': 0, 'score': 0}
        
        if not binary_content:
            return analysis
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in binary_content:
            byte_counts[byte] += 1
        
        # Calculate entropy
        import math
        entropy = 0
        data_len = len(binary_content)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        analysis['entropy'] = entropy
        
        # High entropy indicates encryption/packing
        if entropy > 7.5:
            analysis['score'] = 30
        elif entropy > 7.0:
            analysis['score'] = 20
        elif entropy > 6.5:
            analysis['score'] = 10
        
        return analysis

    def _analyze_strings(self, binary_content):
        """Analyze strings in binary content"""
        analysis = {'strings': [], 'score': 0}
        
        # Extract printable strings (length >= 4)
        strings = []
        current_string = b''
        
        for byte in binary_content:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += bytes([byte])
            else:
                if len(current_string) >= 4:
                    strings.append(current_string.decode('utf-8', errors='ignore'))
                current_string = b''
        
        # Add the last string if it exists
        if len(current_string) >= 4:
            strings.append(current_string.decode('utf-8', errors='ignore'))
        
        analysis['strings'] = strings
        
        # Check for suspicious strings
        suspicious_strings = [
            'meterpreter', 'reverse_tcp', 'bind_tcp', 'payload',
            'shell', 'cmd', 'powershell', 'CreateProcess',
            'WinExec', 'VirtualAlloc', 'CreateThread',
            'kernel32.dll', 'ws2_32.dll', 'wininet.dll',
            '/bin/sh', '/bin/bash', 'execve', 'socket',
            'connect', 'bind', 'listen', 'accept'
        ]
        
        found_suspicious = 0
        for string in strings:
            for suspicious in suspicious_strings:
                if suspicious.lower() in string.lower():
                    found_suspicious += 1
                    break
        
        if found_suspicious > 0:
            analysis['score'] = min(found_suspicious * 10, 50)
        
        return analysis

    def _detect_network_patterns(self, binary_content):
        """Detect network-related patterns"""
        score = 0
        found_patterns = []
        
        network_patterns = [
            b'HTTP/1.1',
            b'GET /',
            b'POST /',
            b'User-Agent:',
            b'Host:',
            b'Connection:',
            b'Content-Type:',
            b'Content-Length:',
            b'socket',
            b'connect',
            b'bind',
            b'listen',
            b'accept',
            b'send',
            b'recv',
        ]
        
        for pattern in network_patterns:
            if pattern in binary_content:
                found_patterns.append(pattern.decode('utf-8', errors='ignore'))
                score += 15
        
        return min(100, score)

    def _determine_payload_type(self, binary_content):
        """Determine the type of payload"""
        content_lower = binary_content.lower()
        
        if b'meterpreter' in content_lower:
            if b'reverse_tcp' in content_lower:
                return 'Meterpreter Reverse TCP'
            elif b'bind_tcp' in content_lower:
                return 'Meterpreter Bind TCP'
            elif b'reverse_https' in content_lower:
                return 'Meterpreter Reverse HTTPS'
            elif b'reverse_http' in content_lower:
                return 'Meterpreter Reverse HTTP'
            else:
                return 'Meterpreter'
        elif b'shell' in content_lower:
            return 'Shell'
        elif b'cmd' in content_lower:
            return 'Command'
        elif b'socket' in content_lower:
            return 'Network Payload'
        else:
            return 'Binary Payload'

    def _collect_indicators(self, analysis_details):
        """Collect all suspicious indicators"""
        indicators = []
        
        # High confidence indicators
        if analysis_details.get('high_confidence_score', 0) > 0:
            indicators.append(f"High-confidence payload patterns detected (score: {analysis_details['high_confidence_score']})")
        
        if analysis_details.get('payload_score', 0) > 30:
            indicators.append(f"Payload signatures detected (score: {analysis_details['payload_score']})")
        
        if analysis_details.get('shellcode_score', 0) > 0:
            indicators.append(f"Shellcode patterns detected (score: {analysis_details['shellcode_score']})")
        
        # Entropy analysis
        entropy_analysis = analysis_details.get('entropy_analysis', {})
        if entropy_analysis.get('score', 0) > 0:
            indicators.append(f"High entropy detected ({entropy_analysis['entropy']:.2f}) - possible encryption/packing")
        
        # String analysis
        string_analysis = analysis_details.get('string_analysis', {})
        if string_analysis.get('score', 0) > 0:
            indicators.append(f"Suspicious strings detected (score: {string_analysis['score']})")
        
        # Network patterns
        if analysis_details.get('network_score', 0) > 0:
            indicators.append(f"Network patterns detected (score: {analysis_details['network_score']})")
        
        # File format
        format_analysis = analysis_details.get('format_analysis', {})
        if format_analysis.get('format') != 'Unknown':
            indicators.append(f"File format: {format_analysis['format']}")
        
        return indicators

    def display_result(self, result, file_path):
        """Display analysis result"""
        print(f"\n{self.colors.CYAN}🔍 BIN Payload Analysis: {os.path.basename(file_path)}{self.colors.RESET}")
        print(f"   Payload Type: {result['payload_type']}")
        
        if result['infected']:
            print(f"{self.colors.RED}🚨 RESULT: INFECTED{self.colors.RESET}")
        else:
            print(f"{self.colors.GREEN}✅ RESULT: CLEAR{self.colors.RESET}")
        
        print(f"   Confidence: {result['confidence']}%")
        
        # Display analysis details
        details = result.get('analysis_details', {})
        if details:
            print(f"\n{self.colors.YELLOW}📊 Analysis Details:{self.colors.RESET}")
            print(f"   File Size: {details.get('file_size', 0)} bytes")
            print(f"   High-Confidence Score: {details.get('high_confidence_score', 0)}/100")
            print(f"   Payload Score: {details.get('payload_score', 0)}/100")
            print(f"   Shellcode Score: {details.get('shellcode_score', 0)}/100")
            print(f"   Network Score: {details.get('network_score', 0)}/100")
            
            entropy_analysis = details.get('entropy_analysis', {})
            if entropy_analysis.get('entropy', 0) > 0:
                print(f"   Entropy: {entropy_analysis['entropy']:.2f}")
            
            string_analysis = details.get('string_analysis', {})
            if string_analysis.get('strings'):
                print(f"   Extracted Strings: {len(string_analysis['strings'])}")
            
            format_analysis = details.get('format_analysis', {})
            if format_analysis.get('format') != 'Unknown':
                print(f"   File Format: {format_analysis['format']}")
        
        if result['indicators']:
            print(f"\n{self.colors.YELLOW}⚠️  Suspicious Indicators:{self.colors.RESET}")
            for indicator in result['indicators']:
                print(f"   • {indicator}")
        else:
            print(f"\n{self.colors.GREEN}✅ No suspicious indicators found{self.colors.RESET}")
        
        return result
