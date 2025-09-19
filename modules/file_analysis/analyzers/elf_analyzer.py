"""
ELF Analyzer - Comprehensive analysis for Linux ELF payloads
Professional-grade detection with multiple analysis layers
"""

import os
import re
import hashlib
import subprocess
import struct
from ...colors import Colors

class ElfAnalyzer:
    def __init__(self):
        self.colors = Colors()
        
        # ELF-specific suspicious patterns
        self.elf_suspicious_patterns = [
            # System calls
            r'syscall',
            r'int\s+0x80',
            r'sysenter',
            r'sysexit',
            r'call\s+gs:0x10',
            
            # Process execution
            r'execve',
            r'fork',
            r'vfork',
            r'clone',
            r'waitpid',
            r'exit',
            r'_exit',
            
            # Network operations
            r'socket',
            r'connect',
            r'bind',
            r'listen',
            r'accept',
            r'send',
            r'recv',
            r'sendto',
            r'recvfrom',
            r'setsockopt',
            r'getsockopt',
            
            # File operations
            r'open',
            r'read',
            r'write',
            r'close',
            r'lseek',
            r'stat',
            r'fstat',
            r'lstat',
            r'chmod',
            r'chown',
            r'unlink',
            r'rmdir',
            r'mkdir',
            r'rename',
            r'link',
            r'symlink',
            r'readlink',
            
            # Memory operations
            r'mmap',
            r'munmap',
            r'mprotect',
            r'brk',
            r'sbrk',
            r'mlock',
            r'munlock',
            r'mlockall',
            r'munlockall',
            
            # Signal handling
            r'signal',
            r'sigaction',
            r'sigprocmask',
            r'kill',
            r'killpg',
            r'raise',
            
            # Thread operations
            r'pthread_create',
            r'pthread_join',
            r'pthread_exit',
            r'pthread_cancel',
            r'pthread_mutex_init',
            r'pthread_mutex_lock',
            r'pthread_mutex_unlock',
            r'pthread_cond_init',
            r'pthread_cond_wait',
            r'pthread_cond_signal',
        ]
        
        # Metasploit Linux payload patterns
        self.metasploit_patterns = [
            r'linux/x86/meterpreter/reverse_tcp',
            r'linux/x86/meterpreter/bind_tcp',
            r'linux/x86/shell/reverse_tcp',
            r'linux/x86/shell/bind_tcp',
            r'linux/x64/meterpreter/reverse_tcp',
            r'linux/x64/meterpreter/bind_tcp',
            r'linux/x64/shell/reverse_tcp',
            r'linux/x64/shell/bind_tcp',
            r'meterpreter',
            r'reverse_tcp',
            r'bind_tcp',
            r'payload',
            r'msfvenom',
            r'msfconsole',
        ]
        
        # High-confidence ELF payload indicators
        self.high_confidence_patterns = [
            r'execve\s*\(\s*["\']/bin/sh["\']',
            r'socket\s*\(\s*AF_INET',
            r'connect\s*\(\s*[^,]+,\s*&addr',
            r'fork\s*\(\s*\)',
            r'waitpid\s*\(\s*pid',
            r'mmap\s*\(\s*NULL',
            r'mprotect\s*\(\s*[^,]+,\s*PROT_EXEC',
            r'syscall\s*\(\s*SYS_execve',
        ]
        
        # Suspicious ELF sections
        self.suspicious_sections = [
            '.text',
            '.data',
            '.rodata',
            '.bss',
            '.plt',
            '.got',
            '.got.plt',
            '.init',
            '.fini',
            '.ctors',
            '.dtors',
            '.jcr',
            '.dynamic',
            '.dynsym',
            '.dynstr',
            '.rel.plt',
            '.rel.dyn',
            '.eh_frame',
            '.eh_frame_hdr',
            '.gcc_except_table',
            '.comment',
            '.debug_info',
            '.debug_line',
            '.debug_str',
            '.debug_abbrev',
            '.debug_ranges',
            '.debug_loc',
            '.debug_macinfo',
            '.debug_pubnames',
            '.debug_pubtypes',
        ]
        
        # Suspicious ELF symbols
        self.suspicious_symbols = [
            'main',
            '_start',
            '__libc_start_main',
            'execve',
            'fork',
            'socket',
            'connect',
            'bind',
            'listen',
            'accept',
            'send',
            'recv',
            'mmap',
            'mprotect',
            'syscall',
            'signal',
            'kill',
            'pthread_create',
            'dlopen',
            'dlsym',
            'dlclose',
        ]

    def analyze(self, file_path):
        """Comprehensive ELF file analysis"""
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
            
            # 1. ELF Header Analysis
            elf_header_analysis = self._analyze_elf_header(binary_content)
            result['analysis_details']['elf_header_analysis'] = elf_header_analysis
            
            # 2. High-Confidence Pattern Detection
            high_confidence_score = self._detect_high_confidence_patterns(binary_content)
            result['analysis_details']['high_confidence_score'] = high_confidence_score
            
            # 3. ELF Suspicious Pattern Detection
            elf_score = self._detect_elf_patterns(binary_content)
            result['analysis_details']['elf_score'] = elf_score
            
            # 4. Metasploit Payload Detection
            metasploit_score = self._detect_metasploit_payloads(binary_content)
            result['analysis_details']['metasploit_score'] = metasploit_score
            
            # 5. Section Analysis
            section_analysis = self._analyze_sections(binary_content)
            result['analysis_details']['section_analysis'] = section_analysis
            
            # 6. Symbol Analysis
            symbol_analysis = self._analyze_symbols(binary_content)
            result['analysis_details']['symbol_analysis'] = symbol_analysis
            
            # 7. String Analysis
            string_analysis = self._analyze_strings(binary_content)
            result['analysis_details']['string_analysis'] = string_analysis
            
            # 8. Entropy Analysis
            entropy_analysis = self._analyze_entropy(binary_content)
            result['analysis_details']['entropy_analysis'] = entropy_analysis
            
            # 9. Binary Metasploit Signature Detection
            binary_signature_score = self._detect_binary_metasploit_signatures(binary_content)
            result['analysis_details']['binary_signature_score'] = binary_signature_score
            
            # 10. Shellcode Detection
            shellcode_score = self._detect_shellcode(binary_content)
            result['analysis_details']['shellcode_score'] = shellcode_score
            
            # Calculate overall confidence
            total_score = (high_confidence_score * 0.2 + 
                          elf_score * 0.1 + 
                          metasploit_score * 0.1 + 
                          binary_signature_score * 0.2 +  # High weight for binary signatures
                          shellcode_score * 0.3 +  # Highest weight for shellcode
                          section_analysis['score'] * 0.05 + 
                          symbol_analysis['score'] * 0.05)
            
            result['confidence'] = min(100, total_score)
            
            # Determine if infected - Lower threshold for Metasploit payloads
            if result['confidence'] >= 5:
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
                'extension': '.elf'
            }
        except Exception as e:
            return {'error': str(e)}

    def _analyze_elf_header(self, binary_content):
        """Analyze ELF header"""
        analysis = {'valid_elf': False, 'architecture': 'Unknown', 'score': 0}
        
        try:
            if len(binary_content) < 16:
                return analysis
            
            # Check ELF magic number
            if binary_content[:4] == b'\x7fELF':
                analysis['valid_elf'] = True
                analysis['score'] = 10
                
                # Check architecture
                if binary_content[4] == 1:  # 32-bit
                    analysis['architecture'] = 'x86'
                elif binary_content[4] == 2:  # 64-bit
                    analysis['architecture'] = 'x64'
                
                # Check endianness
                if binary_content[5] == 1:  # Little endian
                    analysis['endianness'] = 'Little'
                elif binary_content[5] == 2:  # Big endian
                    analysis['endianness'] = 'Big'
                
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis

    def _detect_high_confidence_patterns(self, binary_content):
        """Detect high-confidence ELF payload patterns"""
        score = 0
        found_patterns = []
        
        # Convert binary content to string for regex search
        content_str = binary_content.decode('utf-8', errors='ignore')
        
        for pattern in self.high_confidence_patterns:
            if re.search(pattern, content_str, re.IGNORECASE):
                found_patterns.append(pattern)
                score += 50  # High weight for these patterns
        
        return min(100, score)

    def _detect_elf_patterns(self, binary_content):
        """Detect ELF-specific suspicious patterns"""
        score = 0
        found_patterns = []
        
        # Convert binary content to string for regex search
        content_str = binary_content.decode('utf-8', errors='ignore')
        
        for pattern in self.elf_suspicious_patterns:
            if re.search(pattern, content_str, re.IGNORECASE):
                found_patterns.append(pattern)
                score += 8
        
        return min(100, score)

    def _detect_metasploit_payloads(self, binary_content):
        """Detect Metasploit payload patterns"""
        score = 0
        found_patterns = []
        
        # Convert binary content to string for regex search
        content_str = binary_content.decode('utf-8', errors='ignore')
        
        for pattern in self.metasploit_patterns:
            if re.search(pattern, content_str, re.IGNORECASE):
                found_patterns.append(pattern)
                score += 35
        
        return min(100, score)

    def _analyze_sections(self, binary_content):
        """Analyze ELF sections"""
        analysis = {'sections': [], 'score': 0}
        
        try:
            # Use objdump to analyze sections
            result = subprocess.run(['objdump', '-h', '/dev/stdin'], 
                                  input=binary_content, 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Extract section names
                for line in output.split('\n'):
                    if line.strip() and not line.startswith('Idx'):
                        parts = line.split()
                        if len(parts) > 1:
                            section_name = parts[1]
                            if section_name in self.suspicious_sections:
                                analysis['sections'].append(section_name)
                                analysis['score'] += 5
                
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis

    def _analyze_symbols(self, binary_content):
        """Analyze ELF symbols"""
        analysis = {'symbols': [], 'score': 0}
        
        try:
            # Use objdump to analyze symbols
            result = subprocess.run(['objdump', '-T', '/dev/stdin'], 
                                  input=binary_content, 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Extract symbol names
                for line in output.split('\n'):
                    if line.strip() and not line.startswith('DYNAMIC'):
                        parts = line.split()
                        if len(parts) > 6:
                            symbol_name = parts[6]
                            if symbol_name in self.suspicious_symbols:
                                analysis['symbols'].append(symbol_name)
                                analysis['score'] += 10
                
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis

    def _analyze_strings(self, binary_content):
        """Analyze strings in ELF binary"""
        analysis = {'strings': [], 'score': 0}
        
        try:
            # Use strings command to extract strings
            result = subprocess.run(['strings', '/dev/stdin'], 
                                  input=binary_content, 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                strings = result.stdout.split('\n')
                analysis['strings'] = strings
                
                # Check for suspicious strings
                suspicious_strings = [
                    'meterpreter', 'reverse_tcp', 'bind_tcp', 'payload',
                    'shell', 'cmd', 'bash', 'sh', 'execve',
                    'socket', 'connect', 'bind', 'listen', 'accept',
                    'fork', 'waitpid', 'mmap', 'mprotect', 'syscall',
                    '/bin/sh', '/bin/bash', '/usr/bin/python', '/usr/bin/perl',
                    'libc.so', 'libpthread.so', 'ld-linux.so',
                ]
                
                found_suspicious = 0
                for string in strings:
                    for suspicious in suspicious_strings:
                        if suspicious.lower() in string.lower():
                            found_suspicious += 1
                            break
                
                if found_suspicious > 0:
                    analysis['score'] = min(found_suspicious * 8, 40)
                
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis

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
            analysis['score'] = 25
        elif entropy > 7.0:
            analysis['score'] = 15
        elif entropy > 6.5:
            analysis['score'] = 10
        
        return analysis

    def _detect_binary_metasploit_signatures(self, binary_content):
        """Detect Metasploit signatures in binary content"""
        score = 0
        found_signatures = []
        
        # Metasploit-specific binary signatures
        metasploit_signatures = [
            b'meterpreter',
            b'reverse_tcp',
            b'bind_tcp',
            b'reverse_https',
            b'reverse_http',
            b'payload',
            b'shell',
            b'cmd',
            b'bash',
            b'/bin/sh',
            b'/bin/bash',
            b'execve',
            b'socket',
            b'connect',
            b'bind',
            b'listen',
            b'accept',
            b'send',
            b'recv',
            b'fork',
            b'waitpid',
            b'mmap',
            b'mprotect',
            b'syscall',
            b'int 0x80',
            b'sysenter',
            b'libc.so',
            b'libpthread.so',
            b'ld-linux.so',
        ]
        
        for signature in metasploit_signatures:
            if signature in binary_content:
                found_signatures.append(signature.decode('utf-8', errors='ignore'))
                score += 30  # High weight for binary signatures
        
        return min(100, score)

    def _detect_shellcode(self, binary_content):
        """Detect shellcode patterns in binary content"""
        score = 0
        found_patterns = []
        
        # Common shellcode patterns
        shellcode_patterns = [
            b'\x6a\x0a',  # push 10
            b'\x5e',      # pop esi
            b'\x31\xdb',  # xor ebx, ebx
            b'\xf7\xe3',  # mul ebx
            b'\x53',      # push ebx
            b'\x43\x53',  # push ebx; push ebx
            b'\x6a\x02',  # push 2
            b'\xb0\x66',  # mov al, 0x66
            b'\x89\xe1',  # mov ecx, esp
            b'\xcd\x80',  # int 0x80
            b'\x97',      # xchg eax, edi
            b'\x5b',      # pop ebx
            b'\x68',      # push (IP address)
            b'\x6a\x66',  # push 0x66
            b'\x58',      # pop eax
            b'\x50',      # push eax
            b'\x51',      # push ecx
            b'\x57',      # push edi
            b'\x89\xe1',  # mov ecx, esp
            b'\x43',      # inc ebx
            b'\x85\xc0',  # test eax, eax
            b'\x79',      # jns
            b'\x4e',      # dec esi
            b'\x74',      # je
            b'\x68',      # push
            b'\x58',      # pop eax
            b'\x6a\x00',  # push 0
            b'\x6a\x05',  # push 5
            b'\x89\xe3',  # mov ebx, esp
            b'\x31\xc9',  # xor ecx, ecx
            b'\xb2\x07',  # mov dl, 7
            b'\xb9',      # mov ecx, (large value)
            b'\xc1\xeb\x0c',  # shr ebx, 12
            b'\xc1\xe3\x0c',  # shl ebx, 12
            b'\xb0\x7d',  # mov al, 0x7d
            b'\x78',      # js
            b'\x5b',      # pop ebx
            b'\x99',      # cdq
            b'\xb2\x6a',  # mov dl, 0x6a
            b'\xb0\x03',  # mov al, 3
            b'\xff\xe1',  # jmp ecx
            b'\xb8\x01\x00\x00\x00',  # mov eax, 1
            b'\xbb\x01\x00\x00\x00',  # mov ebx, 1
        ]
        
        for pattern in shellcode_patterns:
            if pattern in binary_content:
                found_patterns.append(pattern.hex())
                score += 20  # High weight for shellcode patterns
        
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
            return 'ELF Payload'

    def _collect_indicators(self, analysis_details):
        """Collect all suspicious indicators"""
        indicators = []
        
        # High confidence indicators
        if analysis_details.get('high_confidence_score', 0) > 0:
            indicators.append(f"High-confidence ELF payload patterns detected (score: {analysis_details['high_confidence_score']})")
        
        if analysis_details.get('elf_score', 0) > 40:
            indicators.append(f"ELF suspicious patterns detected (score: {analysis_details['elf_score']})")
        
        if analysis_details.get('metasploit_score', 0) > 0:
            indicators.append(f"Metasploit payload patterns detected (score: {analysis_details['metasploit_score']})")
        
        # ELF header analysis
        elf_header_analysis = analysis_details.get('elf_header_analysis', {})
        if elf_header_analysis.get('valid_elf'):
            indicators.append(f"Valid ELF file ({elf_header_analysis.get('architecture', 'Unknown')})")
        
        # Section analysis
        section_analysis = analysis_details.get('section_analysis', {})
        if section_analysis.get('sections'):
            indicators.append(f"Suspicious ELF sections: {len(section_analysis['sections'])}")
        
        # Symbol analysis
        symbol_analysis = analysis_details.get('symbol_analysis', {})
        if symbol_analysis.get('symbols'):
            indicators.append(f"Suspicious ELF symbols: {len(symbol_analysis['symbols'])}")
        
        # String analysis
        string_analysis = analysis_details.get('string_analysis', {})
        if string_analysis.get('score', 0) > 0:
            indicators.append(f"Suspicious strings detected (score: {string_analysis['score']})")
        
        # Entropy analysis
        entropy_analysis = analysis_details.get('entropy_analysis', {})
        if entropy_analysis.get('score', 0) > 0:
            indicators.append(f"High entropy detected ({entropy_analysis['entropy']:.2f}) - possible encryption/packing")
        
        # Binary signature analysis
        if analysis_details.get('binary_signature_score', 0) > 0:
            indicators.append(f"Binary Metasploit signatures detected (score: {analysis_details['binary_signature_score']})")
        
        # Shellcode analysis
        if analysis_details.get('shellcode_score', 0) > 0:
            indicators.append(f"Shellcode patterns detected (score: {analysis_details['shellcode_score']})")
        
        return indicators

    def display_result(self, result, file_path):
        """Display analysis result"""
        print(f"\n{self.colors.CYAN}🔍 ELF Payload Analysis: {os.path.basename(file_path)}{self.colors.RESET}")
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
            print(f"   ELF Score: {details.get('elf_score', 0)}/100")
            print(f"   Metasploit Score: {details.get('metasploit_score', 0)}/100")
            
            elf_header_analysis = details.get('elf_header_analysis', {})
            if elf_header_analysis.get('valid_elf'):
                print(f"   Architecture: {elf_header_analysis.get('architecture', 'Unknown')}")
                print(f"   Endianness: {elf_header_analysis.get('endianness', 'Unknown')}")
            
            section_analysis = details.get('section_analysis', {})
            if section_analysis.get('sections'):
                print(f"   Suspicious Sections: {len(section_analysis['sections'])}")
            
            symbol_analysis = details.get('symbol_analysis', {})
            if symbol_analysis.get('symbols'):
                print(f"   Suspicious Symbols: {len(symbol_analysis['symbols'])}")
            
            string_analysis = details.get('string_analysis', {})
            if string_analysis.get('strings'):
                print(f"   Extracted Strings: {len(string_analysis['strings'])}")
            
            entropy_analysis = details.get('entropy_analysis', {})
            if entropy_analysis.get('entropy', 0) > 0:
                print(f"   Entropy: {entropy_analysis['entropy']:.2f}")
            
            if details.get('binary_signature_score', 0) > 0:
                print(f"   Binary Signature Score: {details['binary_signature_score']}/100")
            
            if details.get('shellcode_score', 0) > 0:
                print(f"   Shellcode Score: {details['shellcode_score']}/100")
        
        if result['indicators']:
            print(f"\n{self.colors.YELLOW}⚠️  Suspicious Indicators:{self.colors.RESET}")
            for indicator in result['indicators']:
                print(f"   • {indicator}")
        else:
            print(f"\n{self.colors.GREEN}✅ No suspicious indicators found{self.colors.RESET}")
        
        return result
