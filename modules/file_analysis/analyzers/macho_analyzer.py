import os
import re
import hashlib
import subprocess
import struct
from ...colors import Colors

class MachoAnalyzer:
    def __init__(self):
        self.colors = Colors()
        
        # Mach-O magic numbers
        self.macho_magics = {
            0xfeedface: 'Mach-O 32-bit',
            0xfeedfacf: 'Mach-O 64-bit',
            0xcafebabe: 'Universal Binary',
            0xcffaedfe: 'Mach-O 32-bit (reverse)',
            0xcefaedfe: 'Mach-O 64-bit (reverse)'
        }
        
        # Metasploit patterns for macOS payloads
        self.metasploit_patterns = [
            r'osx/x86/shell_reverse_tcp',
            r'osx/x64/shell_reverse_tcp',
            r'osx/x86/meterpreter/reverse_tcp',
            r'osx/x64/meterpreter/reverse_tcp',
            r'meterpreter',
            r'reverse_tcp',
            r'bind_tcp',
            r'payload',
            r'shell',
            r'msfvenom'
        ]
        
        # High-confidence macOS payload patterns
        self.high_confidence_patterns = [
            r'execve\s*\(',
            r'system\s*\(',
            r'popen\s*\(',
            r'fork\s*\(',
            r'socket\s*\(',
            r'connect\s*\(',
            r'bind\s*\(',
            r'listen\s*\(',
            r'accept\s*\(',
            r'send\s*\(',
            r'recv\s*\(',
            r'dlopen\s*\(',
            r'dlsym\s*\(',
            r'mmap\s*\(',
            r'mprotect\s*\(',
            r'__attribute__\s*\(\s*\(constructor\)\s*\)',
            r'__attribute__\s*\(\s*\(destructor\)\s*\)'
        ]
        
        # Suspicious macOS syscalls and functions
        self.macos_suspicious_patterns = [
            r'_main',
            r'_start',
            r'__dyld_start',
            r'dyld_stub_binder',
            r'libSystem.B.dylib',
            r'libc.dylib',
            r'libdl.dylib',
            r'Foundation.framework',
            r'CoreFoundation.framework',
            r'Security.framework',
            r'SystemConfiguration.framework',
            r'IOKit.framework',
            r'ApplicationServices.framework',
            r'Carbon.framework',
            r'Cocoa.framework',
            r'AppKit.framework',
            r'CoreData.framework',
            r'CoreGraphics.framework',
            r'CoreImage.framework',
            r'CoreLocation.framework',
            r'CoreServices.framework',
            r'CoreText.framework',
            r'CoreVideo.framework',
            r'CoreWLAN.framework',
            r'DiskArbitration.framework',
            r'ImageIO.framework',
            r'OpenGL.framework',
            r'QuartzCore.framework',
            r'WebKit.framework'
        ]

    def analyze(self, file_path):
        """Analyze Mach-O file for payloads"""
        result = {
            'infected': False,
            'confidence': 0,
            'payload_type': 'Unknown',
            'indicators': [],
            'analysis_details': {},
            'file_info': self._get_file_info(file_path)
        }
        
        try:
            with open(file_path, 'rb') as f:
                binary_content = f.read()
            
            # 1. Mach-O header analysis
            header_analysis = self._analyze_macho_header(binary_content)
            result['analysis_details']['header_analysis'] = header_analysis
            
            # 2. High-confidence pattern detection
            high_confidence_score = self._detect_high_confidence_patterns(binary_content)
            result['analysis_details']['high_confidence_score'] = high_confidence_score
            
            # 3. macOS pattern detection
            macos_score = self._detect_macos_patterns(binary_content)
            result['analysis_details']['macos_score'] = macos_score
            
            # 4. Metasploit payload detection
            metasploit_score = self._detect_metasploit_payloads(binary_content)
            result['analysis_details']['metasploit_score'] = metasploit_score
            
            # 5. Binary Metasploit signature detection
            binary_signature_score = self._detect_binary_metasploit_signatures(binary_content)
            result['analysis_details']['binary_signature_score'] = binary_signature_score
            
            # 6. Shellcode detection
            shellcode_score = self._detect_shellcode(binary_content)
            result['analysis_details']['shellcode_score'] = shellcode_score
            
            # Calculate overall confidence
            total_score = (high_confidence_score * 0.25 + 
                          macos_score * 0.15 + 
                          metasploit_score * 0.2 + 
                          binary_signature_score * 0.25 + 
                          shellcode_score * 0.15)
            
            result['confidence'] = min(100, total_score)
            
            # Determine if infected - Lower threshold for Metasploit payloads
            if result['confidence'] >= 5:
                result['infected'] = True
                result['payload_type'] = self._determine_payload_type(binary_content)
            
            # Collect indicators
            result['indicators'] = self._collect_indicators(result['analysis_details'])
            
            return result
            
        except Exception as e:
            result['infected'] = False
            result['confidence'] = 0
            result['payload_type'] = 'Analysis Error'
            result['indicators'].append(f'Analysis failed: {str(e)}')
            result['analysis_details']['error'] = str(e)
            return result

    def _get_file_info(self, file_path):
        """Get basic file information"""
        stat = os.stat(file_path)
        with open(file_path, 'rb') as f:
            content = f.read()
        return {
            'name': os.path.basename(file_path),
            'path': file_path,
            'size': stat.st_size,
            'md5': hashlib.md5(content).hexdigest(),
            'sha256': hashlib.sha256(content).hexdigest(),
            'extension': '.macho'
        }

    def _analyze_macho_header(self, binary_content):
        """Analyze Mach-O header"""
        analysis = {'score': 0, 'indicators': [], 'architecture': 'Unknown', 'type': 'Unknown'}
        
        if len(binary_content) < 4:
            analysis['indicators'].append("File too small for Mach-O header")
            analysis['score'] += 50
            return analysis
        
        # Read magic number
        magic = struct.unpack('<I', binary_content[0:4])[0]
        
        if magic in self.macho_magics:
            analysis['type'] = self.macho_magics[magic]
            analysis['indicators'].append(f"Valid Mach-O file: {analysis['type']}")
        else:
            analysis['indicators'].append(f"Invalid Mach-O magic: 0x{magic:08x}")
            analysis['score'] += 30
        
        return analysis

    def _detect_high_confidence_patterns(self, binary_content):
        """Detect high-confidence macOS payload patterns"""
        score = 0
        found_patterns = []
        content_str = binary_content.decode('utf-8', errors='ignore')
        
        for pattern in self.high_confidence_patterns:
            if re.search(pattern, content_str, re.IGNORECASE):
                found_patterns.append(pattern)
                score += 50
        
        return min(100, score)

    def _detect_macos_patterns(self, binary_content):
        """Detect macOS-specific patterns"""
        score = 0
        found_patterns = []
        content_str = binary_content.decode('utf-8', errors='ignore')
        
        for pattern in self.macos_suspicious_patterns:
            if re.search(pattern, content_str, re.IGNORECASE):
                found_patterns.append(pattern)
                score += 8
        
        return min(100, score)

    def _detect_metasploit_payloads(self, binary_content):
        """Detect Metasploit payload patterns"""
        score = 0
        found_patterns = []
        content_str = binary_content.decode('utf-8', errors='ignore')
        
        for pattern in self.metasploit_patterns:
            if re.search(pattern, content_str, re.IGNORECASE):
                found_patterns.append(pattern)
                score += 35
        
        return min(100, score)

    def _detect_binary_metasploit_signatures(self, binary_content):
        """Detect Metasploit signatures in binary content"""
        score = 0
        found_signatures = []
        
        metasploit_signatures = [
            b'meterpreter',
            b'reverse_tcp',
            b'bind_tcp',
            b'reverse_https',
            b'payload',
            b'shell',
            b'cmd',
            b'bash',
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
            b'libSystem.B.dylib',
            b'libc.dylib',
            b'libdl.dylib'
        ]
        
        for signature in metasploit_signatures:
            if signature in binary_content:
                found_signatures.append(signature.decode('utf-8', errors='ignore'))
                score += 30
        
        return min(100, score)

    def _detect_shellcode(self, binary_content):
        """Detect shellcode patterns in binary content"""
        score = 0
        found_patterns = []
        
        # Common macOS/x86_64 shellcode patterns
        shellcode_patterns = [
            b'\x48\x31\xc0',  # xor rax, rax
            b'\x48\x31\xdb',  # xor rbx, rbx
            b'\x48\x31\xc9',  # xor rcx, rcx
            b'\x48\x31\xd2',  # xor rdx, rdx
            b'\x48\x31\xf6',  # xor rsi, rsi
            b'\x48\x31\xff',  # xor rdi, rdi
            b'\x48\x89\xe5',  # mov rbp, rsp
            b'\x48\x89\xc7',  # mov rdi, rax
            b'\x48\x89\xc6',  # mov rsi, rax
            b'\x48\x89\xc2',  # mov rdx, rax
            b'\x48\x89\xc1',  # mov rcx, rax
            b'\x48\x89\xc3',  # mov rbx, rax
            b'\x0f\x05',      # syscall
            b'\xcd\x80',      # int 0x80
            b'\x90\x90\x90\x90',  # NOP sled
            b'\xcc\xcc\xcc\xcc',  # INT3 breakpoint
            b'\x48\xc7\xc0',  # mov rax, imm32
            b'\x48\xc7\xc7',  # mov rdi, imm32
            b'\x48\xc7\xc6',  # mov rsi, imm32
            b'\x48\xc7\xc2',  # mov rdx, imm32
        ]
        
        for pattern in shellcode_patterns:
            if pattern in binary_content:
                found_patterns.append(pattern.hex())
                score += 25
        
        return min(100, score)

    def _determine_payload_type(self, binary_content):
        """Determine the type of payload"""
        content_str = binary_content.decode('utf-8', errors='ignore').lower()
        
        if 'meterpreter' in content_str:
            if 'reverse_tcp' in content_str:
                return 'Metasploit macOS Reverse TCP Payload'
            elif 'bind_tcp' in content_str:
                return 'Metasploit macOS Bind TCP Payload'
            elif 'reverse_https' in content_str:
                return 'Metasploit macOS Reverse HTTPS Payload'
            else:
                return 'Metasploit macOS Payload'
        
        if 'shell' in content_str:
            return 'macOS Shell Payload'
        
        if 'exec' in content_str:
            return 'macOS Command Execution Payload'
        
        return 'macOS Payload'

    def _collect_indicators(self, analysis_details):
        """Collect all indicators from analysis details"""
        indicators = []
        
        # Header analysis
        header_analysis = analysis_details.get('header_analysis', {})
        if header_analysis.get('score', 0) > 0:
            indicators.append(f"Suspicious Mach-O header (score: {header_analysis['score']})")
        
        # High-confidence patterns
        if analysis_details.get('high_confidence_score', 0) > 0:
            indicators.append(f"High-confidence macOS payload patterns (score: {analysis_details['high_confidence_score']})")
        
        # macOS patterns
        if analysis_details.get('macos_score', 0) > 0:
            indicators.append(f"Suspicious macOS patterns (score: {analysis_details['macos_score']})")
        
        # Metasploit patterns
        if analysis_details.get('metasploit_score', 0) > 0:
            indicators.append(f"Metasploit payload patterns (score: {analysis_details['metasploit_score']})")
        
        # Binary signature analysis
        if analysis_details.get('binary_signature_score', 0) > 0:
            indicators.append(f"Binary Metasploit signatures (score: {analysis_details['binary_signature_score']})")
        
        # Shellcode analysis
        if analysis_details.get('shellcode_score', 0) > 0:
            indicators.append(f"Shellcode patterns (score: {analysis_details['shellcode_score']})")
        
        return indicators

    def display_result(self, result, file_path):
        """Display analysis result"""
        print(f"\n{self.colors.CYAN}🔍 Mach-O Payload Analysis: {os.path.basename(file_path)}{self.colors.RESET}")
        print(f"   Payload Type: {result['payload_type']}")
        
        if result['infected']:
            print(f"{self.colors.RED}🚨 RESULT: INFECTED{self.colors.RESET}")
        else:
            print(f"{self.colors.GREEN}✅ RESULT: CLEAR{self.colors.RESET}")
        
        print(f"   Confidence: {result['confidence']}%")
        
        details = result.get('analysis_details', {})
        if details:
            print(f"\n{self.colors.YELLOW}📊 Analysis Details:{self.colors.RESET}")
            print(f"   File Size: {details.get('file_info', {}).get('size', 0)} bytes")
            
            header_analysis = details.get('header_analysis', {})
            if header_analysis.get('type'):
                print(f"   Mach-O Type: {header_analysis['type']}")
            
            print(f"   High-Confidence Score: {details.get('high_confidence_score', 0)}/100")
            print(f"   macOS Pattern Score: {details.get('macos_score', 0)}/100")
            print(f"   Metasploit Score: {details.get('metasploit_score', 0)}/100")
            
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
