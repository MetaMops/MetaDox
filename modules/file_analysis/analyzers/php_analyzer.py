"""
PHP Analyzer - Comprehensive analysis for PHP web shells and payloads
Professional-grade detection with multiple analysis layers
"""

import os
import re
import hashlib
import base64
import subprocess
from ...colors import Colors

class PhpAnalyzer:
    def __init__(self):
        self.colors = Colors()
        
        # PHP Web Shell Patterns
        self.web_shell_patterns = [
            # Common web shell functions
            r'eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)',
            r'assert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)',
            r'preg_replace\s*\(\s*["\']/e["\']',
            r'create_function\s*\(',
            r'call_user_func\s*\(\s*\$_(?:GET|POST|REQUEST)',
            r'system\s*\(\s*\$_(?:GET|POST|REQUEST)',
            r'exec\s*\(\s*\$_(?:GET|POST|REQUEST)',
            r'shell_exec\s*\(\s*\$_(?:GET|POST|REQUEST)',
            r'passthru\s*\(\s*\$_(?:GET|POST|REQUEST)',
            r'`.*\$_(?:GET|POST|REQUEST).*`',
            
            # Base64 encoded payloads
            r'base64_decode\s*\(\s*["\'][A-Za-z0-9+/=]{20,}["\']',
            r'eval\s*\(\s*base64_decode\s*\(',
            r'gzinflate\s*\(\s*base64_decode',
            r'str_rot13\s*\(\s*base64_decode',
            
            # Obfuscated code patterns
            r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*["\'][^"\']*["\']\s*;\s*eval\s*\(',
            r'chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)',
            r'hex2bin\s*\(\s*["\'][0-9a-fA-F]+["\']',
            
            # File manipulation
            r'file_get_contents\s*\(\s*["\']php://input["\']',
            r'fwrite\s*\(\s*fopen\s*\(',
            r'file_put_contents\s*\(\s*["\'][^"\']*\.php["\']',
            
            # Network functions
            r'fsockopen\s*\(',
            r'socket_create\s*\(',
            r'curl_exec\s*\(',
            r'file_get_contents\s*\(\s*["\']http[s]?://',
            
            # Process execution
            r'proc_open\s*\(',
            r'popen\s*\(',
            r'pcntl_exec\s*\(',
        ]
        
        # Metasploit PHP payload patterns
        self.metasploit_patterns = [
            r'php/meterpreter/reverse_tcp',
            r'php/meterpreter/bind_tcp',
            r'php/shell/reverse_tcp',
            r'php/shell/bind_tcp',
            r'php/download_exec',
            r'php/exec',
            r'php/meterpreter_reverse_tcp',
            r'php/meterpreter_bind_tcp',
            r'meterpreter',
            r'reverse_tcp',
            r'bind_tcp',
            r'payload',
            r'msfvenom',
            r'msfconsole',
        ]
        
        # High-confidence web shell indicators
        self.high_confidence_patterns = [
            r'eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)',
            r'assert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)',
            r'system\s*\(\s*\$_(?:GET|POST|REQUEST)',
            r'exec\s*\(\s*\$_(?:GET|POST|REQUEST)',
            r'shell_exec\s*\(\s*\$_(?:GET|POST|REQUEST)',
            r'passthru\s*\(\s*\$_(?:GET|POST|REQUEST)',
            r'`.*\$_(?:GET|POST|REQUEST).*`',
            r'file_get_contents\s*\(\s*["\']php://input["\']',
            r'preg_replace\s*\(\s*["\']/e["\']',
        ]
        
        # Suspicious function combinations
        self.suspicious_combinations = [
            (r'eval\s*\(', r'base64_decode'),
            (r'assert\s*\(', r'gzinflate'),
            (r'system\s*\(', r'\$_(?:GET|POST)'),
            (r'exec\s*\(', r'file_get_contents'),
            (r'shell_exec\s*\(', r'curl_exec'),
        ]
        
        # Common web shell file names
        self.suspicious_filenames = [
            'shell.php', 'cmd.php', 'backdoor.php', 'webshell.php',
            'admin.php', 'login.php', 'config.php', 'index.php',
            'upload.php', 'filemanager.php', 'c99.php', 'r57.php',
            'b374k.php', 'wso.php', 'indoxploit.php', 'mini.php'
        ]
        
        # Obfuscation techniques
        self.obfuscation_patterns = [
            r'\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*["\'][^"\']*["\']\s*;\s*eval\s*\(',
            r'chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)',
            r'hex2bin\s*\(\s*["\'][0-9a-fA-F]+["\']',
            r'str_rot13\s*\(\s*["\'][^"\']*["\']',
            r'gzinflate\s*\(\s*base64_decode',
            r'gzuncompress\s*\(\s*base64_decode',
        ]

    def analyze(self, file_path):
        """Comprehensive PHP file analysis"""
        try:
            result = {
                'infected': False,
                'confidence': 0,
                'payload_type': 'Unknown',
                'indicators': [],
                'analysis_details': {},
                'file_info': self._get_file_info(file_path)
            }
            
            # Read file content (try binary first for encrypted content)
            with open(file_path, 'rb') as f:
                binary_content = f.read()
            
            # Try to decode as UTF-8, but keep binary for analysis
            try:
                content = binary_content.decode('utf-8')
            except UnicodeDecodeError:
                content = binary_content.decode('utf-8', errors='ignore')
            
            # Analysis layers
            result['analysis_details']['file_size'] = len(content)
            result['analysis_details']['lines_of_code'] = len(content.split('\n'))
            
            # 1. High-Confidence Pattern Detection
            high_confidence_score = self._detect_high_confidence_patterns(content)
            result['analysis_details']['high_confidence_score'] = high_confidence_score
            
            # 2. Web Shell Pattern Detection
            web_shell_score = self._detect_web_shells(content)
            result['analysis_details']['web_shell_score'] = web_shell_score
            
            # 2. Metasploit Payload Detection
            metasploit_score = self._detect_metasploit_payloads(content)
            result['analysis_details']['metasploit_score'] = metasploit_score
            
            # 3. Obfuscation Detection
            obfuscation_score = self._detect_obfuscation(content)
            result['analysis_details']['obfuscation_score'] = obfuscation_score
            
            # 4. Suspicious Function Analysis
            suspicious_functions = self._analyze_suspicious_functions(content)
            result['analysis_details']['suspicious_functions'] = suspicious_functions
            
            # 5. Base64 Content Analysis
            base64_analysis = self._analyze_base64_content(content)
            result['analysis_details']['base64_analysis'] = base64_analysis
            
            # 5.5. Binary Content Analysis
            binary_analysis = self._analyze_binary_content(binary_content)
            result['analysis_details']['binary_analysis'] = binary_analysis
            
            # 6. Network Activity Detection
            network_activity = self._detect_network_activity(content)
            result['analysis_details']['network_activity'] = network_activity
            
            # 7. File System Operations
            file_operations = self._detect_file_operations(content)
            result['analysis_details']['file_operations'] = file_operations
            
            # 8. Process Execution Detection
            process_execution = self._detect_process_execution(content)
            result['analysis_details']['process_execution'] = process_execution
            
            # Calculate overall confidence
            total_score = (high_confidence_score * 0.2 + 
                          web_shell_score * 0.15 + 
                          metasploit_score * 0.15 + 
                          obfuscation_score * 0.1 + 
                          len(suspicious_functions) * 5 + 
                          base64_analysis['score'] * 0.1 + 
                          binary_analysis['score'] * 0.3)  # Increased weight for binary analysis
            
            result['confidence'] = min(100, total_score)
            
            # Determine if infected
            if result['confidence'] >= 1:
                result['infected'] = True
                result['payload_type'] = self._determine_payload_type(content)
            
            # Collect indicators
            result['indicators'] = self._collect_indicators(content, result['analysis_details'])
            
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
                'extension': '.php'
            }
        except Exception as e:
            return {'error': str(e)}

    def _detect_high_confidence_patterns(self, content):
        """Detect high-confidence web shell patterns"""
        score = 0
        for pattern in self.high_confidence_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                score += len(matches) * 50  # High weight for these patterns
        return min(100, score)

    def _detect_web_shells(self, content):
        """Detect web shell patterns"""
        score = 0
        for pattern in self.web_shell_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                score += len(matches) * 10
        return min(100, score)

    def _detect_metasploit_payloads(self, content):
        """Detect Metasploit payload patterns"""
        score = 0
        for pattern in self.metasploit_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                score += 50
        return min(100, score)

    def _detect_obfuscation(self, content):
        """Detect code obfuscation"""
        score = 0
        for pattern in self.obfuscation_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                score += len(matches) * 15
        return min(100, score)

    def _analyze_suspicious_functions(self, content):
        """Analyze suspicious function combinations"""
        suspicious = []
        for func1, func2 in self.suspicious_combinations:
            if re.search(func1, content, re.IGNORECASE) and re.search(func2, content, re.IGNORECASE):
                suspicious.append(f"Combination: {func1} + {func2}")
        return suspicious

    def _analyze_base64_content(self, content):
        """Analyze Base64 encoded content"""
        base64_pattern = r'base64_decode\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\']'
        matches = re.findall(base64_pattern, content, re.IGNORECASE)
        
        analysis = {'count': len(matches), 'score': 0, 'decoded_content': [], 'suspicious_decoded': []}
        
        for match in matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                analysis['decoded_content'].append(decoded[:100])  # First 100 chars
                
                # Check if decoded content contains suspicious patterns
                if any(pattern in decoded.lower() for pattern in ['eval', 'system', 'exec', 'shell', 'payload', 'meterpreter']):
                    analysis['score'] += 30
                    analysis['suspicious_decoded'].append(decoded[:200])
                
                # Check for Metasploit patterns in decoded content
                if any(pattern in decoded.lower() for pattern in ['msfvenom', 'payload', 'reverse_tcp', 'bind_tcp']):
                    analysis['score'] += 50
                    
            except:
                analysis['score'] += 10
        
        return analysis

    def _analyze_binary_content(self, binary_content):
        """Analyze binary/encrypted content for Metasploit payloads"""
        analysis = {'score': 0, 'indicators': []}
        
        # Check for binary content (non-printable characters)
        printable_chars = sum(1 for c in binary_content if 32 <= c <= 126 or c in [9, 10, 13])  # Printable ASCII + tab, newline, carriage return
        total_chars = len(binary_content)
        printable_ratio = printable_chars / total_chars if total_chars > 0 else 0
        
        # If less than 70% printable characters, likely binary/encrypted
        if printable_ratio < 0.7:
            analysis['score'] += 40
            analysis['indicators'].append("Binary/encrypted content detected")
        
        # Check for common Metasploit payload signatures in binary
        metasploit_signatures = [
            b'MZ',  # PE header
            b'This program cannot be run in DOS mode',
            b'meterpreter',
            b'payload',
            b'reverse_tcp',
            b'bind_tcp',
            b'msfvenom',
            b'msfconsole',
        ]
        
        for signature in metasploit_signatures:
            if signature in binary_content:
                analysis['score'] += 30
                analysis['indicators'].append(f"Metasploit signature found: {signature.decode('utf-8', errors='ignore')}")
        
        # Check for HTTP headers (common in web payloads)
        if b'HTTP/' in binary_content:
            analysis['score'] += 20
            analysis['indicators'].append("HTTP headers detected")
        
        # Check for User-Agent strings (common in web payloads)
        if b'User-Agent:' in binary_content:
            analysis['score'] += 15
            analysis['indicators'].append("User-Agent string detected")
        
        # Check for IP addresses (common in payloads)
        import re
        ip_pattern = rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        if re.search(ip_pattern, binary_content):
            analysis['score'] += 10
            analysis['indicators'].append("IP addresses detected")
        
        return analysis

    def _detect_network_activity(self, content):
        """Detect network activity patterns"""
        network_patterns = [
            r'fsockopen\s*\(',
            r'socket_create\s*\(',
            r'curl_exec\s*\(',
            r'file_get_contents\s*\(\s*["\']http[s]?://',
            r'stream_context_create\s*\(',
        ]
        
        activity = {'patterns_found': [], 'score': 0}
        for pattern in network_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                activity['patterns_found'].append(pattern)
                activity['score'] += 20
        
        return activity

    def _detect_file_operations(self, content):
        """Detect suspicious file operations"""
        file_patterns = [
            r'file_put_contents\s*\(\s*["\'][^"\']*\.php["\']',
            r'fwrite\s*\(\s*fopen\s*\(',
            r'move_uploaded_file\s*\(',
            r'copy\s*\(\s*["\'][^"\']*["\']',
            r'unlink\s*\(\s*["\'][^"\']*["\']',
        ]
        
        operations = {'patterns_found': [], 'score': 0}
        for pattern in file_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                operations['patterns_found'].append(pattern)
                operations['score'] += 15
        
        return operations

    def _detect_process_execution(self, content):
        """Detect process execution patterns"""
        exec_patterns = [
            r'system\s*\(',
            r'exec\s*\(',
            r'shell_exec\s*\(',
            r'passthru\s*\(',
            r'proc_open\s*\(',
            r'popen\s*\(',
            r'pcntl_exec\s*\(',
        ]
        
        execution = {'patterns_found': [], 'score': 0}
        for pattern in exec_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                execution['patterns_found'].append(pattern)
                execution['score'] += 25
        
        return execution

    def _determine_payload_type(self, content):
        """Determine the type of payload"""
        if re.search(r'meterpreter', content, re.IGNORECASE):
            return 'Meterpreter Payload'
        elif re.search(r'shell', content, re.IGNORECASE):
            return 'Shell Payload'
        elif re.search(r'backdoor', content, re.IGNORECASE):
            return 'Backdoor'
        elif re.search(r'webshell', content, re.IGNORECASE):
            return 'Web Shell'
        else:
            return 'Suspicious PHP Code'

    def _collect_indicators(self, content, analysis_details):
        """Collect all suspicious indicators"""
        indicators = []
        
        # High confidence indicators
        if analysis_details.get('high_confidence_score', 0) > 0:
            indicators.append(f"High-confidence web shell patterns detected (score: {analysis_details['high_confidence_score']})")
        
        if analysis_details.get('web_shell_score', 0) > 50:
            indicators.append(f"Web shell patterns detected (score: {analysis_details['web_shell_score']})")
        
        if analysis_details.get('metasploit_score', 0) > 0:
            indicators.append(f"Metasploit payload patterns detected (score: {analysis_details['metasploit_score']})")
        
        if analysis_details.get('obfuscation_score', 0) > 30:
            indicators.append(f"Code obfuscation detected (score: {analysis_details['obfuscation_score']})")
        
        # Suspicious functions
        if analysis_details.get('suspicious_functions'):
            indicators.append(f"Suspicious function combinations: {len(analysis_details['suspicious_functions'])}")
        
        # Base64 content
        if analysis_details.get('base64_analysis', {}).get('score', 0) > 0:
            indicators.append(f"Base64 encoded suspicious content: {analysis_details['base64_analysis']['count']} instances")
        
        # Binary content
        if analysis_details.get('binary_analysis', {}).get('score', 0) > 0:
            binary_indicators = analysis_details['binary_analysis'].get('indicators', [])
            for indicator in binary_indicators:
                indicators.append(f"Binary analysis: {indicator}")
        
        # Network activity
        if analysis_details.get('network_activity', {}).get('score', 0) > 0:
            indicators.append(f"Network activity patterns: {len(analysis_details['network_activity']['patterns_found'])}")
        
        # File operations
        if analysis_details.get('file_operations', {}).get('score', 0) > 0:
            indicators.append(f"Suspicious file operations: {len(analysis_details['file_operations']['patterns_found'])}")
        
        # Process execution
        if analysis_details.get('process_execution', {}).get('score', 0) > 0:
            indicators.append(f"Process execution patterns: {len(analysis_details['process_execution']['patterns_found'])}")
        
        return indicators

    def display_result(self, result, file_path):
        """Display analysis result"""
        print(f"\n{self.colors.CYAN}🔍 PHP Payload Analysis: {os.path.basename(file_path)}{self.colors.RESET}")
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
            print(f"   Lines of Code: {details.get('lines_of_code', 0)}")
            print(f"   High-Confidence Score: {details.get('high_confidence_score', 0)}/100")
            print(f"   Web Shell Score: {details.get('web_shell_score', 0)}/100")
            print(f"   Metasploit Score: {details.get('metasploit_score', 0)}/100")
            print(f"   Obfuscation Score: {details.get('obfuscation_score', 0)}/100")
            
            if details.get('base64_analysis', {}).get('count', 0) > 0:
                print(f"   Base64 Instances: {details['base64_analysis']['count']}")
            
            if details.get('binary_analysis', {}).get('score', 0) > 0:
                print(f"   Binary Analysis Score: {details['binary_analysis']['score']}/100")
            
            if details.get('suspicious_functions'):
                print(f"   Suspicious Combinations: {len(details['suspicious_functions'])}")
        
        if result['indicators']:
            print(f"\n{self.colors.YELLOW}⚠️  Suspicious Indicators:{self.colors.RESET}")
            for indicator in result['indicators']:
                print(f"   • {indicator}")
        else:
            print(f"\n{self.colors.GREEN}✅ No suspicious indicators found{self.colors.RESET}")
        
        return result
