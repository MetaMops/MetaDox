"""
ASPX Analyzer - Comprehensive analysis for ASP.NET web shells and .NET payloads
Professional-grade detection with multiple analysis layers
"""

import os
import re
import hashlib
import base64
import subprocess
from ...colors import Colors

class AspxAnalyzer:
    def __init__(self):
        self.colors = Colors()
        
        # ASPX Web Shell Patterns
        self.web_shell_patterns = [
            # Process execution
            r'Process\.Start\s*\(',
            r'new\s+ProcessStartInfo\s*\(',
            r'ProcessStartInfo\s+psi\s*=',
            r'System\.Diagnostics\.Process',
            
            # Request parameter execution
            r'Request\.QueryString\s*\[',
            r'Request\.Form\s*\[',
            r'Request\.Params\s*\[',
            r'Request\.Cookies\s*\[',
            
            # File operations
            r'File\.WriteAllText\s*\(',
            r'File\.ReadAllText\s*\(',
            r'File\.WriteAllBytes\s*\(',
            r'File\.ReadAllBytes\s*\(',
            r'File\.Create\s*\(',
            r'File\.Open\s*\(',
            r'File\.Delete\s*\(',
            r'File\.Copy\s*\(',
            r'File\.Move\s*\(',
            
            # Directory operations
            r'Directory\.CreateDirectory\s*\(',
            r'Directory\.Delete\s*\(',
            r'Directory\.GetFiles\s*\(',
            r'Directory\.GetDirectories\s*\(',
            
            # Network operations
            r'WebRequest\.Create\s*\(',
            r'HttpWebRequest\s*\(',
            r'TcpClient\s*\(',
            r'Socket\s*\(',
            r'UdpClient\s*\(',
            
            # Reflection and assembly loading
            r'Assembly\.Load\s*\(',
            r'Assembly\.LoadFrom\s*\(',
            r'Assembly\.LoadFile\s*\(',
            r'Type\.GetType\s*\(',
            r'Activator\.CreateInstance\s*\(',
            r'MethodInfo\.Invoke\s*\(',
            
            # Base64 and encoding
            r'Convert\.FromBase64String\s*\(',
            r'Convert\.ToBase64String\s*\(',
            r'Encoding\.UTF8\.GetString\s*\(',
            r'Encoding\.ASCII\.GetString\s*\(',
            
            # Obfuscation patterns
            r'new\s+string\s*\(\s*new\s+char\[\]\s*\{[^}]+\}\s*\)',
            r'Convert\.ToChar\s*\(\s*\d+\s*\)',
            r'Convert\.ToInt32\s*\(\s*["\'][^"\']*["\']\s*\)',
        ]
        
        # Metasploit ASPX payload patterns
        self.metasploit_patterns = [
            r'windows/meterpreter/reverse_tcp',
            r'windows/meterpreter/bind_tcp',
            r'windows/shell/reverse_tcp',
            r'windows/shell/bind_tcp',
            r'windows/meterpreter_reverse_tcp',
            r'windows/meterpreter_bind_tcp',
            r'windows/shell_reverse_tcp',
            r'windows/shell_bind_tcp',
            r'meterpreter',
            r'reverse_tcp',
            r'bind_tcp',
            r'payload',
            r'msfvenom',
            r'msfconsole',
        ]
        
        # High-confidence ASPX web shell indicators
        self.high_confidence_patterns = [
            r'Process\.Start\s*\(\s*Request\.',
            r'ProcessStartInfo\s+psi\s*=\s*new\s+ProcessStartInfo',
            r'System\.Diagnostics\.Process',
            r'Request\.QueryString\s*\[',
            r'Request\.Form\s*\[',
            r'Request\.Params\s*\[',
            r'Request\.Cookies\s*\[',
            r'Assembly\.Load\s*\(',
            r'Assembly\.LoadFrom\s*\(',
            r'Type\.GetType\s*\(',
            r'Activator\.CreateInstance\s*\(',
        ]
        
        # Suspicious ASPX directives and controls
        self.suspicious_directives = [
            r'<%@\s+Page\s+[^%]*Language\s*=\s*["\']C#[^%]*%>',
            r'<%@\s+Page\s+[^%]*Language\s*=\s*["\']VB[^%]*%>',
            r'<%@\s+Import\s+Namespace\s*=\s*["\'][^"\']*System\.Diagnostics[^"\']*["\'][^%]*%>',
            r'<%@\s+Import\s+Namespace\s*=\s*["\'][^"\']*System\.IO[^"\']*["\'][^%]*%>',
            r'<%@\s+Import\s+Namespace\s*=\s*["\'][^"\']*System\.Net[^"\']*["\'][^%]*%>',
            r'<%@\s+Import\s+Namespace\s*=\s*["\'][^"\']*System\.Reflection[^"\']*["\'][^%]*%>',
        ]
        
        # Common web shell patterns in ASPX
        self.common_webshell_patterns = [
            r'string\s+cmd\s*=\s*Request\.',
            r'Process\.Start\s*\(\s*cmd\s*\)',
            r'ProcessStartInfo\s+psi\s*=\s*new\s+ProcessStartInfo',
            r'StreamReader\s+reader\s*=\s*new\s+StreamReader',
            r'StringBuilder\s+output\s*=\s*new\s+StringBuilder',
        ]
        
        # Obfuscation techniques
        self.obfuscation_patterns = [
            r'new\s+string\s*\(\s*new\s+char\[\]\s*\{[^}]+\}\s*\)',
            r'Convert\.ToChar\s*\(\s*\d+\s*\)\s*\+',
            r'Convert\.ToInt32\s*\(\s*["\'][^"\']*["\']\s*\)\s*\+',
            r'new\s+string\s*\(\s*Convert\.FromBase64String',
            r'Encoding\.UTF8\.GetString\s*\(\s*Convert\.FromBase64String',
            r'System\.Text\.Encoding\.Default\.GetString',
        ]
        
        # File upload patterns
        self.upload_patterns = [
            r'FileUpload\s+',
            r'PostedFile\s*\.',
            r'HttpPostedFile\s+',
            r'SaveAs\s*\(',
            r'PostedFile\.SaveAs\s*\(',
        ]
        
        # Database connection patterns
        self.database_patterns = [
            r'SqlConnection\s*\(',
            r'OleDbConnection\s*\(',
            r'OdbcConnection\s*\(',
            r'SqlCommand\s*\(',
            r'SqlDataReader\s*\(',
            r'ExecuteReader\s*\(',
            r'ExecuteNonQuery\s*\(',
        ]
        
        # Registry access patterns
        self.registry_patterns = [
            r'Registry\.CurrentUser',
            r'Registry\.LocalMachine',
            r'RegistryKey\s+',
            r'OpenSubKey\s*\(',
            r'SetValue\s*\(',
            r'GetValue\s*\(',
        ]

    def analyze(self, file_path):
        """Comprehensive ASPX file analysis"""
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
            
            # 3. ASPX Directive Analysis
            directive_analysis = self._analyze_directives(content)
            result['analysis_details']['directive_analysis'] = directive_analysis
            
            # 4. Obfuscation Detection
            obfuscation_score = self._detect_obfuscation(content)
            result['analysis_details']['obfuscation_score'] = obfuscation_score
            
            # 5. Process Execution Detection
            process_execution = self._detect_process_execution(content)
            result['analysis_details']['process_execution'] = process_execution
            
            # 6. File Operations Detection
            file_operations = self._detect_file_operations(content)
            result['analysis_details']['file_operations'] = file_operations
            
            # 7. Network Operations Detection
            network_operations = self._detect_network_operations(content)
            result['analysis_details']['network_operations'] = network_operations
            
            # 8. Reflection and Assembly Loading
            reflection_analysis = self._detect_reflection(content)
            result['analysis_details']['reflection_analysis'] = reflection_analysis
            
            # 9. Base64 Content Analysis
            base64_analysis = self._analyze_base64_content(content)
            result['analysis_details']['base64_analysis'] = base64_analysis
            
            # 9.5. Binary Content Analysis
            binary_analysis = self._analyze_binary_content(binary_content)
            result['analysis_details']['binary_analysis'] = binary_analysis
            
            # 10. Upload Functionality Detection
            upload_analysis = self._detect_upload_functionality(content)
            result['analysis_details']['upload_analysis'] = upload_analysis
            
            # 11. Registry Access Detection
            registry_analysis = self._detect_registry_access(content)
            result['analysis_details']['registry_analysis'] = registry_analysis
            
            # Calculate overall confidence
            total_score = (high_confidence_score * 0.3 + 
                          web_shell_score * 0.15 + 
                          metasploit_score * 0.15 + 
                          directive_analysis['score'] * 0.1 + 
                          obfuscation_score * 0.1 + 
                          binary_analysis['score'] * 0.2)  # Increased weight for binary analysis
            
            result['confidence'] = min(100, total_score)
            
            # Determine if infected
            if result['confidence'] >= 5:
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
                'extension': '.aspx'
            }
        except Exception as e:
            return {'error': str(e)}

    def _detect_high_confidence_patterns(self, content):
        """Detect high-confidence ASPX web shell patterns"""
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
                score += len(matches) * 8
        return min(100, score)

    def _detect_metasploit_payloads(self, content):
        """Detect Metasploit payload patterns"""
        score = 0
        for pattern in self.metasploit_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                score += 40
        return min(100, score)

    def _analyze_directives(self, content):
        """Analyze ASPX directives"""
        analysis = {'suspicious_directives': [], 'score': 0}
        
        for pattern in self.suspicious_directives:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                analysis['suspicious_directives'].extend(matches)
                analysis['score'] += len(matches) * 20
        
        return analysis

    def _detect_obfuscation(self, content):
        """Detect code obfuscation"""
        score = 0
        for pattern in self.obfuscation_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                score += len(matches) * 12
        return min(100, score)

    def _detect_process_execution(self, content):
        """Detect process execution patterns"""
        execution_patterns = [
            r'Process\.Start\s*\(',
            r'new\s+ProcessStartInfo\s*\(',
            r'ProcessStartInfo\s+psi\s*=',
            r'System\.Diagnostics\.Process',
        ]
        
        execution = {'patterns_found': [], 'score': 0}
        for pattern in execution_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                execution['patterns_found'].append(pattern)
                execution['score'] += 25
        
        return execution

    def _detect_file_operations(self, content):
        """Detect file operations"""
        file_patterns = [
            r'File\.WriteAllText\s*\(',
            r'File\.ReadAllText\s*\(',
            r'File\.WriteAllBytes\s*\(',
            r'File\.ReadAllBytes\s*\(',
            r'File\.Create\s*\(',
            r'File\.Open\s*\(',
            r'File\.Delete\s*\(',
            r'File\.Copy\s*\(',
            r'File\.Move\s*\(',
            r'Directory\.CreateDirectory\s*\(',
            r'Directory\.Delete\s*\(',
        ]
        
        operations = {'patterns_found': [], 'score': 0}
        for pattern in file_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                operations['patterns_found'].append(pattern)
                operations['score'] += 15
        
        return operations

    def _detect_network_operations(self, content):
        """Detect network operations"""
        network_patterns = [
            r'WebRequest\.Create\s*\(',
            r'HttpWebRequest\s*\(',
            r'TcpClient\s*\(',
            r'Socket\s*\(',
            r'UdpClient\s*\(',
            r'HttpClient\s*\(',
        ]
        
        operations = {'patterns_found': [], 'score': 0}
        for pattern in network_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                operations['patterns_found'].append(pattern)
                operations['score'] += 20
        
        return operations

    def _detect_reflection(self, content):
        """Detect reflection and assembly loading"""
        reflection_patterns = [
            r'Assembly\.Load\s*\(',
            r'Assembly\.LoadFrom\s*\(',
            r'Assembly\.LoadFile\s*\(',
            r'Type\.GetType\s*\(',
            r'Activator\.CreateInstance\s*\(',
            r'MethodInfo\.Invoke\s*\(',
            r'FieldInfo\.SetValue\s*\(',
        ]
        
        reflection = {'patterns_found': [], 'score': 0}
        for pattern in reflection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                reflection['patterns_found'].append(pattern)
                reflection['score'] += 18
        
        return reflection

    def _analyze_base64_content(self, content):
        """Analyze Base64 encoded content"""
        base64_pattern = r'Convert\.FromBase64String\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\']'
        matches = re.findall(base64_pattern, content, re.IGNORECASE)
        
        analysis = {'count': len(matches), 'score': 0, 'decoded_content': []}
        
        for match in matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                analysis['decoded_content'].append(decoded[:100])  # First 100 chars
                
                # Check if decoded content contains suspicious patterns
                if any(pattern in decoded.lower() for pattern in ['process', 'system', 'exec', 'shell']):
                    analysis['score'] += 30
            except:
                analysis['score'] += 10
        
        return analysis

    def _analyze_binary_content(self, binary_content):
        """Analyze binary/encrypted content for ASPX payloads"""
        analysis = {'score': 0, 'indicators': []}
        
        # Check for binary content (non-printable characters)
        printable_chars = sum(1 for c in binary_content if 32 <= c <= 126 or c in [9, 10, 13])  # Printable ASCII + tab, newline, carriage return
        total_chars = len(binary_content)
        printable_ratio = printable_chars / total_chars if total_chars > 0 else 0
        
        # If less than 70% printable characters, likely binary/encrypted
        if printable_ratio < 0.7:
            analysis['score'] += 40
            analysis['indicators'].append("Binary/encrypted content detected")
        
        # Check for common ASPX web shell signatures in binary
        aspx_signatures = [
            b'Process.Start',
            b'Request.QueryString',
            b'Request.Form',
            b'Assembly.Load',
            b'Convert.FromBase64String',
            b'System.Diagnostics.Process',
            b'ProcessStartInfo',
            b'meterpreter',
            b'payload',
            b'reverse_tcp',
            b'bind_tcp',
            b'msfvenom',
            b'msfconsole',
        ]
        
        for signature in aspx_signatures:
            if signature in binary_content:
                analysis['score'] += 30
                analysis['indicators'].append(f"ASPX web shell signature found: {signature.decode('utf-8', errors='ignore')}")
        
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
        
        # Check for .NET assembly signatures
        if b'System.' in binary_content:
            analysis['score'] += 15
            analysis['indicators'].append(".NET System namespace detected")
        
        return analysis

    def _detect_upload_functionality(self, content):
        """Detect file upload functionality"""
        upload = {'patterns_found': [], 'score': 0}
        for pattern in self.upload_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                upload['patterns_found'].append(pattern)
                upload['score'] += 20
        
        return upload

    def _detect_registry_access(self, content):
        """Detect registry access patterns"""
        registry = {'patterns_found': [], 'score': 0}
        for pattern in self.registry_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                registry['patterns_found'].append(pattern)
                registry['score'] += 15
        
        return registry

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
        elif re.search(r'upload', content, re.IGNORECASE):
            return 'File Upload Shell'
        else:
            return 'Suspicious ASPX Code'

    def _collect_indicators(self, content, analysis_details):
        """Collect all suspicious indicators"""
        indicators = []
        
        # High confidence indicators
        if analysis_details.get('high_confidence_score', 0) > 0:
            indicators.append(f"High-confidence ASPX web shell patterns detected (score: {analysis_details['high_confidence_score']})")
        
        if analysis_details.get('web_shell_score', 0) > 50:
            indicators.append(f"Web shell patterns detected (score: {analysis_details['web_shell_score']})")
        
        if analysis_details.get('metasploit_score', 0) > 0:
            indicators.append(f"Metasploit payload patterns detected (score: {analysis_details['metasploit_score']})")
        
        if analysis_details.get('directive_analysis', {}).get('score', 0) > 0:
            indicators.append(f"Suspicious ASPX directives: {len(analysis_details['directive_analysis']['suspicious_directives'])}")
        
        if analysis_details.get('obfuscation_score', 0) > 30:
            indicators.append(f"Code obfuscation detected (score: {analysis_details['obfuscation_score']})")
        
        # Process execution
        if analysis_details.get('process_execution', {}).get('score', 0) > 0:
            indicators.append(f"Process execution patterns: {len(analysis_details['process_execution']['patterns_found'])}")
        
        # File operations
        if analysis_details.get('file_operations', {}).get('score', 0) > 0:
            indicators.append(f"File operations: {len(analysis_details['file_operations']['patterns_found'])}")
        
        # Network operations
        if analysis_details.get('network_operations', {}).get('score', 0) > 0:
            indicators.append(f"Network operations: {len(analysis_details['network_operations']['patterns_found'])}")
        
        # Reflection
        if analysis_details.get('reflection_analysis', {}).get('score', 0) > 0:
            indicators.append(f"Reflection/Assembly loading: {len(analysis_details['reflection_analysis']['patterns_found'])}")
        
        # Base64 content
        if analysis_details.get('base64_analysis', {}).get('score', 0) > 0:
            indicators.append(f"Base64 encoded content: {analysis_details['base64_analysis']['count']} instances")
        
        # Binary content
        if analysis_details.get('binary_analysis', {}).get('score', 0) > 0:
            binary_indicators = analysis_details['binary_analysis'].get('indicators', [])
            for indicator in binary_indicators:
                indicators.append(f"Binary analysis: {indicator}")
        
        # Upload functionality
        if analysis_details.get('upload_analysis', {}).get('score', 0) > 0:
            indicators.append(f"File upload functionality detected")
        
        # Registry access
        if analysis_details.get('registry_analysis', {}).get('score', 0) > 0:
            indicators.append(f"Registry access patterns: {len(analysis_details['registry_analysis']['patterns_found'])}")
        
        return indicators

    def display_result(self, result, file_path):
        """Display analysis result"""
        print(f"\n{self.colors.CYAN}🔍 ASPX Payload Analysis: {os.path.basename(file_path)}{self.colors.RESET}")
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
            print(f"   Directive Score: {details.get('directive_analysis', {}).get('score', 0)}/100")
            
            if details.get('base64_analysis', {}).get('count', 0) > 0:
                print(f"   Base64 Instances: {details['base64_analysis']['count']}")
            
            if details.get('binary_analysis', {}).get('score', 0) > 0:
                print(f"   Binary Analysis Score: {details['binary_analysis']['score']}/100")
            
            if details.get('process_execution', {}).get('patterns_found'):
                print(f"   Process Execution: {len(details['process_execution']['patterns_found'])} patterns")
            
            if details.get('upload_analysis', {}).get('score', 0) > 0:
                print(f"   Upload Functionality: Detected")
            
            if details.get('registry_analysis', {}).get('score', 0) > 0:
                print(f"   Registry Access: {len(details['registry_analysis']['patterns_found'])} patterns")
        
        if result['indicators']:
            print(f"\n{self.colors.YELLOW}⚠️  Suspicious Indicators:{self.colors.RESET}")
            for indicator in result['indicators']:
                print(f"   • {indicator}")
        else:
            print(f"\n{self.colors.GREEN}✅ No suspicious indicators found{self.colors.RESET}")
        
        return result
