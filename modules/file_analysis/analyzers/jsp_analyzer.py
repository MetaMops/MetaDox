"""
JSP Analyzer - Comprehensive analysis for JSP web shells and Java payloads
Professional-grade detection with multiple analysis layers
"""

import os
import re
import hashlib
import base64
import subprocess
from ...colors import Colors

class JspAnalyzer:
    def __init__(self):
        self.colors = Colors()
        
        # JSP Web Shell Patterns
        self.web_shell_patterns = [
            # Runtime execution
            r'Runtime\.getRuntime\(\)\.exec\s*\(',
            r'ProcessBuilder\s*\(',
            r'Process\s+process\s*=',
            
            # Scriptlet execution
            r'<%[^%]*Runtime[^%]*%>',
            r'<%[^%]*exec[^%]*%>',
            r'<%[^%]*ProcessBuilder[^%]*%>',
            
            # Request parameter execution
            r'request\.getParameter\s*\(\s*["\'][^"\']*["\']\s*\)',
            r'request\.getParameterValues\s*\(',
            r'request\.getQueryString\s*\(',
            
            # File operations
            r'new\s+File\s*\(',
            r'FileInputStream\s*\(',
            r'FileOutputStream\s*\(',
            r'FileWriter\s*\(',
            r'FileReader\s*\(',
            
            # Network operations
            r'Socket\s*\(',
            r'ServerSocket\s*\(',
            r'URLConnection\s*\(',
            r'HttpURLConnection\s*\(',
            
            # Reflection and class loading
            r'Class\.forName\s*\(',
            r'ClassLoader\s*\(',
            r'URLClassLoader\s*\(',
            r'Method\.invoke\s*\(',
            
            # Base64 and encoding
            r'Base64\.getDecoder\(\)\.decode\s*\(',
            r'Base64\.getEncoder\(\)\.encode\s*\(',
            r'new\s+String\s*\(\s*Base64\.getDecoder',
            
            # Obfuscation patterns
            r'new\s+String\s*\(\s*new\s+byte\[\]\s*\{[^}]+\}\s*\)',
            r'Character\.toString\s*\(\s*\d+\s*\)',
            r'Integer\.toString\s*\(\s*\d+\s*\)',
        ]
        
        # Metasploit JSP payload patterns
        self.metasploit_patterns = [
            r'java/meterpreter/reverse_tcp',
            r'java/meterpreter/bind_tcp',
            r'java/shell/reverse_tcp',
            r'java/shell/bind_tcp',
            r'java/meterpreter_reverse_tcp',
            r'java/meterpreter_bind_tcp',
            r'java/shell_reverse_tcp',
            r'java/shell_bind_tcp',
        ]
        
        # Suspicious JSP tags and directives
        self.suspicious_jsp_tags = [
            r'<%@\s*page\s+[^%]*import\s*=\s*["\'][^"\']*Runtime[^"\']*["\'][^%]*%>',
            r'<%@\s*page\s+[^%]*import\s*=\s*["\'][^"\']*Process[^"\']*["\'][^%]*%>',
            r'<%@\s*page\s+[^%]*import\s*=\s*["\'][^"\']*Socket[^"\']*["\'][^%]*%>',
            r'<%@\s*page\s+[^%]*import\s*=\s*["\'][^"\']*File[^"\']*["\'][^%]*%>',
            r'<%@\s*page\s+[^%]*import\s*=\s*["\'][^"\']*Class[^"\']*["\'][^%]*%>',
        ]
        
        # Common web shell patterns in JSP
        self.common_webshell_patterns = [
            r'String\s+cmd\s*=\s*request\.getParameter',
            r'Runtime\.getRuntime\(\)\.exec\s*\(\s*cmd\s*\)',
            r'Process\s+proc\s*=\s*Runtime\.getRuntime\(\)\.exec',
            r'BufferedReader\s+reader\s*=\s*new\s+BufferedReader',
            r'StringBuilder\s+output\s*=\s*new\s+StringBuilder',
        ]
        
        # Obfuscation techniques
        self.obfuscation_patterns = [
            r'new\s+String\s*\(\s*new\s+byte\[\]\s*\{[^}]+\}\s*\)',
            r'Character\.toString\s*\(\s*\d+\s*\)\s*\+',
            r'Integer\.toString\s*\(\s*\d+\s*\)\s*\+',
            r'Long\.toString\s*\(\s*\d+\s*\)\s*\+',
            r'new\s+String\s*\(\s*Base64\.getDecoder\(\)\.decode',
            r'URLDecoder\.decode\s*\(',
            r'URLEncoder\.encode\s*\(',
        ]
        
        # File upload patterns
        self.upload_patterns = [
            r'Part\s+filePart\s*=\s*request\.getPart',
            r'MultipartRequest\s*\(',
            r'CommonsMultipartFile\s*\(',
            r'DiskFileItemFactory\s*\(',
            r'ServletFileUpload\s*\(',
        ]
        
        # Database connection patterns (potential for SQL injection)
        self.database_patterns = [
            r'Connection\s+conn\s*=',
            r'DriverManager\.getConnection\s*\(',
            r'PreparedStatement\s*\(',
            r'Statement\s+stmt\s*=',
            r'ResultSet\s+rs\s*=',
        ]

    def analyze(self, file_path):
        """Comprehensive JSP file analysis"""
        try:
            result = {
                'infected': False,
                'confidence': 0,
                'payload_type': 'Unknown',
                'indicators': [],
                'analysis_details': {},
                'file_info': self._get_file_info(file_path)
            }
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Analysis layers
            result['analysis_details']['file_size'] = len(content)
            result['analysis_details']['lines_of_code'] = len(content.split('\n'))
            
            # 1. Web Shell Pattern Detection
            web_shell_score = self._detect_web_shells(content)
            result['analysis_details']['web_shell_score'] = web_shell_score
            
            # 2. Metasploit Payload Detection
            metasploit_score = self._detect_metasploit_payloads(content)
            result['analysis_details']['metasploit_score'] = metasploit_score
            
            # 3. JSP Tag Analysis
            jsp_tag_analysis = self._analyze_jsp_tags(content)
            result['analysis_details']['jsp_tag_analysis'] = jsp_tag_analysis
            
            # 4. Obfuscation Detection
            obfuscation_score = self._detect_obfuscation(content)
            result['analysis_details']['obfuscation_score'] = obfuscation_score
            
            # 5. Runtime Execution Detection
            runtime_execution = self._detect_runtime_execution(content)
            result['analysis_details']['runtime_execution'] = runtime_execution
            
            # 6. File Operations Detection
            file_operations = self._detect_file_operations(content)
            result['analysis_details']['file_operations'] = file_operations
            
            # 7. Network Operations Detection
            network_operations = self._detect_network_operations(content)
            result['analysis_details']['network_operations'] = network_operations
            
            # 8. Reflection and Class Loading
            reflection_analysis = self._detect_reflection(content)
            result['analysis_details']['reflection_analysis'] = reflection_analysis
            
            # 9. Base64 Content Analysis
            base64_analysis = self._analyze_base64_content(content)
            result['analysis_details']['base64_analysis'] = base64_analysis
            
            # 9.5. Hex Content Analysis
            hex_analysis = self._analyze_hex_content(content)
            result['analysis_details']['hex_analysis'] = hex_analysis
            
            # 10. Upload Functionality Detection
            upload_analysis = self._detect_upload_functionality(content)
            result['analysis_details']['upload_analysis'] = upload_analysis
            
            # Calculate overall confidence
            total_score = (web_shell_score * 0.2 + 
                          metasploit_score * 0.2 + 
                          jsp_tag_analysis['score'] * 0.1 + 
                          obfuscation_score * 0.1 + 
                          runtime_execution['score'] * 0.1 + 
                          file_operations['score'] * 0.05 + 
                          network_operations['score'] * 0.05 + 
                          reflection_analysis['score'] * 0.05 + 
                          base64_analysis['score'] * 0.1 + 
                          hex_analysis['score'] * 0.05)
            
            result['confidence'] = min(100, total_score)
            
            # Determine if infected
            if result['confidence'] >= 15:
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
                'extension': '.jsp'
            }
        except Exception as e:
            return {'error': str(e)}

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

    def _analyze_jsp_tags(self, content):
        """Analyze JSP tags and directives"""
        analysis = {'suspicious_tags': [], 'score': 0}
        
        for pattern in self.suspicious_jsp_tags:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                analysis['suspicious_tags'].extend(matches)
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

    def _detect_runtime_execution(self, content):
        """Detect runtime execution patterns"""
        execution_patterns = [
            r'Runtime\.getRuntime\(\)\.exec\s*\(',
            r'ProcessBuilder\s*\(',
            r'Process\s+proc\s*=',
            r'BufferedReader\s+reader\s*=\s*new\s+BufferedReader',
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
            r'new\s+File\s*\(',
            r'FileInputStream\s*\(',
            r'FileOutputStream\s*\(',
            r'FileWriter\s*\(',
            r'FileReader\s*\(',
            r'Files\.write\s*\(',
            r'Files\.readAllBytes\s*\(',
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
            r'Socket\s*\(',
            r'ServerSocket\s*\(',
            r'URLConnection\s*\(',
            r'HttpURLConnection\s*\(',
            r'URL\s*\(',
            r'InetAddress\s*\(',
        ]
        
        operations = {'patterns_found': [], 'score': 0}
        for pattern in network_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                operations['patterns_found'].append(pattern)
                operations['score'] += 20
        
        return operations

    def _detect_reflection(self, content):
        """Detect reflection and class loading"""
        reflection_patterns = [
            r'Class\.forName\s*\(',
            r'ClassLoader\s*\(',
            r'URLClassLoader\s*\(',
            r'Method\.invoke\s*\(',
            r'Constructor\.newInstance\s*\(',
            r'Field\.set\s*\(',
        ]
        
        reflection = {'patterns_found': [], 'score': 0}
        for pattern in reflection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                reflection['patterns_found'].append(pattern)
                reflection['score'] += 18
        
        return reflection

    def _analyze_base64_content(self, content):
        """Analyze Base64 encoded content"""
        base64_pattern = r'Base64\.getDecoder\(\)\.decode\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\']'
        matches = re.findall(base64_pattern, content, re.IGNORECASE)
        
        analysis = {'count': len(matches), 'score': 0, 'decoded_content': [], 'suspicious_decoded': []}
        
        for match in matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                analysis['decoded_content'].append(decoded[:100])  # First 100 chars
                
                # Check if decoded content contains suspicious patterns
                if any(pattern in decoded.lower() for pattern in ['runtime', 'exec', 'process', 'socket', 'payload', 'meterpreter']):
                    analysis['score'] += 25
                    analysis['suspicious_decoded'].append(decoded[:200])
                
                # Check for Metasploit patterns in decoded content
                if any(pattern in decoded.lower() for pattern in ['msfvenom', 'payload', 'reverse_tcp', 'bind_tcp']):
                    analysis['score'] += 50
                    
            except:
                analysis['score'] += 8
        
        return analysis

    def _analyze_hex_content(self, content):
        """Analyze hex encoded content (common in JSP payloads)"""
        # Look for long hex strings (likely encoded payloads)
        hex_pattern = r'["\']([0-9a-fA-F]{100,})["\']'
        matches = re.findall(hex_pattern, content, re.IGNORECASE)
        
        analysis = {'count': len(matches), 'score': 0, 'decoded_content': [], 'suspicious_decoded': []}
        
        for match in matches:
            try:
                # Convert hex to bytes
                hex_bytes = bytes.fromhex(match)
                # Try to decode as UTF-8
                decoded = hex_bytes.decode('utf-8', errors='ignore')
                analysis['decoded_content'].append(decoded[:100])
                
                # Check for suspicious patterns in decoded content
                if any(pattern in decoded.lower() for pattern in ['payload', 'meterpreter', 'shell', 'exec', 'runtime']):
                    analysis['score'] += 40
                    analysis['suspicious_decoded'].append(decoded[:200])
                
                # Check for PE header signatures (Windows executables)
                if hex_bytes.startswith(b'MZ') or b'This program cannot be run in DOS mode' in hex_bytes:
                    analysis['score'] += 60
                    analysis['suspicious_decoded'].append("PE Executable detected in hex content")
                    
            except:
                analysis['score'] += 15
        
        return analysis

    def _detect_upload_functionality(self, content):
        """Detect file upload functionality"""
        upload = {'patterns_found': [], 'score': 0}
        for pattern in self.upload_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                upload['patterns_found'].append(pattern)
                upload['score'] += 20
        
        return upload

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
            return 'Suspicious JSP Code'

    def _collect_indicators(self, content, analysis_details):
        """Collect all suspicious indicators"""
        indicators = []
        
        # High confidence indicators
        if analysis_details.get('web_shell_score', 0) > 40:
            indicators.append(f"Web shell patterns detected (score: {analysis_details['web_shell_score']})")
        
        if analysis_details.get('metasploit_score', 0) > 0:
            indicators.append(f"Metasploit payload patterns detected (score: {analysis_details['metasploit_score']})")
        
        if analysis_details.get('jsp_tag_analysis', {}).get('score', 0) > 0:
            indicators.append(f"Suspicious JSP tags: {len(analysis_details['jsp_tag_analysis']['suspicious_tags'])}")
        
        if analysis_details.get('obfuscation_score', 0) > 25:
            indicators.append(f"Code obfuscation detected (score: {analysis_details['obfuscation_score']})")
        
        # Runtime execution
        if analysis_details.get('runtime_execution', {}).get('score', 0) > 0:
            indicators.append(f"Runtime execution patterns: {len(analysis_details['runtime_execution']['patterns_found'])}")
        
        # File operations
        if analysis_details.get('file_operations', {}).get('score', 0) > 0:
            indicators.append(f"File operations: {len(analysis_details['file_operations']['patterns_found'])}")
        
        # Network operations
        if analysis_details.get('network_operations', {}).get('score', 0) > 0:
            indicators.append(f"Network operations: {len(analysis_details['network_operations']['patterns_found'])}")
        
        # Reflection
        if analysis_details.get('reflection_analysis', {}).get('score', 0) > 0:
            indicators.append(f"Reflection/Class loading: {len(analysis_details['reflection_analysis']['patterns_found'])}")
        
        # Base64 content
        if analysis_details.get('base64_analysis', {}).get('score', 0) > 0:
            indicators.append(f"Base64 encoded content: {analysis_details['base64_analysis']['count']} instances")
        
        # Hex content
        if analysis_details.get('hex_analysis', {}).get('score', 0) > 0:
            indicators.append(f"Hex encoded content: {analysis_details['hex_analysis']['count']} instances")
        
        # Upload functionality
        if analysis_details.get('upload_analysis', {}).get('score', 0) > 0:
            indicators.append(f"File upload functionality detected")
        
        return indicators

    def display_result(self, result, file_path):
        """Display analysis result"""
        print(f"\n{self.colors.CYAN}🔍 JSP Payload Analysis: {os.path.basename(file_path)}{self.colors.RESET}")
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
            print(f"   Web Shell Score: {details.get('web_shell_score', 0)}/100")
            print(f"   Metasploit Score: {details.get('metasploit_score', 0)}/100")
            print(f"   Obfuscation Score: {details.get('obfuscation_score', 0)}/100")
            print(f"   JSP Tag Score: {details.get('jsp_tag_analysis', {}).get('score', 0)}/100")
            
            if details.get('base64_analysis', {}).get('count', 0) > 0:
                print(f"   Base64 Instances: {details['base64_analysis']['count']}")
            
            if details.get('hex_analysis', {}).get('count', 0) > 0:
                print(f"   Hex Instances: {details['hex_analysis']['count']}")
            
            if details.get('runtime_execution', {}).get('patterns_found'):
                print(f"   Runtime Execution: {len(details['runtime_execution']['patterns_found'])} patterns")
            
            if details.get('upload_analysis', {}).get('score', 0) > 0:
                print(f"   Upload Functionality: Detected")
        
        if result['indicators']:
            print(f"\n{self.colors.YELLOW}⚠️  Suspicious Indicators:{self.colors.RESET}")
            for indicator in result['indicators']:
                print(f"   • {indicator}")
        
        return result
