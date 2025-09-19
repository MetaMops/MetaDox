"""
APK Analyzer - Comprehensive analysis for Android APK payloads
Professional-grade detection with multiple analysis layers
"""

import os
import re
import hashlib
import subprocess
import zipfile
from ...colors import Colors

class ApkAnalyzer:
    def __init__(self):
        self.colors = Colors()
        
        # Android-specific suspicious patterns
        self.android_suspicious_patterns = [
            # Network operations
            r'HttpURLConnection',
            r'URLConnection',
            r'Socket\s*\(',
            r'ServerSocket\s*\(',
            r'DatagramSocket\s*\(',
            r'InetAddress\s*\.',
            r'URL\s*\(',
            
            # Process execution
            r'Runtime\.getRuntime\(\)\.exec\s*\(',
            r'ProcessBuilder\s*\(',
            r'Process\s+',
            r'System\.exec\s*\(',
            
            # File operations
            r'FileOutputStream\s*\(',
            r'FileInputStream\s*\(',
            r'FileWriter\s*\(',
            r'FileReader\s*\(',
            r'File\s*\(',
            r'File\.createTempFile\s*\(',
            
            # Reflection and dynamic loading
            r'Class\.forName\s*\(',
            r'ClassLoader\s*\.',
            r'DexClassLoader\s*\(',
            r'PathClassLoader\s*\(',
            r'URLClassLoader\s*\(',
            
            # Base64 and encoding
            r'Base64\.decode\s*\(',
            r'Base64\.encode\s*\(',
            r'new\s+String\s*\(\s*Base64\.decode',
            
            # Obfuscation patterns
            r'new\s+String\s*\(\s*new\s+char\[\]\s*\{[^}]+\}\s*\)',
            r'Character\.toChars\s*\(',
            r'Integer\.parseInt\s*\(',
        ]
        
        # Metasploit Android payload patterns
        self.metasploit_patterns = [
            r'android/meterpreter/reverse_tcp',
            r'android/meterpreter/reverse_https',
            r'android/meterpreter/reverse_http',
            r'android/shell/reverse_tcp',
            r'android/shell/reverse_https',
            r'android/shell/reverse_http',
            r'meterpreter',
            r'reverse_tcp',
            r'reverse_https',
            r'reverse_http',
            r'bind_tcp',
            r'payload',
            r'msfvenom',
            r'msfconsole',
        ]
        
        # High-confidence Android payload indicators
        self.high_confidence_patterns = [
            r'Runtime\.getRuntime\(\)\.exec\s*\(\s*["\']',
            r'ProcessBuilder\s*\(\s*["\']',
            r'Class\.forName\s*\(\s*["\']',
            r'DexClassLoader\s*\(',
            r'Base64\.decode\s*\(\s*["\']',
            r'Socket\s*\(\s*["\']',
            r'HttpURLConnection\s*\.',
        ]
        
        # Suspicious Android permissions
        self.suspicious_permissions = [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.ACCESS_WIFI_STATE',
            'android.permission.CHANGE_WIFI_STATE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.READ_PHONE_STATE',
            'android.permission.CALL_PHONE',
            'android.permission.SEND_SMS',
            'android.permission.READ_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.WRITE_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.READ_CALENDAR',
            'android.permission.WRITE_CALENDAR',
        ]
        
        # Suspicious Android components
        self.suspicious_components = [
            r'<service\s+android:name',
            r'<receiver\s+android:name',
            r'<provider\s+android:name',
            r'<activity\s+android:name',
            r'<activity-alias\s+android:name',
        ]

    def analyze(self, file_path):
        """Comprehensive APK file analysis"""
        try:
            result = {
                'infected': False,
                'confidence': 0,
                'payload_type': 'Unknown',
                'indicators': [],
                'analysis_details': {},
                'file_info': self._get_file_info(file_path)
            }
            
            # Read file content (APK is a ZIP file)
            try:
                with zipfile.ZipFile(file_path, 'r') as apk_zip:
                    # Extract and analyze AndroidManifest.xml
                    manifest_analysis = self._analyze_manifest(apk_zip)
                    result['analysis_details']['manifest_analysis'] = manifest_analysis
                    
                    # Extract and analyze DEX files
                    dex_analysis = self._analyze_dex_files(apk_zip)
                    result['analysis_details']['dex_analysis'] = dex_analysis
                    
                    # Analyze APK structure
                    structure_analysis = self._analyze_apk_structure(apk_zip)
                    result['analysis_details']['structure_analysis'] = structure_analysis
                    
            except zipfile.BadZipFile:
                # Not a valid APK/ZIP file
                result['analysis_details']['error'] = 'Invalid APK file format'
                return result
            
            # Analysis layers
            result['analysis_details']['file_size'] = os.path.getsize(file_path)
            
            # 1. High-Confidence Pattern Detection
            high_confidence_score = self._detect_high_confidence_patterns(dex_analysis.get('content', ''))
            result['analysis_details']['high_confidence_score'] = high_confidence_score
            
            # 2. Android Suspicious Pattern Detection
            android_score = self._detect_android_patterns(dex_analysis.get('content', ''))
            result['analysis_details']['android_score'] = android_score
            
            # 3. Metasploit Payload Detection
            metasploit_score = self._detect_metasploit_payloads(dex_analysis.get('content', ''))
            result['analysis_details']['metasploit_score'] = metasploit_score
            
            # 4. Permission Analysis
            permission_score = manifest_analysis.get('score', 0)
            result['analysis_details']['permission_score'] = permission_score
            
            # 5. Component Analysis
            component_score = manifest_analysis.get('component_score', 0)
            result['analysis_details']['component_score'] = component_score
            
            # 6. Binary Metasploit Signature Detection
            binary_signature_score = self._detect_binary_metasploit_signatures(apk_zip)
            result['analysis_details']['binary_signature_score'] = binary_signature_score
            
            # Calculate overall confidence
            total_score = (high_confidence_score * 0.25 + 
                          android_score * 0.15 + 
                          metasploit_score * 0.15 + 
                          binary_signature_score * 0.25 +  # High weight for binary signatures
                          permission_score * 0.1 + 
                          component_score * 0.1)
            
            result['confidence'] = min(100, total_score)
            
            # Determine if infected - Lower threshold for Metasploit payloads
            if result['confidence'] >= 5:
                result['infected'] = True
                result['payload_type'] = self._determine_payload_type(dex_analysis.get('content', ''))
            
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
                'extension': '.apk'
            }
        except Exception as e:
            return {'error': str(e)}

    def _analyze_manifest(self, apk_zip):
        """Analyze AndroidManifest.xml"""
        analysis = {'permissions': [], 'components': [], 'score': 0, 'component_score': 0}
        
        try:
            # Look for AndroidManifest.xml
            manifest_files = [f for f in apk_zip.namelist() if 'AndroidManifest.xml' in f]
            
            if manifest_files:
                manifest_content = apk_zip.read(manifest_files[0]).decode('utf-8', errors='ignore')
                
                # Analyze permissions
                for permission in self.suspicious_permissions:
                    if permission in manifest_content:
                        analysis['permissions'].append(permission)
                        analysis['score'] += 5
                
                # Analyze components
                for component in self.suspicious_components:
                    if re.search(component, manifest_content, re.IGNORECASE):
                        analysis['components'].append(component)
                        analysis['component_score'] += 10
                
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis

    def _analyze_dex_files(self, apk_zip):
        """Analyze DEX files for suspicious patterns"""
        analysis = {'content': '', 'score': 0, 'patterns_found': []}
        
        try:
            # Look for DEX files
            dex_files = [f for f in apk_zip.namelist() if f.endswith('.dex')]
            
            if dex_files:
                # Read the first DEX file (usually classes.dex)
                dex_content = apk_zip.read(dex_files[0])
                
                # Convert to string for pattern matching
                analysis['content'] = dex_content.decode('utf-8', errors='ignore')
                
                # Analyze for suspicious patterns
                for pattern in self.android_suspicious_patterns:
                    if re.search(pattern, analysis['content'], re.IGNORECASE):
                        analysis['patterns_found'].append(pattern)
                        analysis['score'] += 8
                
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis

    def _analyze_apk_structure(self, apk_zip):
        """Analyze APK structure"""
        analysis = {'files': [], 'score': 0}
        
        try:
            files = apk_zip.namelist()
            analysis['files'] = files
            
            # Check for suspicious file types
            suspicious_extensions = ['.so', '.dex', '.jar', '.class']
            for file in files:
                for ext in suspicious_extensions:
                    if file.endswith(ext):
                        analysis['score'] += 5
                        break
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis

    def _detect_binary_metasploit_signatures(self, apk_zip):
        """Detect Metasploit signatures in APK binary content"""
        score = 0
        found_signatures = []
        
        try:
            # Get all files in the APK
            files = apk_zip.namelist()
            
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
                b'Runtime.getRuntime',
                b'ProcessBuilder',
                b'Process.start',
                b'Class.forName',
                b'DexClassLoader',
                b'PathClassLoader',
                b'URLClassLoader',
                b'Base64.decode',
                b'System.load',
                b'System.loadLibrary',
            ]
            
            # Check each file for Metasploit signatures
            for file_name in files:
                try:
                    file_content = apk_zip.read(file_name)
                    
                    for signature in metasploit_signatures:
                        if signature in file_content:
                            found_signatures.append(signature.decode('utf-8', errors='ignore'))
                            score += 25  # High weight for binary signatures
                            
                except Exception:
                    continue
                    
        except Exception as e:
            pass
        
        return min(100, score)

    def _detect_high_confidence_patterns(self, content):
        """Detect high-confidence Android payload patterns"""
        score = 0
        for pattern in self.high_confidence_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                score += len(matches) * 40  # High weight for these patterns
        return min(100, score)

    def _detect_android_patterns(self, content):
        """Detect Android-specific suspicious patterns"""
        score = 0
        for pattern in self.android_suspicious_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                score += len(matches) * 6
        return min(100, score)

    def _detect_metasploit_payloads(self, content):
        """Detect Metasploit payload patterns"""
        score = 0
        for pattern in self.metasploit_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                score += 35
        return min(100, score)

    def _determine_payload_type(self, content):
        """Determine the type of payload"""
        if re.search(r'meterpreter', content, re.IGNORECASE):
            return 'Meterpreter Payload'
        elif re.search(r'shell', content, re.IGNORECASE):
            return 'Shell Payload'
        elif re.search(r'backdoor', content, re.IGNORECASE):
            return 'Backdoor'
        elif re.search(r'keylogger', content, re.IGNORECASE):
            return 'Keylogger'
        else:
            return 'Suspicious Android App'

    def _collect_indicators(self, analysis_details):
        """Collect all suspicious indicators"""
        indicators = []
        
        # High confidence indicators
        if analysis_details.get('high_confidence_score', 0) > 0:
            indicators.append(f"High-confidence Android payload patterns detected (score: {analysis_details['high_confidence_score']})")
        
        if analysis_details.get('android_score', 0) > 30:
            indicators.append(f"Android suspicious patterns detected (score: {analysis_details['android_score']})")
        
        if analysis_details.get('metasploit_score', 0) > 0:
            indicators.append(f"Metasploit payload patterns detected (score: {analysis_details['metasploit_score']})")
        
        # Permission analysis
        manifest_analysis = analysis_details.get('manifest_analysis', {})
        if manifest_analysis.get('permissions'):
            indicators.append(f"Suspicious permissions: {len(manifest_analysis['permissions'])}")
        
        if manifest_analysis.get('components'):
            indicators.append(f"Suspicious components: {len(manifest_analysis['components'])}")
        
        # DEX analysis
        dex_analysis = analysis_details.get('dex_analysis', {})
        if dex_analysis.get('patterns_found'):
            indicators.append(f"Suspicious DEX patterns: {len(dex_analysis['patterns_found'])}")
        
        # Structure analysis
        structure_analysis = analysis_details.get('structure_analysis', {})
        if structure_analysis.get('score', 0) > 0:
            indicators.append(f"Suspicious APK structure detected")
        
        # Binary signature analysis
        if analysis_details.get('binary_signature_score', 0) > 0:
            indicators.append(f"Binary Metasploit signatures detected (score: {analysis_details['binary_signature_score']})")
        
        return indicators

    def display_result(self, result, file_path):
        """Display analysis result"""
        print(f"\n{self.colors.CYAN}🔍 APK Payload Analysis: {os.path.basename(file_path)}{self.colors.RESET}")
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
            print(f"   Android Score: {details.get('android_score', 0)}/100")
            print(f"   Metasploit Score: {details.get('metasploit_score', 0)}/100")
            print(f"   Permission Score: {details.get('permission_score', 0)}/100")
            print(f"   Component Score: {details.get('component_score', 0)}/100")
            
            manifest_analysis = details.get('manifest_analysis', {})
            if manifest_analysis.get('permissions'):
                print(f"   Suspicious Permissions: {len(manifest_analysis['permissions'])}")
            
            if manifest_analysis.get('components'):
                print(f"   Suspicious Components: {len(manifest_analysis['components'])}")
            
            dex_analysis = details.get('dex_analysis', {})
            if dex_analysis.get('patterns_found'):
                print(f"   DEX Patterns: {len(dex_analysis['patterns_found'])}")
            
            if details.get('binary_signature_score', 0) > 0:
                print(f"   Binary Signature Score: {details['binary_signature_score']}/100")
        
        if result['indicators']:
            print(f"\n{self.colors.YELLOW}⚠️  Suspicious Indicators:{self.colors.RESET}")
            for indicator in result['indicators']:
                print(f"   • {indicator}")
        else:
            print(f"\n{self.colors.GREEN}✅ No suspicious indicators found{self.colors.RESET}")
        
        return result
