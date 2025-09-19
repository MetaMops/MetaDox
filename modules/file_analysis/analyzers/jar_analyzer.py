import os
import re
import hashlib
import zipfile
import xml.etree.ElementTree as ET
from ...colors import Colors

class JarAnalyzer:
    def __init__(self):
        self.colors = Colors()
        
        # Metasploit-specific patterns for Java payloads
        self.metasploit_patterns = [
            r'java/meterpreter/reverse_tcp',
            r'java/meterpreter/reverse_https',
            r'java/shell/reverse_tcp',
            r'meterpreter',
            r'payload',
            r'msfvenom',
            r'msfconsole',
        ]
        
        # High-confidence Java payload patterns
        self.high_confidence_patterns = [
            r'Runtime\.getRuntime\(\)\.exec\s*\(',
            r'ProcessBuilder\s*\(',
            r'Process\.start\s*\(',
            r'Class\.forName\s*\(',
            r'URLClassLoader\s*\(',
            r'DexClassLoader\s*\(',
            r'PathClassLoader\s*\(',
            r'Base64\.decode\s*\(',
            r'System\.load\s*\(',
            r'System\.loadLibrary\s*\(',
            r'ProcessBuilder\s*\([^)]*\)\.start\s*\(',
            r'Runtime\.exec\s*\([^)]*\)',
            r'ClassLoader\.loadClass\s*\(',
            r'Method\.invoke\s*\(',
            r'Constructor\.newInstance\s*\(',
            r'Reflection\.getDeclaredMethod\s*\(',
            r'Reflection\.getDeclaredField\s*\(',
            r'Reflection\.setAccessible\s*\(',
        ]
        
        # Suspicious Java patterns
        self.java_suspicious_patterns = [
            r'java\.net\.Socket',
            r'java\.net\.ServerSocket',
            r'java\.net\.URL',
            r'java\.net\.URLConnection',
            r'java\.io\.File',
            r'java\.io\.FileInputStream',
            r'java\.io\.FileOutputStream',
            r'java\.io\.BufferedReader',
            r'java\.io\.BufferedWriter',
            r'java\.io\.PrintWriter',
            r'java\.io\.InputStreamReader',
            r'java\.io\.OutputStreamWriter',
            r'java\.io\.DataInputStream',
            r'java\.io\.DataOutputStream',
            r'java\.io\.ObjectInputStream',
            r'java\.io\.ObjectOutputStream',
            r'java\.io\.Serializable',
            r'java\.io\.Externalizable',
            r'java\.io\.FileReader',
            r'java\.io\.FileWriter',
            r'java\.io\.RandomAccessFile',
            r'java\.io\.PipedInputStream',
            r'java\.io\.PipedOutputStream',
            r'java\.io\.ByteArrayInputStream',
            r'java\.io\.ByteArrayOutputStream',
            r'java\.io\.StringReader',
            r'java\.io\.StringWriter',
            r'java\.io\.CharArrayReader',
            r'java\.io\.CharArrayWriter',
            r'java\.io\.FilterInputStream',
            r'java\.io\.FilterOutputStream',
            r'java\.io\.BufferedInputStream',
            r'java\.io\.BufferedOutputStream',
            r'java\.io\.PushbackInputStream',
            r'java\.io\.SequenceInputStream',
            r'java\.io\.LineNumberInputStream',
            r'java\.io\.LineNumberReader',
            r'java\.io\.StringBufferInputStream',
            r'java\.io\.StringBufferOutputStream',
            r'java\.io\.PipedReader',
            r'java\.io\.PipedWriter',
            r'java\.io\.FilterReader',
            r'java\.io\.FilterWriter',
            r'java\.io\.PushbackReader',
            r'java\.io\.PrintStream',
            r'java\.io\.PrintWriter',
            r'java\.io\.OutputStreamWriter',
            r'java\.io\.InputStreamReader',
            r'java\.io\.FileDescriptor',
            r'java\.io\.FilePermission',
            r'java\.io\.SerializablePermission',
            r'java\.io\.ObjectStreamClass',
            r'java\.io\.ObjectStreamField',
            r'java\.io\.ObjectInput',
            r'java\.io\.ObjectOutput',
            r'java\.io\.ObjectInputStream',
            r'java\.io\.ObjectOutputStream',
            r'java\.io\.ObjectStreamConstants',
            r'java\.io\.ObjectStreamException',
            r'java\.io\.InvalidClassException',
            r'java\.io\.InvalidObjectException',
            r'java\.io\.NotActiveException',
            r'java\.io\.NotSerializableException',
            r'java\.io\.OptionalDataException',
            r'java\.io\.StreamCorruptedException',
            r'java\.io\.WriteAbortedException',
            r'java\.io\.SyncFailedException',
            r'java\.io\.UTFDataFormatException',
            r'java\.io\.UnsupportedEncodingException',
            r'java\.io\.InterruptedIOException',
            r'java\.io\.EOFException',
            r'java\.io\.FileNotFoundException',
            r'java\.io\.IOException',
            r'java\.io\.UncheckedIOException',
            r'java\.io\.Closeable',
            r'java\.io\.Flushable',
            r'java\.io\.AutoCloseable',
            r'java\.io\.FileFilter',
            r'java\.io\.FilenameFilter',
            r'java\.io\.Serializable',
            r'java\.io\.Externalizable',
            r'java\.io\.ObjectInputValidation',
            r'java\.io\.ObjectStreamConstants',
            r'java\.io\.ObjectStreamException',
            r'java\.io\.InvalidClassException',
            r'java\.io\.InvalidObjectException',
            r'java\.io\.NotActiveException',
            r'java\.io\.NotSerializableException',
            r'java\.io\.OptionalDataException',
            r'java\.io\.StreamCorruptedException',
            r'java\.io\.WriteAbortedException',
            r'java\.io\.SyncFailedException',
            r'java\.io\.UTFDataFormatException',
            r'java\.io\.UnsupportedEncodingException',
            r'java\.io\.InterruptedIOException',
            r'java\.io\.EOFException',
            r'java\.io\.FileNotFoundException',
            r'java\.io\.IOException',
            r'java\.io\.UncheckedIOException',
            r'java\.io\.Closeable',
            r'java\.io\.Flushable',
            r'java\.io\.AutoCloseable',
            r'java\.io\.FileFilter',
            r'java\.io\.FilenameFilter',
            r'java\.io\.Serializable',
            r'java\.io\.Externalizable',
            r'java\.io\.ObjectInputValidation',
        ]
        
        # Suspicious permissions in MANIFEST.MF
        self.suspicious_permissions = [
            'java.net.SocketPermission',
            'java.io.FilePermission',
            'java.lang.RuntimePermission',
            'java.security.AllPermission',
            'java.util.PropertyPermission',
            'java.awt.AWTPermission',
            'java.sql.SQLPermission',
            'java.util.logging.LoggingPermission',
            'java.lang.management.ManagementPermission',
            'java.nio.file.LinkPermission',
            'java.nio.file.FileSystemPermission',
            'java.nio.file.PathPermission',
            'java.nio.file.FilePermission',
            'java.nio.file.DirectoryPermission',
            'java.nio.file.ReadPermission',
            'java.nio.file.WritePermission',
            'java.nio.file.ExecutePermission',
            'java.nio.file.DeletePermission',
            'java.nio.file.CreatePermission',
            'java.nio.file.ModifyPermission',
            'java.nio.file.AccessPermission',
            'java.nio.file.AttributePermission',
            'java.nio.file.LinkPermission',
            'java.nio.file.FileSystemPermission',
            'java.nio.file.PathPermission',
            'java.nio.file.FilePermission',
            'java.nio.file.DirectoryPermission',
            'java.nio.file.ReadPermission',
            'java.nio.file.WritePermission',
            'java.nio.file.ExecutePermission',
            'java.nio.file.DeletePermission',
            'java.nio.file.CreatePermission',
            'java.nio.file.ModifyPermission',
            'java.nio.file.AccessPermission',
            'java.nio.file.AttributePermission',
        ]

    def analyze(self, file_path):
        """Analyze JAR file for payloads"""
        result = {
            'infected': False,
            'confidence': 0,
            'payload_type': 'Unknown',
            'indicators': [],
            'analysis_details': {},
            'file_info': self._get_file_info(file_path)
        }
        
        try:
            with zipfile.ZipFile(file_path, 'r') as jar_zip:
                # 1. High-confidence pattern detection
                high_confidence_score = self._detect_high_confidence_patterns(jar_zip)
                result['analysis_details']['high_confidence_score'] = high_confidence_score
                
                # 2. Java pattern detection
                java_score = self._detect_java_patterns(jar_zip)
                result['analysis_details']['java_score'] = java_score
                
                # 3. Metasploit payload detection
                metasploit_score = self._detect_metasploit_payloads(jar_zip)
                result['analysis_details']['metasploit_score'] = metasploit_score
                
                # 4. MANIFEST.MF analysis
                manifest_analysis = self._analyze_manifest(jar_zip)
                result['analysis_details']['manifest_analysis'] = manifest_analysis
                
                # 5. Binary Metasploit signature detection
                binary_signature_score = self._detect_binary_metasploit_signatures(jar_zip)
                result['analysis_details']['binary_signature_score'] = binary_signature_score
                
                # Calculate overall confidence
                total_score = (high_confidence_score * 0.3 + 
                              java_score * 0.2 + 
                              metasploit_score * 0.2 + 
                              binary_signature_score * 0.3)  # High weight for binary signatures
                
                result['confidence'] = min(100, total_score)
                
                # Determine if infected - Lower threshold for Metasploit payloads
                if result['confidence'] >= 5:
                    result['infected'] = True
                    result['payload_type'] = self._determine_payload_type(jar_zip)
                
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
            'extension': '.jar'
        }

    def _detect_high_confidence_patterns(self, jar_zip):
        """Detect high-confidence Java payload patterns"""
        score = 0
        found_patterns = []
        
        try:
            # Get all files in the JAR
            files = jar_zip.namelist()
            
            for file_name in files:
                if file_name.endswith('.class') or file_name.endswith('.java'):
                    try:
                        file_content = jar_zip.read(file_name).decode('utf-8', errors='ignore')
                        
                        for pattern in self.high_confidence_patterns:
                            if re.search(pattern, file_content, re.IGNORECASE):
                                found_patterns.append(pattern)
                                score += 50  # High weight for high-confidence patterns
                                
                    except Exception:
                        continue
                        
        except Exception as e:
            pass
        
        return min(100, score)

    def _detect_java_patterns(self, jar_zip):
        """Detect suspicious Java patterns"""
        score = 0
        found_patterns = []
        
        try:
            # Get all files in the JAR
            files = jar_zip.namelist()
            
            for file_name in files:
                if file_name.endswith('.class') or file_name.endswith('.java'):
                    try:
                        file_content = jar_zip.read(file_name).decode('utf-8', errors='ignore')
                        
                        for pattern in self.java_suspicious_patterns:
                            if re.search(pattern, file_content, re.IGNORECASE):
                                found_patterns.append(pattern)
                                score += 5  # Lower weight for suspicious patterns
                                
                    except Exception:
                        continue
                        
        except Exception as e:
            pass
        
        return min(100, score)

    def _detect_metasploit_payloads(self, jar_zip):
        """Detect Metasploit payload patterns"""
        score = 0
        found_patterns = []
        
        try:
            # Get all files in the JAR
            files = jar_zip.namelist()
            
            for file_name in files:
                if file_name.endswith('.class') or file_name.endswith('.java'):
                    try:
                        file_content = jar_zip.read(file_name).decode('utf-8', errors='ignore')
                        
                        for pattern in self.metasploit_patterns:
                            if re.search(pattern, file_content, re.IGNORECASE):
                                found_patterns.append(pattern)
                                score += 35  # High weight for Metasploit patterns
                                
                    except Exception:
                        continue
                        
        except Exception as e:
            pass
        
        return min(100, score)

    def _analyze_manifest(self, jar_zip):
        """Analyze MANIFEST.MF for suspicious entries"""
        analysis = {'score': 0, 'indicators': [], 'permissions': []}
        
        try:
            # Check if MANIFEST.MF exists
            if 'META-INF/MANIFEST.MF' in jar_zip.namelist():
                manifest_content = jar_zip.read('META-INF/MANIFEST.MF').decode('utf-8', errors='ignore')
                
                # Look for suspicious permissions
                for permission in self.suspicious_permissions:
                    if permission in manifest_content:
                        analysis['permissions'].append(permission)
                        analysis['score'] += 10
                
                if analysis['permissions']:
                    analysis['indicators'].append(f"Suspicious permissions found: {len(analysis['permissions'])}")
                
                # Look for suspicious attributes
                suspicious_attributes = [
                    'Main-Class',
                    'Class-Path',
                    'Implementation-Version',
                    'Implementation-Vendor',
                    'Implementation-Title',
                    'Specification-Version',
                    'Specification-Vendor',
                    'Specification-Title',
                    'Sealed',
                    'Extension-Name',
                    'Extension-List',
                    'Extension-Installation',
                    'Extension-Name',
                    'Extension-List',
                    'Extension-Installation',
                ]
                
                for attr in suspicious_attributes:
                    if attr in manifest_content:
                        analysis['score'] += 5
                
                if analysis['score'] > 0:
                    analysis['indicators'].append("Suspicious MANIFEST.MF entries detected")
                    
        except Exception as e:
            analysis['indicators'].append(f"MANIFEST.MF analysis error: {str(e)}")
        
        return analysis

    def _detect_binary_metasploit_signatures(self, jar_zip):
        """Detect Metasploit signatures in JAR binary content"""
        score = 0
        found_signatures = []
        
        try:
            # Get all files in the JAR
            files = jar_zip.namelist()
            
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
                b'java.net.Socket',
                b'java.net.ServerSocket',
                b'java.net.URL',
                b'java.net.URLConnection',
                b'java.io.File',
                b'java.io.FileInputStream',
                b'java.io.FileOutputStream',
                b'java.io.BufferedReader',
                b'java.io.BufferedWriter',
                b'java.io.PrintWriter',
                b'java.io.InputStreamReader',
                b'java.io.OutputStreamWriter',
                b'java.io.DataInputStream',
                b'java.io.DataOutputStream',
                b'java.io.ObjectInputStream',
                b'java.io.ObjectOutputStream',
                b'java.io.Serializable',
                b'java.io.Externalizable',
                b'java.io.FileReader',
                b'java.io.FileWriter',
                b'java.io.RandomAccessFile',
                b'java.io.PipedInputStream',
                b'java.io.PipedOutputStream',
                b'java.io.ByteArrayInputStream',
                b'java.io.ByteArrayOutputStream',
                b'java.io.StringReader',
                b'java.io.StringWriter',
                b'java.io.CharArrayReader',
                b'java.io.CharArrayWriter',
                b'java.io.FilterInputStream',
                b'java.io.FilterOutputStream',
                b'java.io.BufferedInputStream',
                b'java.io.BufferedOutputStream',
                b'java.io.PushbackInputStream',
                b'java.io.SequenceInputStream',
                b'java.io.LineNumberInputStream',
                b'java.io.LineNumberReader',
                b'java.io.StringBufferInputStream',
                b'java.io.StringBufferOutputStream',
                b'java.io.PipedReader',
                b'java.io.PipedWriter',
                b'java.io.FilterReader',
                b'java.io.FilterWriter',
                b'java.io.PushbackReader',
                b'java.io.PrintStream',
                b'java.io.PrintWriter',
                b'java.io.OutputStreamWriter',
                b'java.io.InputStreamReader',
                b'java.io.FileDescriptor',
                b'java.io.FilePermission',
                b'java.io.SerializeablePermission',
                b'java.io.ObjectStreamClass',
                b'java.io.ObjectStreamField',
                b'java.io.ObjectInput',
                b'java.io.ObjectOutput',
                b'java.io.ObjectInputStream',
                b'java.io.ObjectOutputStream',
                b'java.io.ObjectStreamConstants',
                b'java.io.ObjectStreamException',
                b'java.io.InvalidClassException',
                b'java.io.InvalidObjectException',
                b'java.io.NotActiveException',
                b'java.io.NotSerializableException',
                b'java.io.OptionalDataException',
                b'java.io.StreamCorruptedException',
                b'java.io.WriteAbortedException',
                b'java.io.SyncFailedException',
                b'java.io.UTFDataFormatException',
                b'java.io.UnsupportedEncodingException',
                b'java.io.InterruptedIOException',
                b'java.io.EOFException',
                b'java.io.FileNotFoundException',
                b'java.io.IOException',
                b'java.io.UncheckedIOException',
                b'java.io.Closeable',
                b'java.io.Flushable',
                b'java.io.AutoCloseable',
                b'java.io.FileFilter',
                b'java.io.FilenameFilter',
                b'java.io.Serializable',
                b'java.io.Externalizable',
                b'java.io.ObjectInputValidation',
                b'java.io.ObjectStreamConstants',
                b'java.io.ObjectStreamException',
                b'java.io.InvalidClassException',
                b'java.io.InvalidObjectException',
                b'java.io.NotActiveException',
                b'java.io.NotSerializableException',
                b'java.io.OptionalDataException',
                b'java.io.StreamCorruptedException',
                b'java.io.WriteAbortedException',
                b'java.io.SyncFailedException',
                b'java.io.UTFDataFormatException',
                b'java.io.UnsupportedEncodingException',
                b'java.io.InterruptedIOException',
                b'java.io.EOFException',
                b'java.io.FileNotFoundException',
                b'java.io.IOException',
                b'java.io.UncheckedIOException',
                b'java.io.Closeable',
                b'java.io.Flushable',
                b'java.io.AutoCloseable',
                b'java.io.FileFilter',
                b'java.io.FilenameFilter',
                b'java.io.Serializable',
                b'java.io.Externalizable',
                b'java.io.ObjectInputValidation',
            ]
            
            # Check each file for Metasploit signatures
            for file_name in files:
                try:
                    file_content = jar_zip.read(file_name)
                    
                    for signature in metasploit_signatures:
                        if signature in file_content:
                            found_signatures.append(signature.decode('utf-8', errors='ignore'))
                            score += 25  # High weight for binary signatures
                            
                except Exception:
                    continue
                    
        except Exception as e:
            pass
        
        return min(100, score)

    def _determine_payload_type(self, jar_zip):
        """Determine the type of payload"""
        try:
            # Get all files in the JAR
            files = jar_zip.namelist()
            
            for file_name in files:
                if file_name.endswith('.class') or file_name.endswith('.java'):
                    try:
                        file_content = jar_zip.read(file_name).decode('utf-8', errors='ignore')
                        
                        if 'meterpreter' in file_content.lower():
                            if 'reverse_tcp' in file_content.lower():
                                return 'Metasploit Java Reverse TCP Payload'
                            elif 'bind_tcp' in file_content.lower():
                                return 'Metasploit Java Bind TCP Payload'
                            elif 'reverse_https' in file_content.lower():
                                return 'Metasploit Java Reverse HTTPS Payload'
                            else:
                                return 'Metasploit Java Payload'
                        
                        if 'shell' in file_content.lower():
                            return 'Java Shell Payload'
                        
                        if 'exec' in file_content.lower():
                            return 'Java Command Execution Payload'
                        
                    except Exception:
                        continue
                        
        except Exception as e:
            pass
        
        return 'Java Payload'

    def _collect_indicators(self, analysis_details):
        """Collect all indicators from analysis details"""
        indicators = []
        
        # High-confidence patterns
        if analysis_details.get('high_confidence_score', 0) > 0:
            indicators.append(f"High-confidence Java payload patterns detected (score: {analysis_details['high_confidence_score']})")
        
        # Java patterns
        if analysis_details.get('java_score', 0) > 0:
            indicators.append(f"Suspicious Java patterns detected (score: {analysis_details['java_score']})")
        
        # Metasploit patterns
        if analysis_details.get('metasploit_score', 0) > 0:
            indicators.append(f"Metasploit payload patterns detected (score: {analysis_details['metasploit_score']})")
        
        # MANIFEST.MF analysis
        manifest_analysis = analysis_details.get('manifest_analysis', {})
        if manifest_analysis.get('score', 0) > 0:
            indicators.append(f"Suspicious MANIFEST.MF entries detected (score: {manifest_analysis['score']})")
        
        # Binary signature analysis
        if analysis_details.get('binary_signature_score', 0) > 0:
            indicators.append(f"Binary Metasploit signatures detected (score: {analysis_details['binary_signature_score']})")
        
        return indicators

    def display_result(self, result, file_path):
        """Display analysis result"""
        print(f"\n{self.colors.CYAN}🔍 JAR Payload Analysis: {os.path.basename(file_path)}{self.colors.RESET}")
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
            print(f"   High-Confidence Score: {details.get('high_confidence_score', 0)}/100")
            print(f"   Java Pattern Score: {details.get('java_score', 0)}/100")
            print(f"   Metasploit Score: {details.get('metasploit_score', 0)}/100")
            
            manifest_analysis = details.get('manifest_analysis', {})
            if manifest_analysis.get('score', 0) > 0:
                print(f"   MANIFEST.MF Score: {manifest_analysis['score']}/100")
            
            if details.get('binary_signature_score', 0) > 0:
                print(f"   Binary Signature Score: {details['binary_signature_score']}/100")
        
        if result['indicators']:
            print(f"\n{self.colors.YELLOW}⚠️  Suspicious Indicators:{self.colors.RESET}")
            for indicator in result['indicators']:
                print(f"   • {indicator}")
        else:
            print(f"\n{self.colors.GREEN}✅ No suspicious indicators found{self.colors.RESET}")
        
        return result
