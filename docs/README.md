# 📚 Metasploit Manager - Complete Documentation

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Core Modules](#core-modules)
4. [File Analysis System](#file-analysis-system)
5. [Payload Generation](#payload-generation)
6. [Database Management](#database-management)
7. [Legal and Ethical Guidelines](#legal-and-ethical-guidelines)
8. [Technical Implementation](#technical-implementation)
9. [Security Considerations](#security-considerations)
10. [Troubleshooting](#troubleshooting)

## Project Overview

**Metasploit Manager** is a comprehensive security testing framework designed for educational purposes and authorized penetration testing. The tool provides a unified interface for system verification, database management, payload generation, payload management, and advanced file analysis operations.

### Key Features

- **System Verification**: Check Metasploit installation and system requirements
- **Database Management**: Metasploit database initialization and management
- **Multi-Platform Payload Generation**: Windows, Linux, macOS, Android, Java, Web
- **Payload Management**: Connect to and manage active payloads
- **Advanced File Analysis**: Detection of embedded payloads and malware in 11 file types
- **Interactive Interface**: User-friendly command-line interface with ASCII art
- **Modular Architecture**: Extensible and maintainable codebase

### Supported Platforms

- **Windows**: EXE, DLL payloads
- **Linux**: ELF payloads
- **macOS**: Mach-O payloads
- **Android**: APK payloads
- **Java**: JAR payloads
- **Web**: PHP, JSP, ASPX payloads
- **Generic**: Binary, Python payloads

## Architecture

### System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Metasploit Manager                       │
├─────────────────────────────────────────────────────────────┤
│  Main Application (main.py)                                │
├─────────────────────────────────────────────────────────────┤
│  Core Modules                                               │
│  ├── System Check (check_system.py)                        │
│  ├── Database Management (metasploit_db.py)                │
│  ├── Payload Creation (create_payload.py)                  │
│  ├── Payload Management (manage_payload.py)                │
│  ├── File Analysis (file_analysis/)                        │
│  ├── Colors (colors.py)                                    │
│  ├── Exit Handler (exit_handler.py)                        │
│  └── Credits (credits.py)                                  │
├─────────────────────────────────────────────────────────────┤
│  File Analysis System                                       │
│  ├── File Analyzer (file_analyzer.py)                      │
│  └── Analyzers (analyzers/)                                │
│      ├── Python Analyzer (python_analyzer.py)              │
│      ├── EXE Analyzer (exe_analyzer.py)                    │
│      ├── PHP Analyzer (php_analyzer.py)                    │
│      ├── JSP Analyzer (jsp_analyzer.py)                    │
│      ├── ASPX Analyzer (aspx_analyzer.py)                  │
│      ├── APK Analyzer (apk_analyzer.py)                    │
│      ├── ELF Analyzer (elf_analyzer.py)                    │
│      ├── JAR Analyzer (jar_analyzer.py)                    │
│      ├── Mach-O Analyzer (macho_analyzer.py)               │
│      └── Binary Analyzer (bin_analyzer.py)                 │
├─────────────────────────────────────────────────────────────┤
│  Payload Generation System                                  │
│  ├── Windows Payloads (windows_payloads.py)                │
│  ├── Linux Payloads (linux_payloads.py)                    │
│  ├── macOS Payloads (macos_payloads.py)                    │
│  ├── Android Payloads (android_payloads.py)                │
│  ├── Java Payloads (java_payloads.py)                      │
│  └── Web Payloads (web_payloads.py)                        │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **User Input** → Main Application
2. **Menu Selection** → Module Router
3. **Module Execution** → Specific Functionality
4. **Result Processing** → Output Display
5. **User Feedback** → Continue/Exit

## Core Modules

### 1. System Check Module (`check_system.py`)

**Purpose**: Verify system requirements and Metasploit installation

**Functions**:
- Check Python version compatibility
- Verify Metasploit Framework installation
- Check required system tools (file, strings, objdump, readelf, unzip)
- Validate file permissions
- Test network connectivity
- Display system information

**Dependencies**:
- `msfvenom` command (Metasploit Framework)
- `file` command (file type detection)
- `strings` command (string extraction)
- `objdump` command (binary analysis)
- `readelf` command (ELF analysis)
- `unzip` command (archive extraction)

### 2. Database Management Module (`metasploit_db.py`)

**Purpose**: Initialize and manage Metasploit database

**Functions**:
- Initialize PostgreSQL database
- Start/stop database services
- Verify database connectivity
- Check database status
- Reset database if needed

**Dependencies**:
- PostgreSQL
- Metasploit Framework
- Database configuration files

### 3. Payload Creation Module (`create_payload.py`)

**Purpose**: Generate payloads for various platforms

**Functions**:
- Platform selection
- Payload type selection
- Parameter configuration
- Payload generation
- Configuration saving

**Supported Platforms**:
- Windows (EXE, DLL)
- Linux (ELF)
- macOS (Mach-O)
- Android (APK)
- Java (JAR)
- Web (PHP, JSP, ASPX)

### 4. Payload Management Module (`manage_payload.py`)

**Purpose**: Connect to and manage active payloads

**Functions**:
- List active payloads
- Connect to reverse payloads
- Start bind payloads
- Monitor payload status
- Handle payload connections

**Features**:
- Reverse TCP connections
- Bind TCP connections
- Payload configuration management
- Connection monitoring

### 5. File Analysis Module (`file_analysis/`)

**Purpose**: Analyze files for embedded payloads and malware

**Functions**:
- File type detection
- Payload signature analysis
- Binary content analysis
- String extraction
- Entropy analysis
- Obfuscation detection

**Supported File Types**:
- Python (.py)
- Windows Executable (.exe, .dll)
- PHP (.php)
- JSP (.jsp)
- ASPX (.aspx)
- Android APK (.apk)
- ELF (.elf)
- Java Archive (.jar)
- Mach-O (.macho)
- Binary (.bin)

## File Analysis System

### Architecture

The file analysis system uses a modular approach with dedicated analyzers for each file type:

```
File Analyzer (file_analyzer.py)
├── File Type Detection
├── Handler Selection
└── Analysis Dispatch
    ├── Python Analyzer
    ├── EXE Analyzer
    ├── PHP Analyzer
    ├── JSP Analyzer
    ├── ASPX Analyzer
    ├── APK Analyzer
    ├── ELF Analyzer
    ├── JAR Analyzer
    ├── Mach-O Analyzer
    └── Binary Analyzer
```

### Analysis Process

1. **File Input**: User selects file from `checkfiles/` directory
2. **Type Detection**: Determine file type using extension and magic bytes
3. **Handler Selection**: Route to appropriate analyzer
4. **Analysis Execution**: Run specific analysis methods
5. **Result Processing**: Calculate confidence score
6. **Output Display**: Show analysis results

### Analysis Methods

#### 1. Signature Detection
- **Metasploit Patterns**: Detect Metasploit-specific strings
- **Payload Signatures**: Identify common payload patterns
- **Shellcode Patterns**: Detect shellcode sequences
- **Obfuscation Patterns**: Identify obfuscated code

#### 2. Binary Analysis
- **Entropy Calculation**: Measure randomness/encryption
- **String Extraction**: Extract readable strings
- **Header Analysis**: Analyze file headers
- **Section Analysis**: Examine file sections

#### 3. Content Analysis
- **Base64 Decoding**: Decode and analyze Base64 content
- **Hex Decoding**: Decode and analyze hex content
- **Compression Detection**: Identify compressed content
- **Encryption Detection**: Detect encrypted content

### Confidence Scoring

Each analyzer uses a confidence scoring system:

- **0-30%**: Low confidence (likely clean)
- **31-60%**: Medium confidence (suspicious)
- **61-100%**: High confidence (likely infected)

**Threshold**: Files with confidence ≥ 30% are marked as "Infected"

### False Positive Mitigation

The system includes several mechanisms to reduce false positives:

1. **Legitimate Pattern Recognition**: Identify legitimate uses of suspicious functions
2. **Context Analysis**: Consider the context of suspicious patterns
3. **Import Analysis**: Check for legitimate imports
4. **Entropy Analysis**: Distinguish between legitimate encryption and obfuscation
5. **Signature Validation**: Verify payload signatures

## Payload Generation

### Supported Platforms

#### Windows Payloads
- **Reverse TCP**: Connect back to attacker
- **Bind TCP**: Listen for connections
- **Reverse HTTP**: HTTP-based communication
- **Reverse HTTPS**: HTTPS-based communication

#### Linux Payloads
- **Reverse TCP**: Connect back to attacker
- **Bind TCP**: Listen for connections
- **Reverse HTTP**: HTTP-based communication
- **Reverse HTTPS**: HTTPS-based communication

#### macOS Payloads
- **Reverse TCP**: Connect back to attacker
- **Bind TCP**: Listen for connections
- **Reverse HTTP**: HTTP-based communication
- **Reverse HTTPS**: HTTPS-based communication

#### Android Payloads
- **Reverse TCP**: Connect back to attacker
- **Bind TCP**: Listen for connections
- **Reverse HTTP**: HTTP-based communication
- **Reverse HTTPS**: HTTPS-based communication

#### Java Payloads
- **Reverse TCP**: Connect back to attacker
- **Bind TCP**: Listen for connections
- **Reverse HTTP**: HTTP-based communication
- **Reverse HTTPS**: HTTPS-based communication

#### Web Payloads
- **PHP**: PHP-based web shells
- **JSP**: Java Server Pages web shells
- **ASPX**: ASP.NET web shells

### Payload Configuration

Each payload is configured with:
- **LHOST**: Local host (attacker's IP)
- **LPORT**: Local port (attacker's port)
- **RHOST**: Remote host (target's IP)
- **RPORT**: Remote port (target's port)
- **Payload Type**: Specific payload variant
- **Encoder**: Optional encoding/obfuscation

### Payload Storage

Generated payloads are stored in:
- **Payload Files**: Actual payload executables
- **Configuration Files**: JSON configuration files
- **Handler Files**: Metasploit handler configurations

## Database Management

### Metasploit Database

The system manages a PostgreSQL database for Metasploit operations:

#### Database Functions
- **Initialization**: Set up database schema
- **Connection Management**: Handle database connections
- **Data Storage**: Store payload configurations
- **Query Operations**: Retrieve stored data
- **Maintenance**: Database cleanup and optimization

#### Database Schema
- **Payloads Table**: Store payload configurations
- **Sessions Table**: Track active sessions
- **Logs Table**: Store operation logs
- **Configs Table**: Store system configurations

### Database Operations

1. **Initialize Database**: Set up PostgreSQL and Metasploit database
2. **Start Services**: Start database and Metasploit services
3. **Verify Connection**: Test database connectivity
4. **Reset Database**: Clear and reinitialize database
5. **Stop Services**: Stop database and Metasploit services

## Legal and Ethical Guidelines

### ⚠️ **CRITICAL LEGAL DISCLAIMER**

**THIS TOOL IS FOR EDUCATIONAL AND TESTING PURPOSES ONLY!**

#### Prohibited Uses
- ❌ **Unauthorized Testing**: Never test systems without explicit permission
- ❌ **Malicious Activities**: Never use for illegal or harmful purposes
- ❌ **Production Systems**: Never test production or live systems
- ❌ **Real-World Targets**: Never test real-world targets without authorization
- ❌ **Illegal Activities**: Never use for any illegal activities

#### Authorized Uses
- ✅ **Educational Purposes**: Learning about cybersecurity
- ✅ **Authorized Testing**: Testing systems you own or have permission to test
- ✅ **Research**: Security research in controlled environments
- ✅ **Training**: Cybersecurity training and exercises
- ✅ **Isolated Environments**: Testing in isolated, controlled environments

### Legal Compliance

Users must:
1. **Obtain Authorization**: Get explicit written permission before testing
2. **Comply with Laws**: Follow all applicable laws and regulations
3. **Use Responsibly**: Use the tool ethically and responsibly
4. **Assume Liability**: Take full legal responsibility for their actions
5. **Report Issues**: Report any security issues responsibly

### Ethical Guidelines

1. **Responsible Disclosure**: Report vulnerabilities responsibly
2. **Privacy Protection**: Protect sensitive information
3. **Minimal Impact**: Minimize impact on target systems
4. **Documentation**: Document all testing activities
5. **Professional Conduct**: Maintain professional standards

## Technical Implementation

### Programming Language
- **Primary**: Python 3.8+
- **Standard Library**: Extensive use of Python standard library
- **External Dependencies**: Minimal external dependencies

### Key Libraries
- **os**: Operating system interface
- **sys**: System-specific parameters
- **subprocess**: Process management
- **json**: JSON data handling
- **re**: Regular expressions
- **hashlib**: Cryptographic hashing
- **base64**: Base64 encoding/decoding
- **pathlib**: Object-oriented filesystem paths

### System Requirements
- **Operating System**: Linux (tested on Parrot OS)
- **Python**: 3.8 or higher
- **Memory**: Minimum 2GB RAM
- **Storage**: Minimum 1GB free space
- **Network**: Internet connection for updates

### Dependencies
- **Metasploit Framework**: Required for payload generation
- **PostgreSQL**: Required for database operations
- **System Tools**: file, strings, objdump, readelf, unzip

### Performance Considerations
- **File Analysis**: Optimized for large files
- **Memory Usage**: Efficient memory management
- **Processing Speed**: Fast analysis algorithms
- **Storage**: Minimal storage requirements

## Security Considerations

### Input Validation
- **File Type Validation**: Verify file types before analysis
- **Path Validation**: Prevent path traversal attacks
- **Size Limits**: Limit file sizes for analysis
- **Content Validation**: Validate file content

### Output Sanitization
- **String Escaping**: Escape special characters in output
- **Path Sanitization**: Sanitize file paths
- **Content Filtering**: Filter sensitive information
- **Error Handling**: Secure error messages

### Access Control
- **File Permissions**: Proper file permissions
- **Directory Access**: Restricted directory access
- **Process Isolation**: Isolated process execution
- **Network Security**: Secure network communications

### Data Protection
- **Sensitive Data**: Protect sensitive information
- **Logging**: Secure logging practices
- **Storage**: Secure data storage
- **Transmission**: Secure data transmission

## Troubleshooting

### Common Issues

#### 1. Metasploit Not Found
**Problem**: `msfvenom` command not found
**Solution**: Install Metasploit Framework
```bash
sudo apt install metasploit-framework
```

#### 2. Database Connection Failed
**Problem**: Cannot connect to Metasploit database
**Solution**: Initialize database
```bash
sudo msfdb init
```

#### 3. Permission Denied
**Problem**: Permission denied errors
**Solution**: Run with sudo
```bash
sudo python3 main.py
```

#### 4. File Analysis Failed
**Problem**: File analysis errors
**Solution**: Check file permissions and format
```bash
chmod 644 checkfiles/your_file
```

#### 5. Payload Generation Failed
**Problem**: Payload generation errors
**Solution**: Check Metasploit installation and parameters
```bash
msfvenom --list payloads
```

### Debug Mode

Enable debug mode for detailed error information:
```bash
export DEBUG=1
python3 main.py
```

### Log Files

Check log files for detailed error information:
- **System Logs**: `/var/log/syslog`
- **Metasploit Logs**: `~/.msf4/logs/`
- **Application Logs**: Check console output

### Support

For technical support:
- **GitHub Issues**: https://github.com/MetaMops/MetaDox/issues
- **Discord**: https://discord.gg/KcuMUUAP5T
- **Email**: latifimods@gmail.com

---

**Remember: Use this tool responsibly and legally!** 🛡️
