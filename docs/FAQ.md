# ❓ MetaDox FAQ

<div align="center">

![FAQ](https://img.shields.io/badge/FAQ-Frequently%20Asked%20Questions-orange?style=for-the-badge)

**🤔 Got Questions? We've Got Answers!**

</div>

---

## 🚀 **Installation**

### ❓ **What Python version do I need?**
**✅ Python 3.7+** (Python 3.9+ recommended for best performance)

```bash
python --version  # Check your version
```

### ❓ **Can I install without admin rights?**
**✅ MetaDox:** Yes, runs without root  
**⚠️ Metasploit:** Admin rights required for installation

### ❓ **Does it work on WSL?**
**✅ Yes!** Works perfectly on WSL2. Use Linux installation guide.

### ❓ **Docker support?**
**⏳ Coming soon!** Currently runs in containers, dedicated Dockerfile planned.

---

## 🔧 **Configuration**

### ❓ **Where's my config stored?**
**📁 Location:**
- **Linux/macOS:** `~/.metadox/config.json`
- **Windows:** `%USERPROFILE%\.metadox\config.json`

### ❓ **How do I edit the config?**
**🎛️ Options:**
1. Edit `config.json` directly
2. Use MetaDox menu (Option 7)

### ❓ **How do I change Metasploit path?**
```json
{
  "metasploit_path": "/opt/metasploit-framework"
}
```

---

## 🗄️ **Database Issues**

### ❓ **Database init fails?**
**🔍 Common causes:**
- PostgreSQL not running
- Permission issues  
- Port 5432 blocked

**🛠️ Solutions:**
```bash
# Check status
sudo systemctl status postgresql  # Linux
brew services list | grep postgresql  # macOS

# Start service
sudo systemctl start postgresql  # Linux
brew services start postgresql  # macOS

# Manual init
msfdb init
```

### ❓ **Can I use other databases?**
**❌ No** - Metasploit officially supports PostgreSQL only.

### ❓ **How do I reset the database?**
```bash
msfdb delete
msfdb init
```

---

## ⚡ **Metasploit Issues**

### ❓ **Metasploit not found?**
**🔍 Check PATH:**
```bash
echo $PATH        # Linux/macOS
which msfconsole  # Find location
```

**🛠️ Fix:** Add to PATH or set in config.

### ❓ **How do I update Metasploit?**
```bash
# Via MetaDox
python metadox.py → Option 9

# Manual
msfupdate
```

### ❓ **Metasploit won't start?**
**🔍 Check:**
- Database initialized?
- PostgreSQL running?
- Permissions correct?

**🛠️ Debug:**
```bash
msfconsole -v                    # Verbose mode
tail -f ~/.msf4/logs/framework.log  # Check logs
```

---

## 🐛 **Troubleshooting**

### ❓ **Permission denied errors?**
**✅ Solutions:**
- Don't run as root
- Check file permissions
- Ensure home directory write access

### ❓ **Module not found?**
```bash
python -c "import sys; print(sys.path)"  # Check Python path
pip install -r requirements.txt --force-reinstall  # Reinstall
```

### ❓ **MetaDox won't start?**
```bash
python --version     # Check Python version
pip list            # Check dependencies
python metadox.py --help  # Show help
```

### ❓ **Installation script fails?**
**📋 Check logs:**
- **Linux/macOS:** `/tmp/metadox_install.log`
- **Windows:** `%TEMP%\metadox_install.log`

**🔍 Verify:**
- Internet connection
- All dependencies installed

---

## 🔒 **Security**

### ❓ **Is MetaDox safe?**
**✅ Yes** - It's a management tool for Metasploit. Safety depends on proper usage:

- ✅ Use only for authorized testing
- ✅ Keep everything updated
- ✅ Use strong passwords
- ✅ Enable firewalls

### ❓ **Antivirus blocking it?**
**⚠️ Common** - Add MetaDox and Metasploit to antivirus exceptions.

### ❓ **How to prevent misuse?**
**🛡️ Security measures:**
- Strong authentication
- User access controls
- Log monitoring
- Network isolation

---

## 🌐 **Network**

### ❓ **Works behind firewall?**
**✅ Yes** - But Metasploit may need outbound connections for updates.

### ❓ **SSH usage?**
**✅ Works** - But some interactive features may be limited.

### ❓ **Which ports are used?**
**📡 Ports:**
- **PostgreSQL:** 5432
- **Metasploit Listener:** 4444 (default)
- **SSH:** 22 (if used)

---

## 📊 **Performance**

### ❓ **MetaDox runs slowly?**
**🔍 Check:**
- System resources (CPU, RAM, disk)
- Close other resource-heavy programs
- Network connection
- Use SSD for better performance

### ❓ **How much RAM needed?**
**💾 Requirements:**
- **Minimum:** 2 GB RAM
- **Optimal:** 4-8 GB RAM for large projects

### ❓ **Server deployment?**
**✅ Yes** - Can run on servers. Use SSH for remote access and consider security aspects.

---

## 🔄 **Updates**

### ❓ **How often should I update?**
**📅 Schedule:**
- **MetaDox:** When new features/bug fixes available
- **Metasploit:** Weekly or for critical updates
- **Python packages:** Monthly

### ❓ **Auto-updates?**
**⏳ Planned** - Currently use `--auto-setup` for quick reinstallation.

### ❓ **How to backup config?**
```bash
# Config backup
cp ~/.metadox/config.json ~/.metadox/config.json.backup

# Full backup
tar -czf metadox_backup.tar.gz ~/.metadox
```

---

## 🆘 **Support**

### ❓ **Where can I get help?**
**🆘 Support channels:**
1. 📖 Check this FAQ
2. 📚 Read the [documentation](README.md)
3. 🐛 Create [GitHub Issue](https://github.com/MetaMops/MetaDox/issues)
4. 💬 Contact us on Discord: @apt_start_latifi
5. 📖 Check [Metasploit docs](https://docs.metasploit.com/)

### ❓ **How do I report bugs?**
**🐛 Bug report process:**
1. 📋 Collect log files
2. 📝 Describe problem in detail
3. 💻 Mention OS and versions
4. 🎫 Create GitHub issue with all info

### ❓ **Can I contribute?**
**🤝 Yes!** We welcome:
- 💻 Code improvements
- 📚 Documentation
- 🐛 Bug reports
- ✨ Feature requests
- 🧪 Tests

---

## 📚 **Advanced Usage**

### ❓ **Script integration?**
**✅ Yes** - MetaDox supports command line:

```bash
python metadox.py --system-info      # System info only
python metadox.py --metasploit-info  # Metasploit info only
python metadox.py --install          # Install Metasploit
python metadox.py --test             # Test installation
```

### ❓ **CI/CD integration?**
**⏳ Not directly** - But command line features allow automation script integration.

### ❓ **API available?**
**⏳ Not currently** - REST API planned for future versions.

---

<div align="center">

## 🎯 **Still Need Help?**

[![Discord](https://img.shields.io/badge/Discord-@apt_start_latifi-7289DA?style=for-the-badge&logo=discord)](https://discord.gg/metadox)
[![GitHub Issues](https://img.shields.io/github/issues/MetaMops/MetaDox?style=for-the-badge)](https://github.com/MetaMops/MetaDox/issues)

**💬 Contact us on Discord or create a GitHub issue!**

</div>