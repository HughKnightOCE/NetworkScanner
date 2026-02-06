# Security Policy

## Reporting Security Vulnerabilities

We take security seriously. If you discover a security vulnerability in Network Scanner, please **do not** open a GitHub issue. Instead, please contact us privately.

### How to Report

1. **Email**: Send details to hugh.knight.oce@gmail.com
2. **Subject**: "Security Vulnerability in NetworkScanner"
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if you have one)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Investigation**: 1-2 weeks
- **Patch Release**: ASAP (typically within 2 weeks)
- **Public Disclosure**: After patch is released and available

## Supported Versions

| Version | Status | Security Updates |
|---------|--------|------------------|
| 2.0.x   | Current | ✅ Yes |
| 1.0.x   | Legacy | ❌ No |

## Known Security Considerations

### When Using Network Scanner

1. **Authorization**: Only scan networks you own or have explicit permission to scan
2. **Legal**: Network scanning may be illegal in your jurisdiction without proper authorization
3. **Credentials**: Never hardcode credentials in scan configurations
4. **Results**: Scan results contain sensitive network information - handle securely
5. **Logging**: Be careful with log files as they may contain security-sensitive data

### Dependency Security

Network Scanner uses:
- **scapy**: Actively maintained, security updates tracked
- Development tools: All sourced from official PyPI repositories

Run periodic updates:
```bash
pip install --upgrade -r requirements.txt
pip install --upgrade -r requirements-dev.txt
```

## Security Best Practices

### For Users

1. **Update Regularly**: Keep Python and dependencies up to date
2. **Permissions**: Run with minimal necessary privileges (not always as admin/root)
3. **Logging**: Review logs for unexpected activity
4. **Network**: Scan only from secure networks
5. **Storage**: Protect scan results - they contain network topology info

### For Developers

1. **Input Validation**: All user inputs are validated
2. **Error Handling**: Sensitive info not leaked in error messages
3. **Dependencies**: Regular security audits of dependencies
4. **Code Review**: Security-focused code reviews on all PRs
5. **Testing**: Security scenarios included in test suite

## Responsible Disclosure

We believe in responsible disclosure. If you:

- Find a vulnerability
- Have a fix
- Want to disclose responsibly

Please:
1. Report privately first
2. Allow time for a fix
3. Coordinate the disclosure date
4. Accept our thanks and recognition (if desired)

## Thank You

We appreciate your help in keeping Network Scanner secure!
