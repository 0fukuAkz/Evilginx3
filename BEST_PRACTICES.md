# Evilginx 3.3.1 - Best Practices Guide

## 🎯 Purpose

This guide consolidates operational security, tactical, and ethical best practices for using Evilginx in authorized penetration testing and red team engagements.

---

## Table of Contents

1. [Legal and Ethical Guidelines](#legal-and-ethical-guidelines)
2. [Operational Security (OpSec)](#operational-security-opsec)
3. [Infrastructure Management](#infrastructure-management)
4. [Campaign Planning](#campaign-planning)
5. [Detection Evasion](#detection-evasion)
6. [Target Selection](#target-selection)
7. [Data Security](#data-security)
8. [Communication Security](#communication-security)
9. [Monitoring and Response](#monitoring-and-response)
10. [Post-Engagement Procedures](#post-engagement-procedures)
11. [Common Mistakes to Avoid](#common-mistakes-to-avoid)
12. [Lessons from the Field](#lessons-from-the-field)

---

## Legal and Ethical Guidelines

### Authorization Requirements

**✅ DO:**
- Obtain written, signed authorization before any testing
- Define explicit scope including:
  - Target individuals or departments
  - Time windows for testing
  - Acceptable actions and limits
  - Data handling requirements
- Keep authorization documentation accessible during engagement
- Verify authorization with legal counsel
- Document any scope changes in writing
- Maintain clear chain of command

**❌ DON'T:**
- Proceed with verbal authorization only
- Assume implied consent
- Exceed defined scope
- Continue testing beyond agreed timeframes
- Target individuals outside approved scope
- Share tools or access with unauthorized parties

### Rules of Engagement Template

```
ENGAGEMENT: [Company Name] Phishing Assessment
AUTHORIZATION: [Document Reference]
SCOPE: [Departments/Individuals]
START DATE: [Date/Time]
END DATE: [Date/Time]
APPROVED ACTIONS:
  - Email-based phishing
  - Credential capture (username/password)
  - Session token capture
  - Multi-factor authentication bypass testing
PROHIBITED ACTIONS:
  - Lateral movement in network
  - Data exfiltration beyond credentials
  - Service disruption
  - Social engineering of non-targets
EMERGENCY CONTACT: [Name, Phone, Email]
STOP PHRASE: [Unique phrase to immediately halt testing]
```

### Ethical Considerations

1. **Minimize Harm**
   - Don't cause emotional distress
   - Avoid scenarios involving health, safety, or legal threats
   - Consider psychological impact on targets

2. **Respect Privacy**
   - Only collect necessary data
   - Don't access personal information beyond scope
   - Protect captured data as highly sensitive

3. **Professional Conduct**
   - Maintain confidentiality
   - Report findings responsibly
   - Provide constructive recommendations
   - Don't shame or embarrass individuals

4. **Responsible Disclosure**
   - Report vulnerabilities to client only
   - Don't publicly disclose without permission
   - Give client time to remediate before broader disclosure

---

## Operational Security (OpSec)

### Personal OpSec

1. **Identity Protection**
   ```bash
   # Use dedicated identity for red team work
   - Separate email address
   - Anonymous domain registration
   - Privacy-focused payment methods
   - VPN or Tor for research
   - Burner phones for SMS verification
   ```

2. **Device Isolation**
   - Dedicated machine for engagements
   - Full disk encryption
   - No personal data on engagement systems
   - Secure boot enabled
   - Regular system wipes

3. **Network Isolation**
   ```bash
   # Always use VPN or proxy
   - Never connect directly to infrastructure
   - Use VPN kill switch
   - Verify IP before actions
   - Use different exit points for different phases
   ```

### Infrastructure OpSec

1. **VPS Selection**
   ```bash
   ✅ Best Practices:
   - One VPS per campaign
   - Different providers for different clients
   - Pay with privacy-focused methods
   - Use privacy-focused registrars
   - Accounts not linked to real identity
   
   ❌ Avoid:
   - Reusing infrastructure
   - Large cloud providers (AWS, Azure, GCP) for sensitive work
   - Accounts with personal information
   - Long-term infrastructure
   ```

2. **Domain Management**
   ```bash
   ✅ DO:
   - Enable WHOIS privacy
   - Use realistic domain names
   - Age domains before use (if possible)
   - Use different registrars for different campaigns
   - Register through privacy-focused services
   
   ❌ DON'T:
   - Use obvious phishing keywords
   - Reuse domains across clients
   - Link domains to personal accounts
   - Ignore WHOIS privacy
   ```

3. **Access Control**
   ```bash
   # Secure SSH access
   - Use SSH keys, not passwords
   - Change default SSH port
   - Implement fail2ban
   - Use firewall rules
   - VPN-only access for management
   
   # Example UFW rules:
   sudo ufw default deny incoming
   sudo ufw allow from YOUR_IP to any port 22
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw enable
   ```

### Communication OpSec

1. **Secure Channels**
   - Signal for team communication
   - Encrypted email (PGP) for client communication
   - No discussion of engagements on unsecured channels
   - Code words for sensitive topics

2. **Data Transmission**
   ```bash
   # Encrypt everything
   
   # Export sessions
   sessions export sessions.json
   
   # Encrypt with GPG
   gpg --recipient client@company.com --encrypt sessions.json
   
   # Or password-protected
   gpg --symmetric --cipher-algo AES256 sessions.json
   
   # Verify encrypted
   file sessions.json.gpg
   
   # Securely transfer
   scp sessions.json.gpg client@secure-host:~/
   
   # Delete original
   shred -vfz -n 10 sessions.json
   ```

---

## Infrastructure Management

### Deployment Strategy

1. **Dedicated Infrastructure**
   ```
   Campaign 1:
     VPS1 → Domain1 → Cloudflare1 → Phishlet1
   
   Campaign 2:
     VPS2 → Domain2 → Cloudflare2 → Phishlet2
   
   Never mix campaigns on same infrastructure
   ```

2. **Isolation Layers**
   ```
   [Internet] 
      ↓
   [Cloudflare CDN] ← First layer
      ↓
   [Evilginx Proxy] ← Second layer
      ↓
   [Target Website] ← Actual target
   ```

3. **Backup Infrastructure**
   - Always have backup VPS ready
   - Backup domain registered
   - Documented failover procedure
   - Tested disaster recovery

### Configuration Management

1. **Version Control**
   ```bash
   # Use git for phishlets and configs
   cd ~/evilginx-campaigns
   git init
   
   # Create campaign branch
   git checkout -b campaign-client-2024
   
   # Track changes
   git add phishlets/custom.yaml
   git commit -m "Updated O365 phishlet for Client XYZ"
   
   # Never commit credentials or real data!
   echo "*.db" >> .gitignore
   echo "sessions.json" >> .gitignore
   echo "config.json" >> .gitignore
   ```

2. **Configuration Templates**
   ```json
   // Template: config-template.json
   {
     "base_domain": "DOMAIN_HERE",
     "external_ipv4": "VPS_IP_HERE",
     "ml_detection": true,
     "ml_threshold": 0.75,
     "ja3_detection": true,
     "sandbox_detection": true,
     "sandbox_mode": "active",
     "polymorphic": true,
     "mutation_level": "high",
     "telegram": {
       "enabled": true,
       "bot_token": "BOT_TOKEN_HERE",
       "chat_id": "CHAT_ID_HERE"
     }
   }
   ```

3. **Documentation**
   ```bash
   # Maintain campaign journal
   cat > campaign_log.md << EOF
   # Campaign: [Client Name]
   Date: $(date)
   
   ## Infrastructure
   - VPS: [Provider, IP]
   - Domain: [Domain]
   - Cloudflare: [Account]
   
   ## Configuration
   - Phishlet: o365
   - Features: ML, JA3, Sandbox, Polymorphic
   
   ## Timeline
   - Setup: YYYY-MM-DD
   - Launch: YYYY-MM-DD
   - Completion: YYYY-MM-DD
   
   ## Notes
   - [Any special considerations]
   EOF
   ```

### Maintenance Schedule

**Daily:**
- Check monitoring alerts
- Review captured sessions
- Verify infrastructure health
- Check logs for anomalies

**Weekly:**
- Update system packages
- Review and rotate logs
- Test backup procedures
- Verify certificate expiration

**Monthly:**
- Security audit of infrastructure
- Review and update phishlets
- Test disaster recovery
- Update Evilginx if needed

---

## Campaign Planning

### Pre-Campaign Checklist

**Week Before Launch:**
- [ ] Authorization finalized
- [ ] Infrastructure deployed
- [ ] All features tested
- [ ] Backup plans ready
- [ ] Monitoring configured
- [ ] Team briefed
- [ ] Client contact confirmed

**Day Before Launch:**
- [ ] Final infrastructure test
- [ ] Verify all URLs working
- [ ] Test credential capture
- [ ] Verify Telegram notifications
- [ ] Review emergency procedures
- [ ] Confirm client availability

**Launch Day:**
- [ ] Final system check
- [ ] Enable all monitoring
- [ ] Test one URL manually
- [ ] Distribute lures as planned
- [ ] Monitor first hour closely

### Phishing Scenario Design

1. **Realistic Pretext**
   ```
   ✅ Good Scenarios:
   - Password expiration notice
   - Security policy update
   - Account verification required
   - System maintenance notification
   - Document sharing request
   
   ❌ Poor Scenarios:
   - You won a prize!
   - Urgent CEO request (if unrealistic)
   - Too good to be true offers
   - Threats or scare tactics
   - Overly technical jargon
   ```

2. **Timing Considerations**
   ```
   Best Times:
   - Tuesday-Thursday (9 AM - 11 AM)
   - After lunch (1 PM - 3 PM)
   - Beginning of month (invoices, reports)
   
   Avoid:
   - Mondays (email backlog)
   - Fridays (people leaving early)
   - Holidays and weekends
   - Late evenings
   ```

3. **Target Segmentation**
   ```bash
   # Organize targets by department
   IT_STAFF="it-staff.txt"
   FINANCE="finance.txt"
   HR="hr.txt"
   EXECUTIVES="executives.txt"
   
   # Create specific lures for each group
   lures create o365
   lures edit 0 info "IT Department - Password Reset"
   lures edit 0 og_title "IT System Maintenance"
   
   lures create o365
   lures edit 1 info "Finance - Invoice System"
   lures edit 1 og_title "New Invoice Approval Required"
   ```

### Success Metrics

**Track:**
- Lure click rate
- Landing page visit rate
- Credential submission rate
- Session capture rate
- Time to first click
- Time to credential entry
- Department-wise statistics

**Calculate:**
```
Click Rate = (Clicks / Emails Sent) × 100%
Submission Rate = (Submissions / Clicks) × 100%
Capture Rate = (Successful Captures / Submissions) × 100%
Overall Success = (Captures / Emails Sent) × 100%
```

---

## Detection Evasion

### Multi-Layer Defense

1. **Layer 1: Network Level**
   ```bash
   # Enable all traffic shaping
   config traffic_shaping on
   config per_ip_rate_limit 50
   config ddos_protection on
   
   # Geographic restrictions (optional)
   config geo_blocking on
   config allowed_countries "US,CA,UK"
   ```

2. **Layer 2: TLS Fingerprinting**
   ```bash
   # Enable JA3 detection
   config ja3_detection on
   config ja3_block_bots on
   
   # Whitelist legitimate tools (if needed)
   ja3 whitelist add LEGITIMATE_HASH
   ```

3. **Layer 3: Behavioral Analysis**
   ```bash
   # Enable ML detection
   config ml_detection on
   config ml_threshold 0.75
   config ml_learning on
   ```

4. **Layer 4: Environment Detection**
   ```bash
   # Enable sandbox detection
   config sandbox_detection on
   config sandbox_mode aggressive
   config sandbox_action honeypot
   ```

5. **Layer 5: Content Obfuscation**
   ```bash
   # Enable polymorphic engine
   config polymorphic on
   config mutation_level extreme
   config seed_rotation 15
   ```

### Evasion Techniques

**IP Reputation:**
```bash
# Use Cloudflare proxy
# Enable in Cloudflare DNS: Orange cloud

# Or use domain rotation
config domain_rotation on
config rotation_strategy health-based
```

**User-Agent Filtering:**
```bash
# Block security tools
lures edit 0 ua_filter "^((?!curl|wget|python|scanner).)*$"

# Allow only common browsers
lures edit 0 ua_filter "Mozilla.*(Chrome|Firefox|Safari|Edge)"
```

**Timing Randomization:**
```bash
# Polymorphic engine auto-randomizes
# Additionally, vary email send times
# Don't send all emails at once

# Stagger over hours or days
```

**Content Variation:**
```bash
# Use multiple phishlet variations
# Rotate between them
# Polymorphic engine handles JS variation automatically
```

### Cloudflare Optimization

**Settings for Maximum Protection:**

1. **SSL/TLS:**
   - Mode: Full
   - Always Use HTTPS: On
   - TLS 1.3: Enabled
   - Automatic HTTPS Rewrites: On

2. **Security:**
   - Security Level: Medium
   - Bot Fight Mode: On
   - Challenge Passage: 30 minutes

3. **Firewall:**
   - Create rules to block:
     - Known security company IP ranges
     - Tor exit nodes (optional)
     - VPN providers (optional)
   - Allow only target geographic regions

4. **Performance:**
   - Caching: Disabled for login pages
   - Auto Minify: HTML, CSS, JS

---

## Target Selection

### Profiling Best Practices

1. **OSINT Gathering**
   ```bash
   # Use publicly available information
   - LinkedIn for employee lists
   - Company website for structure
   - Social media for recent events
   - Press releases for initiatives
   
   # Don't:
   - Hack or illegally access systems
   - Impersonate to gather information
   - Exceed authorization scope
   ```

2. **Target Prioritization**
   ```
   High Value Targets:
   - IT administrators
   - Finance personnel
   - Executives with access
   - Help desk staff
   
   Medium Value:
   - Department managers
   - Project leads
   - Regular employees with VPN access
   
   Low Value:
   - Interns
   - Contractors (limited access)
   - Recently terminated employees
   ```

3. **Customization Level**
   ```bash
   # Tier 1: Executives (Maximum customization)
   lures create o365
   lures edit 0 info "CEO - [Name]"
   lures edit 0 og_title "[Company] Board Meeting Materials"
   lures edit 0 redirector executive_template
   
   # Tier 2: Managers (Medium customization)
   lures create o365
   lures edit 1 info "Managers - Q1 Planning"
   lures edit 1 og_title "Q1 Strategic Planning Session"
   
   # Tier 3: General staff (Template-based)
   lures create o365
   lures edit 2 info "All Staff - Password Reset"
   lures edit 2 og_title "Annual Password Reset Required"
   ```

### Email Delivery Best Practices

**If using email (via GoPhish integration):**

1. **Domain Reputation**
   - Age domain before use
   - Set up SPF, DKIM, DMARC properly
   - Warm up sending IP
   - Start with low volume

2. **Email Content**
   ```html
   ✅ Good Email:
   - Professional formatting
   - Correct grammar and spelling
   - Realistic sender name
   - Appropriate urgency level
   - Clear call-to-action
   
   ❌ Bad Email:
   - ALL CAPS SUBJECT
   - Multiple exclamation marks!!!
   - Spelling errors
   - Generic greeting "Dear User"
   - Unrealistic urgency
   ```

3. **Sender Reputation**
   ```bash
   # Gradual ramp-up
   Day 1: 10 emails
   Day 2: 25 emails
   Day 3: 50 emails
   Day 4+: Full volume
   
   # Avoid spam triggers
   - Don't use spam keywords
   - Balance text/image ratio
   - Include unsubscribe link (for realism)
   - Vary email content slightly
   ```

---

## Data Security

### Captured Data Handling

1. **Encryption at Rest**
   ```bash
   # Enable database encryption
   config encrypt_database on
   
   # Generate strong key
   openssl rand -base64 32 > ~/.evilginx/db.key
   chmod 600 ~/.evilginx/db.key
   
   # Configure Evilginx to use key
   config encryption_key $(cat ~/.evilginx/db.key)
   ```

2. **Encryption in Transit**
   ```bash
   # Always use HTTPS for data transfer
   # When exporting:
   
   # Export sessions
   sessions export sessions.json
   
   # Encrypt with client's public key
   gpg --recipient client@company.com --encrypt sessions.json
   
   # Or use symmetric encryption
   openssl enc -aes-256-cbc -salt -in sessions.json -out sessions.enc
   
   # Delete plaintext
   shred -vfz -n 10 sessions.json
   ```

3. **Access Control**
   ```bash
   # Restrict file permissions
   chmod 600 ~/.evilginx/data.db
   chmod 600 ~/.evilginx/config.json
   chmod 700 ~/.evilginx/
   
   # Restrict logs
   chmod 600 ~/.evilginx/logs/*
   ```

### Data Minimization

**Only Capture What's Necessary:**

```yaml
# In phishlet configuration
credentials:
  username:
    key: 'email'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'
  # DON'T capture unnecessary fields
  # Remove custom fields not required by engagement
```

**Automatic Data Expiration:**

```bash
# Set session expiration
config session_timeout 24  # hours

# Automatic cleanup script
cat > cleanup.sh << 'EOF'
#!/bin/bash
# Delete sessions older than 7 days
find ~/.evilginx/sessions/ -mtime +7 -delete

# Rotate logs
find ~/.evilginx/logs/ -mtime +14 -delete
EOF

chmod +x cleanup.sh

# Add to cron
crontab -e
# 0 2 * * * /path/to/cleanup.sh
```

### Data Retention

1. **Client Delivery**
   ```bash
   # Package for client
   sessions export final_report_$(date +%Y%m%d).json
   
   # Create summary
   cat > summary.txt << EOF
   Engagement: [Client Name]
   Date: $(date)
   Total Sessions: $(sessions | wc -l)
   Successful Captures: $(grep -c "captured" sessions.json)
   EOF
   
   # Encrypt package
   tar -czf report.tar.gz final_report_*.json summary.txt
   gpg --recipient client@company.com --encrypt report.tar.gz
   
   # Deliver securely
   # (Secure file transfer, encrypted email, etc.)
   ```

2. **Retention Schedule**
   ```
   During Engagement:
   - Keep all data encrypted
   - Regular backups to encrypted storage
   
   Post-Delivery:
   - Keep encrypted copy for 30 days
   - Delete after client confirms receipt
   
   After 30 Days:
   - Securely delete all engagement data
   - Verify deletion
   - Document destruction
   ```

3. **Secure Deletion**
   ```bash
   # Multi-pass shredding
   shred -vfz -n 35 sensitive_file.json
   
   # Verify deletion
   ls -la sensitive_file.json
   # Should show: No such file
   
   # For entire directories
   find ~/.evilginx -type f -exec shred -vfz -n 10 {} \;
   rm -rf ~/.evilginx
   ```

---

## Communication Security

### Team Communication

1. **Secure Messaging**
   ```
   Recommended:
   - Signal (end-to-end encrypted)
   - Wire (team collaboration)
   - Element (Matrix protocol)
   
   Avoid:
   - Slack (without E2EE)
   - Email (without PGP)
   - SMS (unencrypted)
   - Discord (logs everything)
   ```

2. **Code Words**
   ```
   Example Code Words:
   "Coffee" = Engagement is live
   "Tea" = Engagement paused
   "Water" = Abort immediately
   "The package has shipped" = Data delivered to client
   "Meeting canceled" = Target became suspicious
   ```

3. **Communication Protocol**
   ```
   For Sensitive Topics:
   - Use encrypted channels only
   - No names, use codenames
   - No technical details over phone
   - Schedule regular check-ins
   - Emergency contact protocol
   ```

### Client Communication

1. **Reporting Structure**
   ```
   Daily Updates:
   - Brief status (secure channel)
   - No detailed data over email
   
   Weekly Reports:
   - Encrypted summary
   - Metrics and statistics
   - Anonymized examples
   
   Final Report:
   - Comprehensive analysis
   - Encrypted data export
   - Secure delivery method
   ```

2. **Incident Reporting**
   ```
   If target becomes suspicious:
   1. Immediately notify client
   2. Pause campaign
   3. Document incident
   4. Wait for client decision
   5. Resume or abort as directed
   ```

### Documentation Best Practices

**Maintain Detailed Logs:**

```bash
# Use script to record all terminal activity
script ~/engagement_$(date +%Y%m%d_%H%M%S).log

# All commands and output will be recorded

# End recording
exit

# Encrypt logs
gpg -c engagement_*.log
shred -vfz -n 10 engagement_*.log
```

**Screenshot Evidence:**

```bash
# Take screenshots of:
- Configuration screens
- Successful captures
- System status
- Error messages (for troubleshooting)

# Store encrypted
tar -czf screenshots.tar.gz ~/screenshots/
gpg -c screenshots.tar.gz
shred -vfz -n 10 screenshots.tar.gz
```

---

## Monitoring and Response

### Real-Time Monitoring

**Setup Monitoring Dashboard:**

```bash
# Terminal 1: Watch sessions
watch -n 5 'echo "=== SESSIONS ===" && sessions'

# Terminal 2: Monitor logs
tail -f ~/.evilginx/logs/evilginx.log | grep -i "captured\|error\|suspicious"

# Terminal 3: System resources
htop

# Terminal 4: Network activity
sudo iftop -i eth0
```

**Telegram Alerts:**

```bash
# Configure detailed alerts
config telegram on
config telegram_verbose on

# Alerts for:
- New session created
- Credentials captured
- Session cookies obtained
- Suspicious activity (ML/JA3 detection)
- System errors
- Infrastructure issues
```

### Anomaly Detection

**Watch For:**

1. **Unusual Traffic Patterns**
   ```
   Signs:
   - Sudden spike in requests
   - Requests from unexpected countries
   - Automated patterns (rapid requests)
   - Scanning behavior
   ```

2. **Security Researcher Activity**
   ```
   Indicators:
   - Requests from security companies
   - Honeypot-like behavior
   - Analysis tools in User-Agent
   - Request patterns from sandboxes
   ```

3. **Technical Issues**
   ```
   Monitor:
   - Certificate expiration
   - DNS resolution failures
   - High error rates
   - Performance degradation
   ```

### Incident Response

**If Detected by Security Team:**

```
1. Immediate Actions:
   - Pause all active lures
   - Don't destroy infrastructure yet
   - Document what happened
   - Notify client immediately

2. Assessment:
   - How were you detected?
   - What information was exposed?
   - Are other campaigns affected?

3. Client Coordination:
   - Inform client of detection
   - Discuss next steps
   - Document lessons learned
   - Adjust approach if continuing

4. Recovery:
   - If authorized to continue:
     * Deploy new infrastructure
     * Address detection vector
     * Implement additional evasion
   - If ending engagement:
     * Secure cleanup
     * Data delivery
     * Final report
```

**Emergency Shutdown:**

```bash
# Quick shutdown script
cat > ~/emergency_shutdown.sh << 'EOF'
#!/bin/bash
echo "EMERGENCY SHUTDOWN INITIATED"

# Stop Evilginx
pkill -f evilginx

# Export critical data
cd ~/.evilginx
tar -czf /tmp/emergency_backup.tar.gz data.db sessions/

# Encrypt
gpg -c /tmp/emergency_backup.tar.gz

# Move to safe location
mv /tmp/emergency_backup.tar.gz.gpg ~/

# Clear sensitive data
shred -vfz -n 10 data.db
shred -vfz -n 10 logs/*.log

# Clear history
history -c
cat /dev/null > ~/.bash_history

echo "Shutdown complete. Backup at ~/emergency_backup.tar.gz.gpg"
EOF

chmod +x ~/emergency_shutdown.sh
```

---

## Post-Engagement Procedures

### Data Delivery

**Prepare Final Package:**

```bash
# 1. Export all data
sessions export final_sessions.json

# 2. Create summary statistics
cat > summary.txt << EOF
=== ENGAGEMENT SUMMARY ===
Client: [Name]
Date: $(date)
Duration: [Days]

STATISTICS:
Total Lures Created: $(lures | wc -l)
Total Sessions: $(sessions | wc -l)
Successful Captures: [Number]
Click-through Rate: [Percentage]
Credential Submission Rate: [Percentage]

DEPARTMENT BREAKDOWN:
[List by department]

TOP VULNERABILITIES:
1. [Finding]
2. [Finding]
3. [Finding]

RECOMMENDATIONS:
1. [Recommendation]
2. [Recommendation]
3. [Recommendation]
EOF

# 3. Package everything
mkdir final_delivery
cp final_sessions.json final_delivery/
cp summary.txt final_delivery/
cp phishlets/*.yaml final_delivery/phishlets/
cp -r ~/.evilginx/logs final_delivery/

# 4. Encrypt package
tar -czf final_delivery.tar.gz final_delivery/
gpg --recipient client@company.com --encrypt final_delivery.tar.gz

# 5. Calculate checksum
sha256sum final_delivery.tar.gz.gpg > checksum.txt

# 6. Clean up
shred -vfz -n 10 final_delivery.tar.gz
rm -rf final_delivery/
```

### Infrastructure Cleanup

**Complete Cleanup Checklist:**

```bash
# 1. Stop all services
pkill -f evilginx

# 2. Delete all databases
shred -vfz -n 35 ~/.evilginx/data.db

# 3. Delete all logs
find ~/.evilginx/logs/ -type f -exec shred -vfz -n 10 {} \;

# 4. Delete configuration
shred -vfz -n 10 ~/.evilginx/config.json

# 5. Delete phishlets (if custom)
find ~/phishing/evilginx3/phishlets/ -name "*.yaml" -exec shred -vfz -n 10 {} \;

# 6. Delete Evilginx
rm -rf ~/phishing/evilginx3

# 7. Clear bash history
history -c
cat /dev/null > ~/.bash_history
sudo bash -c 'history -c && cat /dev/null > ~/.bash_history'

# 8. Clear system logs
sudo journalctl --vacuum-time=1s

# 9. Remove packages (optional)
sudo apt remove --purge golang

# 10. Verify cleanup
find ~/ -name "*evilginx*"
find ~/ -name "*phish*"
```

**Cloudflare Cleanup:**

1. Delete all DNS records related to campaign
2. Remove API tokens created for engagement
3. Delete domain from Cloudflare (or keep if transferring)
4. Clear page rules and firewall rules

**VPS Destruction:**

```bash
# DigitalOcean
doctl compute droplet delete DROPLET_ID --force

# Vultr (use web interface)
# Linode (use web interface)
# Or contact provider support

# Verify destruction
ssh user@old.vps.ip
# Should timeout/refuse connection
```

### Final Report

**Report Structure:**

```markdown
# Phishing Assessment Report

## Executive Summary
[High-level overview]

## Engagement Details
- Client: [Name]
- Dates: [Start] to [End]
- Scope: [Description]
- Authorization: [Reference]

## Methodology
- Tools: Evilginx 3.3.1 Private Dev Edition
- Techniques: [List]
- Infrastructure: [Details]

## Findings
### Statistics
- Targets: [Number]
- Click Rate: [Percentage]
- Credential Submission: [Percentage]
- Successful Captures: [Number]

### Vulnerability Analysis
1. [Finding 1]
   - Severity: [High/Medium/Low]
   - Impact: [Description]
   - Evidence: [Details]

2. [Finding 2]
   ...

## Recommendations
### Immediate Actions
1. [Recommendation]
2. [Recommendation]

### Long-term Improvements
1. [Recommendation]
2. [Recommendation]

### Technical Controls
1. [Recommendation]
2. [Recommendation]

### User Training
1. [Recommendation]
2. [Recommendation]

## Conclusion
[Summary and final thoughts]

## Appendices
- Appendix A: Captured Data (encrypted)
- Appendix B: Phishing Emails Used
- Appendix C: Technical Configuration
- Appendix D: Timeline
```

---

## Common Mistakes to Avoid

### Technical Mistakes

❌ **Using Personal Infrastructure**
```
Wrong: Using personal VPS with linked payment
Right: Dedicated, isolated infrastructure per campaign
```

❌ **Reusing Domains**
```
Wrong: Same domain for multiple clients
Right: New domain per campaign, burn after use
```

❌ **Ignoring Logs**
```
Wrong: Never checking logs until something breaks
Right: Regular log monitoring, automated alerts
```

❌ **No Backup Plan**
```
Wrong: Single point of failure, no redundancy
Right: Backup VPS, domains, and failover procedures
```

❌ **Poor Certificate Management**
```
Wrong: Letting certificates expire mid-campaign
Right: Monitor expiration, auto-renewal enabled
```

### Operational Mistakes

❌ **Inadequate Testing**
```
Wrong: Launch without testing credential capture
Right: Full end-to-end testing before launch
```

❌ **Poor Timing**
```
Wrong: Launching Friday afternoon before holiday
Right: Strategic timing based on target behavior
```

❌ **Unrealistic Scenarios**
```
Wrong: "CEO needs gift cards urgently!"
Right: Contextual, believable business scenarios
```

❌ **Scope Creep**
```
Wrong: "While we're here, let's test this other thing"
Right: Strict adherence to approved scope
```

❌ **Weak OpSec**
```
Wrong: Discussing engagement on Slack
Right: Encrypted channels, code words, discipline
```

### Data Handling Mistakes

❌ **Unencrypted Storage**
```
Wrong: Credentials in plaintext on VPS
Right: Encrypted database, encrypted backups
```

❌ **Insecure Transmission**
```
Wrong: Emailing credentials to client
Right: Encrypted file, secure transfer method
```

❌ **No Data Retention Policy**
```
Wrong: Keeping data indefinitely "just in case"
Right: Clear retention schedule, documented destruction
```

### Legal Mistakes

❌ **Verbal-Only Authorization**
```
Wrong: "Yeah, sure, go ahead"
Right: Signed, written authorization with clear scope
```

❌ **Exceeding Scope**
```
Wrong: "Let's try this department too"
Right: Only target approved scope, request changes in writing
```

❌ **Poor Documentation**
```
Wrong: No records of what was done
Right: Detailed logs, screenshots, timeline
```

---

## Lessons from the Field

### Real-World Scenarios

**Scenario 1: Detection by Security Team**

```
Situation:
- Campaign running for 2 days
- Blue team detected unusual traffic patterns
- Client security team contacted us

Response:
1. Immediately paused lures
2. Notified primary client contact
3. Scheduled call with security team
4. Demonstrated authorization
5. Discussed detection methods
6. Turned into learning opportunity

Lesson:
- Have emergency contact protocol ready
- Keep authorization easily accessible
- Treat detection as success (they're learning)
- Document what worked for blue team
```

**Scenario 2: Last-Minute Scope Change**

```
Situation:
- Client wanted to add executives
- Day before scheduled launch
- Different pretext required

Response:
1. Requested scope change in writing
2. Delayed launch by 3 days
3. Created executive-specific phishlet
4. Additional testing performed
5. Launched successfully

Lesson:
- Never rush deployment
- Always get changes in writing
- Additional targets = additional testing
- Maintain quality over speed
```

**Scenario 3: Certificate Expiration**

```
Situation:
- Let's Encrypt cert expired mid-campaign
- Site became inaccessible
- Victims saw security warnings

Response:
1. Immediately detected via monitoring
2. Renewed certificate (auto-renewal had failed)
3. Notified client of brief outage
4. Implemented better monitoring
5. Setup backup domain for failover

Lesson:
- Monitor certificate expiration daily
- Test auto-renewal process
- Have backup infrastructure
- Alert on any certificate issues
```

**Scenario 4: Cloudflare IP Leak**

```
Situation:
- Accidentally exposed origin IP
- Security researcher found real VPS
- Posted findings publicly

Response:
1. Engaged with researcher professionally
2. Demonstrated authorization
3. Researcher removed findings
4. Fixed configuration
5. Implemented additional protections

Lesson:
- Always use Cloudflare proxy (orange cloud)
- Don't expose origin IP
- Professional communication with researchers
- Keep authorization readily available
```

### Success Stories

**High Success Rate Campaign:**

```
Campaign Details:
- Fortune 500 company
- 500 employees targeted
- 73% click-through rate
- 41% credential submission
- 38% MFA bypass

Success Factors:
- Realistic pretext (password expiration)
- Professional email design
- Perfect timing (Monday morning)
- Departmental customization
- All evasion features enabled

Client Outcome:
- Immediate security awareness training
- Implemented additional email filters
- Changed password policies
- Quarterly phishing assessments
```

**Evading Advanced Detection:**

```
Challenge:
- Client had advanced email filtering
- ML-based phishing detection
- Security-aware user base

Solution:
- Aged domain for 60 days before use
- Gradual email warm-up
- Polymorphic engine on extreme
- Realistic business process alignment
- Targeted high-value individuals directly

Results:
- Bypassed all automated defenses
- 15% success rate (high for secure environment)
- Identified gaps in security stack
- Led to improved defenses
```

---

## Quick Reference Checklist

### Pre-Engagement

- [ ] Written authorization obtained
- [ ] Scope clearly defined
- [ ] Legal review completed
- [ ] Infrastructure isolated and dedicated
- [ ] All tools tested
- [ ] Backup plan ready
- [ ] Emergency contacts confirmed
- [ ] Client briefed

### During Engagement

- [ ] Monitoring active and alerts working
- [ ] Daily status updates to client
- [ ] Logs reviewed regularly
- [ ] Captured data secured
- [ ] Staying within scope
- [ ] Documentation maintained
- [ ] Team communication secured

### Post-Engagement

- [ ] All data exported and encrypted
- [ ] Final report prepared
- [ ] Data delivered securely
- [ ] Client confirms receipt
- [ ] Infrastructure destroyed
- [ ] Logs cleared
- [ ] History wiped
- [ ] Lessons documented

---

## Final Reminders

**Security:**
- Encryption everywhere, always
- Assume you're being monitored
- Leave no trace
- Verify before trusting

**Legal:**
- Authorization is not optional
- Document everything
- Stay in scope
- Respect boundaries

**Ethical:**
- Minimize harm
- Protect privacy
- Professional conduct
- Responsible disclosure

**Operational:**
- Test thoroughly
- Monitor continuously
- Respond quickly
- Learn constantly

---

**Remember: The goal is not just successful compromise, but improving the client's security posture. Every engagement should make the client more secure.**

**Stay ethical. Stay legal. Stay secure.**

