# Topics

## Abnormal Amount of Failed logins
#### Identify the targeted account(s)
- Single account targeted?
  - Check if account is high-value (admin, service account, executive)
  - Review account's recent successful logins
  - Verify account status (active, disabled, locked)
- Multiple accounts targeted?
  - Identify pattern (sequential, random, alphabetical)
  - Check for password spray indicators
  - List all targeted accounts for monitoring

#### Identify the source
- Internal source?
  - Verify legitimacy of source system
  - Check for compromised credentials on source
  - Interview user if applicable
- External source?
  - Check threat intelligence for known malicious IP
  - Review geolocation of source
  - Identify if VPN/proxy is being used

#### Was the attack successful?
- Yes:
  - Immediately escalate to IR
  - Initiate account compromise workflow
  - Consider disabling affected account(s)
  - Review all activity from successful login time forward
- No:
  - Document failed attempt count and timeframe
  - Determine if account lockout occurred
  - Continue monitoring for 24-48 hours

#### Is this expected behavior?
- Yes (legitimate forgotten password, application misconfiguration):
  - Document reason for false positive
  - Adjust threshold if needed
  - Close alert
- No:
  - Senior analyst review
  - Escalate if threshold exceeded or pattern concerning

## Unknown Traffic
#### Identify traffic characteristics
- What protocol is being used?
  - Standard protocols (HTTP, HTTPS, DNS, SMB): Review legitimacy
  - Non-standard or custom protocols: Flag for deeper analysis
  - Encrypted traffic: Note encryption method and certificate details
- What ports are involved?
  - Standard ports: Verify expected service
  - Non-standard ports: Investigate purpose
  - High-numbered ports: Check for potential backdoor

#### Identify source and destination
- Is source internal?
  - Identify asset and owner
  - Check asset baseline behavior
  - Review recent changes to system
- Is destination internal?
  - Verify destination is authorized service
  - Check if destination should accept this traffic
- Is destination external?
  - Check reputation of external IP/domain
  - Review threat intelligence feeds
  - Identify geolocation and hosting provider

#### Is this traffic authorized?
- Yes:
  - Document business justification
  - Update asset inventory/baseline
  - Create exception if recurring
  - Close alert
- No:
  - Check volume and frequency of traffic
  - Analyze payload if possible
  - Determine if this is data exfiltration, C2, or reconnaissance
  - Block traffic in firewall

#### Does traffic show malicious indicators?
- Yes:
  - Isolate affected system(s)
  - Capture full PCAP if possible
  - Escalate to IR
  - Begin containment procedures
  - Block traffic in firewall
- No but suspicious:
  - Senior analyst review
  - Continue enhanced monitoring
  - Consider blocking at firewall/proxy
  - Document for pattern analysis

## DNS Enumeration
**Check alerts for unusual amount of alerts**\
**Check zeek logs to determine what was enumerated**\
#### Identify the source
- Internal source?
  - Verify asset legitimacy
  - Check if automated tool/script
  - Review recent user activity on system
  - Interview user/owner if needed
- External source?
  - Block at perimeter immediately
  - Check threat intel for known scanner
  - Review firewall logs for other activity from source

#### Analyze enumeration pattern
- What domains are being queried?
  - Internal domains only: Possible reconnaissance for lateral movement
  - External domains: May be normal or part of malware C2
  - Mix of both: Higher concern - map out what was queried
- What is the query volume?
  - Hundreds/thousands of queries: Automated scanning
  - Dozens of queries: Targeted reconnaissance
  - Pattern recognition: Check for dictionary attacks or zone transfer attempts

#### Was sensitive information exposed?
- Yes:
  - Document what internal structure was revealed
  - Review DNS server logs for data leakage
  - Assess impact of exposed information
  - Senior analyst review for potential damage
- No:
  - Proceed to next step

#### Is this authorized activity?
- Yes (vulnerability scan, network inventory, legitimate tool):
  - Verify authorization and schedule
  - Document activity and source
  - Update whitelist if recurring
  - Close alert
- No:
  - Check for other reconnaissance activities (port scans, directory brute force)
  - Review source system for compromise indicators
  - Escalate if combined with other suspicious activity
  - Consider blocking source if external

## Unusual Email
**Need to add stuff about header inspection, domain lookup, ip lookup, etc.**\
#### Contains URL or Attachment?
- Yes:
  - Analyze URL using VirusTotal or *other tools*
  - Compute hash of attachment and upload hash to VirusTotal or *other tools* for evaluation.
- No:
  - Senior CND analyst review.
  - Email reporter to notify and thank them.
#### Malicious URL?
- Yes:
  - Verify that user did not click on the URL.
  - Gather artifacts.
  - Prepare cyber 9-line report.
  - Senior CND analyst review.
  - Escalate incident.
- No:
  - Senior CND analyst review.
  - Email reporter to notify and thank them.
#### Malicious Hash?
- Yes:
  - Verify that attachment was not downloaded or opened.
  - Gather artifacts.
  - Prepare cyber 9-line report.
  - Senior CND analyst review.
  - Escalate incident.
- No:
  - Senior CND analyst review.
  - Email reporter to notify and thank them.

## Alert Triage
#### Contain IOC?
- Yes:
  - Start a hunt playbook.
  - Dig in to find other assets with IOC.
- No:
  - Proceed to next step.
#### Is this alert from an inside resource?
- Yes:
  - Identify that there isn't a malicious application
  - Identify there is no malicious network traffic to or from resource/asset
  - Determine whether this is normal or abnormal traffic or event
- No:
  - Proceed to next step.
#### Is this a real problem?
- Yes:
  - Senior CND analyst review.
  - Develop cyber 9-line.
  - Escalate to Incident Response.
- No:
  - Proceed to next step.
#### Do we want to be alerted on this activity?
- Yes:
  - Senior CND analyst review.
  - Determine if any tweaks need to be made to the rule.
- No:
  - Senior CND analyst review.
  - Determine what triggered false positive.
  - Tune alert so that this doesn't pop-up again.

## Unusual Account Creation
#### Identify account details
- What type of account?
  - Local administrator: High concern
  - Domain user: Standard concern
  - Service account: Verify legitimacy
  - Guest/temporary: Check authorization
- What privileges assigned?
  - Administrative rights: Immediate review
  - Standard user: Lower priority
  - Specific group memberships: Verify necessity

#### Identify who created the account
- Known administrator?
  - Verify with administrator directly (not via email)
  - Check if change ticket exists
  - Confirm business justification
- Unknown or suspicious creator:
  - Check if creator account is compromised
  - Review all recent actions by creator account
  - Escalate immediately

#### When was account created?
- Business hours?
  - More likely legitimate
  - Still verify authorization
- After hours/weekend/holiday?
  - Higher suspicion
  - Immediate verification required
  - Check for other suspicious activity in timeframe

#### Is account creation authorized?
- Yes (verified change ticket, new hire, service requirement):
  - Document justification
  - Verify follows least privilege principle
  - Close alert
- No:
  - Disable account immediately
  - Review all activity performed by account
  - Check for additional unauthorized accounts
  - Escalate to IR
  - Initiate compromise investigation on creator account

## Unusual Network Activity
#### Characterize the activity
- Type of unusual activity:
  - Volume spike: Measure increase percentage and duration
  - Unusual timing: Note deviation from baseline
  - New destination: Identify target and purpose
  - New protocol: Verify legitimacy and reason
  - Bandwidth consumption: Check for data transfer

#### Identify source and destination
- Internal to internal?
  - Check for lateral movement
  - Verify both systems for compromise
  - Review relationship between systems (should they communicate?)
- Internal to external?
  - Check external destination reputation
  - Review for data exfiltration indicators
  - Verify business need for external communication
- External to internal?
  - Verify inbound connection legitimacy
  - Check for scan/probe activity
  - Review firewall rules for authorization

#### Compare to baseline
- Is there a legitimate reason for change?
  - New application deployment: Verify with IT
  - Business process change: Verify with business unit
  - Scheduled backup/update: Check against maintenance windows
  - System migration: Verify change ticket
- No known reason:
  - Proceed to next step

#### Does activity show malicious indicators?
- Yes (C2 beaconing, data exfiltration patterns, scanning):
  - Isolate affected systems
  - Capture network traffic
  - Escalate to IR immediately
  - Begin containment procedures
- Suspicious but unclear:
  - Senior analyst review
  - Continue enhanced monitoring
  - Analyze protocols and payload
  - Check for related alerts
- Benign:
  - Update baseline
  - Document new normal behavior
  - Close alert

## Unusual Application Activity
#### Identify the application
- Known business application?
  - Verify expected behavior
  - Check version and patch level
  - Review recent updates or changes
- Unknown or unauthorized application?
  - Research application purpose
  - Check for known malware matches
  - Review how it was installed

#### Characterize unusual behavior
- What specifically is unusual?
  - Resource usage spike (CPU, memory, disk, network)
  - Unexpected outbound connections
  - Accessing sensitive files/directories
  - Running unusual commands or processes
  - Crashing or error patterns
  - Privilege escalation attempts

#### Identify the user context
- Running as which user?
  - System/root: High concern if unexpected
  - Service account: Verify expected service behavior
  - Standard user: Verify user initiated action
  - Unknown user: Investigate immediately

#### Is this authorized behavior?
- Yes (new feature, legitimate use case, scheduled task):
  - Document business justification
  - Update application baseline
  - Adjust monitoring thresholds if needed
  - Close alert
- No:
  - Check for application compromise
  - Review application logs for anomalies
  - Scan system for malware
  - Check for vulnerable application version
  - Escalate if indicators of compromise found

## Unusual Remote Service Activity
#### Identify the service and protocol
- What remote service?
  - RDP: Check session details
  - SSH: Review authentication method
  - VNC: Verify authorization
  - Remote PowerShell/WinRM: Check commands executed
  - Third-party remote tools: Verify approval

#### Identify source and target
- Source of connection:
  - Internal: Verify source system and user
  - External: Check IP reputation and geolocation
  - Known admin workstation: Lower concern but verify
  - Unexpected source: High concern
- Target system:
  - Critical server: Immediate review required
  - Standard workstation: Standard review
  - Multiple targets: Possible lateral movement

#### Analyze connection characteristics
- Timing:
  - Business hours: More likely legitimate
  - After hours: Verify on-call or authorized maintenance
  - Middle of night: High suspicion
- User account:
  - Known administrator: Verify directly with admin
  - Service account: Check if expected
  - Standard user: Unusual for remote admin access
  - Disabled or dormant account: Immediate escalation

#### Is this authorized activity?
- Yes (verified change ticket, scheduled maintenance, approved remote work):
  - Document justification
  - Verify all activity during session was legitimate
  - Close alert
- No:
  - Terminate session immediately if still active
  - Review all commands/actions performed
  - Check for privilege escalation
  - Check for data access or exfiltration
  - Escalate to IR
  - Reset credentials used for connection

## Credential Dumping
#### Identify dumping method
- What technique was used?
  - LSASS memory dump: Check for Mimikatz or similar tools
  - SAM database access: Review file access logs
  - DCSync: Check domain controller logs
  - Kerberoasting: Review service ticket requests
  - NTDS.dit extraction: Critical - full domain compromise

#### Identify affected system and scope
- Type of system:
  - Domain controller: Critical - assume full domain compromise
  - Server: High concern - check for privileged accounts
  - Workstation: Concern - check what credentials were cached
- What credentials potentially exposed?
  - Domain admin: Critical escalation
  - Local admin: Serious concern
  - Service accounts: Check account privileges
  - Standard users: Lower immediate risk

#### Identify the actor
- Process that performed dump:
  - Known tool (Mimikatz, ProcDump, Task Manager): Direct attack
  - System process: Check for process injection
  - Unknown: Research and identify
- User context:
  - Admin account: Verify if legitimate admin action
  - Standard user with privilege escalation: Attack in progress
  - System account: Possible malware

#### Has this been detected in time?
- Attack ongoing:
  - Isolate system immediately
  - Terminate malicious processes
  - Disable network access
  - Do not shut down (preserve memory)
- Attack completed:
  - Assume credentials compromised
  - Proceed to next step

#### Execute immediate response
- Reset all potentially compromised credentials immediately
- Force logoff of all sessions using affected accounts
- Review all activity by compromised accounts since dump time
- Check for lateral movement from affected system
- Escalate to IR immediately
- Begin full incident response procedures
- Consider domain-wide password reset if DC compromised
- Enable enhanced monitoring on all systems
- Hunt for use of dumped credentials across environment

## Account Compromise
#### Identify compromise indicators
- What triggered the alert?
  - Unusual login location or time
  - Impossible travel
  - Login after credential dump
  - Successful login after brute force
  - Suspicious activity post-authentication
  - Alert from user reporting unauthorized access

#### Verify compromise
- Check account activity:
  - Recent login times and sources
  - Failed login attempts
  - Password changes
  - MFA status and changes
  - Mailbox rules or forwarding changes
  - File access patterns
  - Privileged actions performed
- Contact account owner:
  - Verify recent activity was legitimate
  - Confirm they are in location shown in logs
  - Ask about any unusual password reset emails
  - Determine if they shared credentials

#### Is account actually compromised?
- Yes or likely:
  - Proceed to immediate response
- Unclear:
  - Senior analyst review
  - Continue monitoring
  - Keep user informed
  - Prepare for rapid response if confirmed
- No (false positive):
  - Document reason
  - Tune alert
  - Close

#### Execute immediate response
- Disable account immediately
- Terminate all active sessions
- Reset password (do not notify compromised email)
- Review and remove any persistence mechanisms:
  - Email forwarding rules
  - Mailbox delegations
  - OAuth tokens
  - Saved passwords
  - MFA device enrollments
- Review all actions taken by compromised account:
  - Files accessed, downloaded, uploaded
  - Emails sent
  - Systems accessed
  - Privilege changes made
  - Accounts created or modified

#### Assess damage and scope
- What data was accessed?
  - Sensitive/classified information
  - PII or financial data
  - Intellectual property
  - Customer information
- What systems were accessed?
  - Document all systems logged into
  - Check for lateral movement
  - Verify no additional accounts compromised
- What actions were taken?
  - Changes to security settings
  - Installation of software
  - Creation of persistence
  - Data exfiltration
- Escalate to IR with full impact assessment
- Begin incident response procedures
- Notify stakeholders per IR plan
- Consider threat hunt for additional compromises

## Data Exfiltration
#### Identify the data transfer characteristics
- Volume of data:
  - Large single transfer: Direct exfiltration attempt
  - Small frequent transfers: Slow exfiltration or C2
  - Gradual increase: May be automated malware
- Destination:
  - External IP: Check reputation and location
  - Cloud storage: Verify authorized use
  - Personal email: Policy violation or insider threat
  - Unknown destination: Investigate immediately

#### Identify source and method
- What system is source?
  - Server with sensitive data: High concern
  - Workstation: Check user and data type
  - Database server: Critical concern
- What protocol/method used?
  - HTTP/HTTPS upload: Check destination URL
  - FTP/SFTP: Review credentials and destination
  - Email: Check attachments and recipients
  - DNS tunneling: Advanced exfiltration technique
  - Cloud sync: Check for unauthorized sync tools

#### Identify what data is being transferred
- Can you determine data type?
  - Run DLP analysis on traffic if possible
  - Check source directories/databases accessed
  - Review file types being transferred
- Sensitivity level:
  - Public information: Lower concern
  - Internal business data: Moderate concern
  - Confidential/PII/PHI: High concern
  - Classified: Critical concern

#### Is this authorized activity?
- Yes (approved cloud backup, authorized file transfer, business need):
  - Verify authorization documentation
  - Ensure proper controls in place
  - Document and close
- No or unclear:
  - Proceed to containment

#### Execute containment
- If transfer ongoing:
  - Block at firewall/proxy immediately
  - Isolate source system from network
  - Terminate user session if applicable
- Document what was transferred:
  - Total volume
  - Time period
  - Complete file list if possible
- Identify destination and attempt to:
  - Contact destination provider for takedown
  - Determine if data retrievable
  - Assess if destination is attacker-controlled

#### Assess impact and respond
- Determine what data was successfully exfiltrated
- Identify all potentially affected individuals/customers
- Review compliance and legal obligations:
  - Breach notification requirements
  - Regulatory reporting (HIPAA, GDPR, etc.)
  - Law enforcement notification if criminal
- Escalate to IR immediately
- Engage legal and compliance teams
- Begin incident response and forensics
- Identify root cause and remediate vulnerability
- Consider insider threat investigation if applicable

## Denial of Service
#### Characterize the attack
- Type of DoS:
  - Network flood (SYN, UDP, ICMP): Volume-based
  - Application layer (HTTP flood, slowloris): Resource exhaustion
  - Distributed (DDoS): Multiple sources
  - Amplification attack: Reflected traffic
- Volume and severity:
  - Traffic volume (Gbps, packets per second)
  - Number of attack sources
  - Duration so far
  - Services affected

#### Identify target and impact
- What is being targeted?
  - Specific application/service
  - Entire network segment
  - Specific server or IP
  - DNS infrastructure
- Current impact:
  - Service completely down
  - Degraded performance
  - Partial outage
  - Contained successfully
- Business impact:
  - Customer-facing services affected
  - Internal operations disrupted
  - Financial impact occurring
  - Reputation damage risk

#### Identify attack source(s)
- Source IP analysis:
  - Single source: Simpler to block
  - Multiple sources: DDoS - need upstream help
  - Spoofed sources: Amplification attack
  - Geolocation patterns: May indicate specific campaign
- Attack characteristics:
  - Legitimate-looking traffic: Application layer attack
  - Malformed packets: Network layer attack
  - Known attack patterns: Check threat intel
  - Botnet signature: Research botnet family

#### Implement immediate mitigation
- Network level:
  - Block attacking IPs at firewall
  - Implement rate limiting
  - Enable anti-DDoS features
  - Contact ISP for upstream blocking
  - Route to scrubbing center if available
- Application level:
  - Enable caching/CDN
  - Implement CAPTCHA
  - Adjust WAF rules
  - Scale resources if possible
  - Activate geo-blocking if appropriate

#### Is mitigation effective?
- Yes:
  - Continue monitoring
  - Document attack details
  - Maintain heightened alertness
  - Review logs for other attacks
- No:
  - Escalate to senior analyst and network team
  - Engage ISP/DDoS mitigation service
  - Consider taking service offline temporarily
  - Implement alternative access methods

#### Post-incident actions
- Document full attack timeline and characteristics
- Analyze logs for patterns
- Identify any vulnerabilities exploited
- Review and update DoS response procedures
- Implement permanent preventive measures
- Senior analyst review and approval
- Brief stakeholders on incident and response

## Privilege Escalation Attempts
#### Identify escalation method
- What technique is being used?
  - Exploiting vulnerable service/application
  - Abusing misconfigured permissions
  - Token manipulation
  - Scheduled task abuse
  - DLL hijacking
  - Exploiting kernel vulnerability
  - Sudo/UAC bypass

#### Identify the actor
- User account attempting escalation:
  - Legitimate user account: Check if authorized activity
  - Service account: Unusual, investigate immediately
  - Local account: Verify legitimacy
  - Domain account: Check account status and privileges
- Process attempting escalation:
  - Known application: Check if expected behavior
  - System process: May indicate process injection
  - Suspicious executable: Research and analyze
  - Script (PowerShell, bash): Review script content

#### Was escalation successful?
- Yes:
  - Immediately isolate affected system
  - Terminate elevated processes
  - Review all actions taken with elevated privileges
  - Check for persistence mechanisms
  - Escalate to IR immediately
- No (blocked or failed):
  - Continue monitoring
  - Proceed with investigation

#### Is this authorized activity?
- Yes (IT performing maintenance, authorized software install):
  - Verify change ticket
  - Confirm with user/admin
  - Document and close
- No:
  - Review system for other compromise indicators
  - Check for vulnerability that allowed attempt
  - Review all recent activity on system
  - Scan for malware
  - Senior analyst review
  - Escalate if part of larger attack pattern

## Use of Default or Weak Credentials
#### Identify where detected
- What system/service?
  - Critical server: Immediate remediation required
  - Network device: High priority
  - Application: Check exposure level
  - IoT/embedded device: Often forgotten, high risk
- How was it detected?
  - Successful login with default credential
  - Vulnerability scan finding
  - Password audit
  - Failed attack attempt revealing default credential

#### Assess exposure and risk  
- Is system internet-facing?
  - Yes: Critical - immediate change required
  - No: Still serious but lower urgency
- What level of access do these credentials provide?
  - Administrative access: Critical
  - User-level access: Serious
  - Read-only access: Moderate concern
- How long has weak credential been in use?
  - Review logs for any unauthorized access
  - Check for signs of compromise

#### Has credential been abused?
- Review authentication logs:
  - Unusual login times or sources
  - Multiple failed attempts followed by success
  - Logins from unexpected locations
- Review system activity:
  - Configuration changes
  - Data access
  - Software installation
- Yes, shows signs of abuse:
  - Escalate to account compromise workflow
  - Assume system is compromised
- No signs of abuse:
  - Proceed to remediation

#### Immediate remediation
- Change credential immediately
- Force logout of all existing sessions
- Review and harden security configuration
- Document which default/weak credential was found
- Check for similar issues on related systems
- If vendor default: Check all systems from that vendor
- Update password policy if weak password was user-created

#### Broader response
- Scan environment for other default credentials
- Review password policies and enforcement
- Senior analyst review
- Update hardening standards
- Security awareness notification if user-created weak password
- Close alert after verification of remediation

## Dormant Account Reactivation
#### Identify the account
- Type of account:
  - User account: Check employee status
  - Service account: Verify service still needed
  - Administrative account: High concern
  - Vendor/contractor account: Check contract status
- How long was account dormant?
  - Days: Lower concern
  - Weeks: Moderate concern
  - Months/years: High concern
- What are account privileges?
  - Standard user: Lower risk
  - Elevated privileges: High risk
  - Administrative: Critical concern

#### Identify reactivation details
- Who/what reactivated the account?
  - HR system: Verify with HR
  - Administrator: Verify directly with admin
  - Automated process: Check legitimacy
  - Unknown: Investigate immediately
- Authentication method:
  - Password: When was password last changed?
  - Cached credentials: How were they obtained?
  - Service authentication: Verify service legitimacy

#### Review account activity since reactivation
- What has the account done?
  - Login locations and times
  - Systems accessed
  - Files accessed or modified
  - Commands executed
  - Network connections made
  - Privilege usage

#### Is reactivation legitimate?
- Yes (employee return, contractor rehire, service reactivation):
  - Verify with appropriate department
  - Confirm proper reactivation procedure followed
  - Ensure password was reset
  - Verify current access needs match privileges
  - Document and close
- No or cannot verify:
  - Disable account immediately
  - Reset account password
  - Review all activity for malicious actions
  - Check for how account credentials were obtained
  - Escalate to IR if compromise indicated    
  - Investigate who/what had access to reactivate account

## After-Hours Access from Privileged Accounts
#### Identify access details
- Specific account:
  - Named administrator: Direct contact possible
  - Generic admin account: Check who has access
  - Service account: Should not have interactive login
  - Emergency/break-glass account: Verify emergency exists
- Time of access:
  - Late evening: May be legitimate overtime
  - Middle of night (2-5 AM): Higher suspicion
  - Weekend: Check for scheduled maintenance
  - Holiday: Higher suspicion unless emergency

#### Identify access source and method
- Source location:
  - Corporate VPN: More likely legitimate
  - Direct internet: Higher concern
  - Known admin workstation: Lower concern
  - Unknown system: Investigate immediately
  - Foreign country: Very high concern unless expected
- Access method:
  - Standard protocol (RDP, SSH): Check if normal
  - Unusual protocol: Investigate
  - Multiple failed attempts then success: Possible compromise

#### Verify legitimacy
- Contact account owner directly:
  - Call or text (do not use email - may be compromised)
  - Verify they are working
  - Confirm they accessed the specific system
  - Ask what work they are performing
- Check for authorization:
  - Change ticket or maintenance window
  - On-call schedule
  - Emergency situation
  - Manager approval

#### Is access authorized?
- Yes (verified with account owner or approved change):
  - Monitor activity to ensure it matches stated purpose
  - Document authorization
  - Close alert after work completion
- Cannot verify (user does not respond):
  - Senior analyst review
  - Attempt additional contact methods
  - Review activity for suspicious actions
  - Prepare to disable account if concerning activity found
- No (user denies access or no authorization found):
  - Immediately disable account
  - Terminate all sessions
  - Execute account compromise workflow
  - Review all actions taken during session
  - Escalate to IR

## Access from Impossible Travel Locations
#### Analyze the travel scenario
- Calculate time and distance:
  - Time between logins
  - Distance between locations
  - Physically possible travel time
  - Is VPN or proxy explaining location difference?
- Location details:
  - First location: Verify it matches user's known location
  - Second location: Check if business office, common travel destination
  - Known risk location: Some countries higher risk
  - Data center location: May indicate compromised service

#### Review authentication details
- First authentication:
  - Success or failure
  - Authentication method (password, MFA, SSO)
  - IP address and ISP
  - User agent and device type
- Second authentication:
  - Same details to review
  - Compare device fingerprint
  - Compare user agent strings
  - MFA used on both?

#### Check account activity
- What did user do from each location?
  - First location: Normal user behavior?
  - Second location: Suspicious activity?
  - Data accessed or downloaded
  - Configuration changes
  - Email sent or forwarding rules created

#### Contact user for verification
- Reach user directly (phone, in-person if possible):
  - Verify their current location
  - Confirm they logged in from both locations
  - Ask about VPN usage
  - Check if credentials shared
  - Determine if password recently changed

#### Is this legitimate?
- Yes (VPN, shared account authorized, location error):
  - Document explanation
  - Update baseline if VPN or travel pattern
  - Close alert
- User denies second location:
  - Execute account compromise workflow
  - Disable account immediately
  - Reset password
  - Review all activity from second location
  - Escalate to IR
- Cannot reach user:
  - Senior analyst review
  - Monitor account closely
  - Restrict account if highly suspicious activity
  - Continue attempts to contact user

## Multiple Accounts Accessed from Single Source
#### Characterize the pattern
- How many accounts?
  - 2-5 accounts: Possible legitimate, investigate
  - 5-20 accounts: High concern, likely attack
  - 20+ accounts: Attack in progress, escalate immediately
- Type of accounts:
  - All similar privilege level: May be automated attack
  - Escalating privileges: Targeted attack
  - Mix of privileges: Reconnaissance or brute force
  - Related accounts (same department): Could be legitimate

#### Identify the source
- Source location:
  - Internal IP: Check for compromised system
  - External IP: Check threat intel and reputation
  - VPN connection: Verify VPN account legitimacy
  - Proxy/TOR: High suspicion
- Source system identification:
  - Known workstation: Check for compromise
  - Server: Should not have interactive logins
  - Unknown system: Investigate immediately

#### Analyze authentication pattern
- Authentication method:
  - All using same method: Automated tool
  - Various methods: Manual or sophisticated attack
  - Successful logins: Very high concern
  - All failures: Brute force or password spray
- Timing:
  - Rapid succession: Automated attack
  - Spaced out: Manual or slow/stealthy attack
  - Pattern recognition: Sequential, alphabetical, dictionary

#### Were any authentications successful?
- Yes:
  - Identify which accounts compromised
  - Execute account compromise workflow for each
  - Disable all successfully accessed accounts
  - Reset all passwords
  - Escalate to IR immediately
- No (all failed):
  - Still concerning - attack in progress
  - Proceed to containment

#### Execute containment and response
  - Block source IP at firewall
  - Enable enhanced monitoring on all targeted accounts
  - Force password reset on all targeted accounts (if policy allows)
  - Enable MFA on all targeted accounts if not present
  - Review for other activity from same source
  - Check if source is compromised internal system (if internal)
  - Senior analyst review
  - Document attack pattern and IOCs
  - Update IDS/IPS signatures
  - Consider threat hunt for similar activity

## Beaconing Activity
#### Identify beacon characteristics
  - Timing pattern:
    - Fixed interval: Classic C2 beacon
    - Jittered interval: More sophisticated malware
    - Time-based (hourly, daily): Scheduled task
    - Event-based: Triggered by specific actions
  - Beacon details:
    - Destination IP/domain
    - Port and protocol
    - Packet size consistency
    - Request/response patterns
    - Encryption present?

#### Identify infected system
  - Source system identification:
    - Hostname and IP
    - System owner/department
    - System purpose and criticality
    - Operating system and patch level
  - Current state:
    - System online and accessible
    - User currently logged in
    - Recent system changes

#### Analyze beacon destination
  - Destination analysis:
    - Check threat intelligence feeds
    - Domain registration details (WHOIS)
    - IP geolocation
    - Hosting provider
    - Domain age (newly registered is suspicious)
    - SSL certificate details
  - Known malware family:
    - Match beacon pattern to known families
    - Research malware capabilities
    - Identify likely infection vector

#### Capture and analyze traffic
  - If possible without alerting attacker:
    - Capture full PCAP of beacon traffic
    - Analyze payload (if not encrypted)
    - Document complete communication pattern
    - Extract any IOCs from traffic
  - DO NOT attempt if:
    - It would alert sophisticated attacker
    - System is highly critical and must stay running
    - Containment is more urgent

#### Execute containment
  - Isolate system from network:
    - Disconnect from network (preserve power and memory)
    - Block beacon destination at firewall
    - Isolate network segment if multiple systems affected
  - Preserve evidence:
    - Do not shut down
    - Capture memory dump
    - Image disk if possible
    - Save all logs

#### Investigate scope and impact
  - Check for lateral movement:
    - Review authentication logs for spread
    - Check for similar beacons from other systems
    - Identify other systems accessed from infected system
  - Determine what data was accessed:
    - Review file access logs
    - Check for data staging areas
    - Look for compression
