# Security Event Analysis Workflows

## Unusual Email
#### Analyze email characteristics
- Check sender details:
  - Spoofed display name?
  - Domain legitimacy (typosquatting, look-alike domains)?
  - Email header analysis (SPF, DKIM, DMARC results)
  - Reply-to address matches sender?
- Check email content:
  - Phishing indicators (urgency, threats, requests for credentials)?
  - Suspicious links or attachments?
  - Grammar/spelling issues?
  - Unusual requests (wire transfer, gift cards, password reset)?

#### Identify recipients
- Single recipient?
  - Check if targeted (executive, finance, HR)
  - Interview recipient about interaction
  - Verify if email was opened/clicked
- Multiple recipients?
  - Identify scope of campaign
  - List all recipients for notification
  - Check for any responses or interactions

#### Was there user interaction?
- Yes (link clicked, attachment opened, credentials entered):
  - Immediate escalation to IR
  - Initiate account compromise workflow if credentials provided
  - Isolate affected system if attachment opened
  - Reset credentials immediately
  - Scan system for malware
- No:
  - Proceed to next step

#### Is this a known threat?
- Yes (matches existing campaign, threat intel):
  - Block sender domain/email
  - Create detection rule for similar emails
  - Notify all users via security awareness
  - Remove from all mailboxes
- Unknown but suspicious:
  - Senior analyst review
  - Submit attachments/links to sandbox
  - Report to email security team
  - Consider quarantine
- Legitimate:
  - Document false positive reason
  - Update filters
  - Close alert
