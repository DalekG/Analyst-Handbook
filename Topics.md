# Topics

## Abnormal Amount of Failed logins
#### Local Login Type?
- Yes:
- No:
#### From Trusted Network?
- Yes:
- No:
#### Happen Across Multiple Machines?
- Yes:
- No:

## Unknown Traffic
#### Critical Services Affected?
- Yes:
  - Senior CND analyst review.
  - Drop/Deny traffic.
  - Restore services.
- No:
  - Verify LDIF/FER/Pano
  - Verify with NETENG/SSS
  - Verify with Higher HQ
#### IP Owner Identified?
- Yes:
  - Resolve misconfigurations.
  - Senior CND analyst review.
- No:
  - Identify attempted connections.
  - Initiate packet capture.
  - Gather information and screenshots.
  - Prepare cyber 9-line.
  - Submit report
#### Is This an Incident?
- Yes:
  - Senior CND analyst review.
  - Submit 9-line to higher HQ
  - Perform IR actions IAW SOP
- No:
  - Senior CND analyst review.
  - Drop/Deny traffic.

## DNS Enumeration
**Check alerts for unusual amount of alerts**\
**Check zeek logs to determine what was enumerated**\
#### Come up with better topics

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

## Unusual Network Activity

## Unusual Application Activity

## Unusual Remote Service Activity

## Credential Dumping

## Account Compromise

## Data Exfiltration

## Denial of Service
