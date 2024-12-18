# MailboxCompromise Module

### Synopsis of MailboxCompromise Tool
 
#### Overview
The `MailboxCompromise` tool is a PowerShell module designed to help administrators manage and secure Exchange Online mailboxes. It provides functionalities to check mailboxes for suspicious activities, reset user passwords, and revoke user sessions. As well as content and email searches to find a spreading compromised email. The tool can be run with various parameters to customize its behavior, making it flexible for different administrative needs. By default the tool will run a recursive search, going through all emails within the environment, this can be flagged to target indvidual users.
 
#### Features
 
1. **Check Mailboxes for Suspicious Activity**
   - **QuickRun**: Checks inbox rules, suspicious login activity, and forwarding rules.
   - **Verbose**: Lists all custom permissions and audit logs for each mailbox.
   - **UniqUser**: Allows checking a specific user's mailbox.
   - **Log Path**: Specify a custom path for the log file.
 
2. **Reset User Password**
   - **PassReset**: Resets the password for the specified user.
 
3. **Revoke User Sessions**
   - **Revoke-Sessions**: Revokes all active sessions for a specified user.


## Prerequisites

- **PowerShell 5.1 or later**
- **Exchange Online Management Module**: Ensure you have the Exchange Online Management module installed. You can install it using the following command:
  ```powershell
  Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber

## Installation
Clone the Repository: Clone the repository to your local machine using the following command:

`git clone https://github.com/stevenservo-hub/Check-Mailbox-Compromise.git`

Navigate to the Module Directory: Change to the directory where the module file is located:

`cd Check-Mailbox-Compromise`

Import the Module: Import the MailboxCompromise.psm1 module into your PowerShell session:

`Import-Module ".\MailboxCompromise.psm1"`

## Usage
To use the Check-MailboxCompromise function, you need to provide the Exchange Online administrator’s User Principal Name (UPN). You can also specify the -QuickRun flag to perform a quick check.

## Full Check Example

`invoke-mailboxcheck -ExchangeAdmin "admin@example.com"`

### output


User: user@example.com
Mailbox 1 of 1
  
  - Has 1 rule(s):
    - Rule Name: Forward To example Enabled: True, Priority: 1, Action: 
  - Has 1 forwarding rule(s).
    - Rule Name: Forward To example
      - Forward To: 
  - No suspicious logins in the past 7 days.
  - No password changes found in the specified date range.
  - Has 1 delegate(s) with Full Access.
    - Rights: FullAccess, Identity: _IT (DUO/Sophos/Acronis/DMARC), User: user@example.com
  - No mailbox-level forwarding.
  - No recent audit log entries.
  - Has 2 custom permission(s) set.
    - User: NT AUTHORITY\SELF, Access Rights: FullAccess, ReadPermission
    - User: NT AUTHORITY\SELF, Access Rights: FullAccess, ExternalAccount, ReadPermission
  - Auto-reply is disabled.

## Quick Run Example

`invoke-mailboxchecke -ExchangeAdmin "admin@example.com" -QuickRun`

## Help
For detailed information about the function, you can use the Get-Help cmdlet:

`Get-Help invoke-mailboxcheck -Detailed`
