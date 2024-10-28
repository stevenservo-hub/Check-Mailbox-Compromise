# MailboxComprimise Module

### Synopsis of MailboxCompromise Tool
 
#### Overview
The `MailboxCompromise` tool is a PowerShell module designed to help administrators manage and secure Exchange Online mailboxes. It provides functionalities to check mailboxes for suspicious activities, reset user passwords, and revoke user sessions. The tool can be run with various parameters to customize its behavior, making it flexible for different administrative needs.
 
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

## Quick Run Example

`invoke-mailboxchecke -ExchangeAdmin "admin@example.com" -QuickRun`

## Help
For detailed information about the function, you can use the Get-Help cmdlet:

`Get-Help invoke-mailboxcheck -Detailed`
