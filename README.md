# Check-MailboxCompromise Module

## Prerequisites

- **PowerShell 5.1 or later**
- **Exchange Online Management Module**: Ensure you have the Exchange Online Management module installed. You can install it using the following command:
  ```powershell
  Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber

## Installation
Clone the Repository: Clone the repository to your local machine using the following command:
`git clone https://github.com/yourusername/yourrepository.git`

Navigate to the Module Directory: Change to the directory where the module file is located:
`cd yourrepository`

Import the Module: Import the MailboxCompromise.psm1 module into your PowerShell session:
`Import-Module -Path ".\MailboxCompromise.psm1"`

## Usage
To use the Check-MailboxCompromise function, you need to provide the Exchange Online administrator’s User Principal Name (UPN). You can also specify the -QuickRun flag to perform a quick check.

## Full Check Example
`Check-MailboxCompromise -ExchangeAdmin "admin@example.com"`

## Quick Run Example
`Check-MailboxCompromise -ExchangeAdmin "admin@example.com" -QuickRun`

## Help
For detailed information about the function, you can use the Get-Help cmdlet:

`Get-Help Check-MailboxCompromise -Detailed`
