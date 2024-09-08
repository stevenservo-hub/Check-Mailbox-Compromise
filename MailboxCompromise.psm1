function Invoke-MailboxCheck {
    <#
    .SYNOPSIS
    Checks for potential signs of mailbox compromise.

    .DESCRIPTION
    This function connects to Exchange Online and checks mailboxes for inbox rules, suspicious login activity, forwarding rules, and other potential signs of compromise. It can perform a quick run or a full check based on the provided parameters.

    .PARAMETER ExchangeAdmin
    The User Principal Name (UPN) of the Exchange Online administrator.

    .PARAMETER QuickRun
    If specified, the function will only check inbox rules, suspicious login activity, and forwarding rules.
    
    .PARAMETER Verbose
    If specified, the function will list out all custom permissions and audit logs for each mailbox.
    
    .EXAMPLE
    Check-MailboxCompromise -ExchangeAdmin "admin@example.com"

    .EXAMPLE
    Check-MailboxCompromise -ExchangeAdmin "admin@example.com" -QuickRun

    .EXAMPLE
    Check-MailboxCompromise -ExchangeAdmin "admin@example.com" -Verbose

    .NOTES
    Author: Steven Spring
    Date: 2024-09-07
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program. If not, see <https://www.gnu.org/licenses/>.
    #>

    param (
        [string]$ExchangeAdmin,
        [switch]$QuickRun,
        [switch]$Verbose
    )

    # Check if ExchangeOnlineManagement module is installed
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Output "The ExchangeOnlineManagement module is not installed. Please install it using the following command:"
        Write-Output "Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber"
        Exit
    }

    # Error Handling and Retry Logic for Connection
    $retryCount = 3
    $retryDelay = 5 # seconds
    $connected = $false

    for ($i = 0; $i -lt $retryCount; $i++) {
        try {
            Connect-ExchangeOnline -UserPrincipalName $ExchangeAdmin
            $connected = $true
            break
        } catch {
            Write-Output "Error connecting to Exchange Online. Attempt $($i + 1) of $retryCount."
            Start-Sleep -Seconds $retryDelay
        }
    }

    if (-not $connected) {
        Write-Output "Failed to connect to Exchange Online after $retryCount attempts."
        Exit
    }

    $mailboxes = Get-Mailbox -ResultSize Unlimited

    foreach ($mailbox in $mailboxes) {
        Write-Output "=============================="
        Write-Output "User: $($mailbox.UserPrincipalName)"
        Write-Output "=============================="

        # Inbox Rules
        try {
            $inboxRules = Get-InboxRule -Mailbox $mailbox.UserPrincipalName -ShowHidden

            if ($inboxRules.Count -gt 0) {
                Write-Output "  - Has $($inboxRules.Count) rule(s):"
                foreach ($rule in $inboxRules) {
                    Write-Output "    - Rule Name: $($rule.Name), Enabled: $($rule.Enabled), Priority: $($rule.Priority), Action: $($rule.Action)"
                }
            } else {
                Write-Output "  - No added rules."
            }
        } catch {
            Write-Output "  - Error retrieving inbox rules for $($mailbox.UserPrincipalName)."
        }

        # Forwarding Rules
        try {
            $forwardingRules = $inboxRules | Where-Object { $_.ForwardTo -ne $null -or $_.ForwardAsAttachmentTo -ne $null }
            
            if ($forwardingRules.Count -gt 0) {
                Write-Output "  - Has $($forwardingRules.Count) forwarding rule(s)."
            } else {
                Write-Output "  - No forwarding rules."
            }
        } catch {
            Write-Output "  - Error retrieving forwarding rules for $($mailbox.UserPrincipalName)."
        }

        # Suspicious Login Activity
        try {
            $suspiciousLogins = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -UserIds $mailbox.UserPrincipalName -Operations "UserLoggedIn" | Where-Object { $_.ClientIP -notlike "KnownIPRange" }
            
            if ($suspiciousLogins.Count -gt 0) {
                Write-Output "  - Has $($suspiciousLogins.Count) suspicious login(s) in the past 7 days."
                foreach ($login in $suspiciousLogins) {
                    Write-Output "    - IP: $($login.ClientIP), Date: $($login.CreationDate)"
                }
            } else {
                Write-Output "  - No suspicious logins in the past 7 days."
            }
        } catch {
            Write-Output "  - Error retrieving suspicious login activity for $($mailbox.UserPrincipalName)."
        }
        
        # Search for password changes in the Admin Audit Log
        try {
           $startDate = (Get-Date).AddDays(-30)  # Adjust the date range as needed
            $endDate = Get-Date
        
            $passwordChanges = Search-AdminAuditLog -StartDate $startDate -EndDate $endDate -Cmdlets Set-MsolUserPassword, Set-AzureADUserPassword, Set-UserPassword
        
            if ($passwordChanges.Count -gt 0) {
                Write-Output "Password changes found:"
                foreach ($change in $passwordChanges) {
                    Write-Output "  - User: $($change.UserId), Date: $($change.CreationDate), Cmdlet: $($change.CmdletName)"
                }
            } else {
                Write-Output "No password changes found in the specified date range."
            }
        } catch {
            Write-Output "An error occurred while searching for password changes: $_"
        }
        
        # Additional checks for full run
        if (-not $QuickRun) {
            # Delegates
            try {
                $delegates = Get-MailboxPermission -Identity $mailbox.UserPrincipalName | Where-Object { $_.AccessRights -eq "FullAccess" -and $_.IsInherited -eq $false }

                if ($delegates.Count -gt 0) {
                    Write-Output "  - Has $($delegates.Count) delegate(s) with Full Access."
                } else {
                    Write-Output "  - No delegates with Full Access."
                }
            } catch {
                Write-Output "  - Error retrieving delegates for $($mailbox.UserPrincipalName)."
            }

            # Mailbox Forwarding
            try {
                $mailboxForwarding = Get-Mailbox -Identity $mailbox.UserPrincipalName | Select-Object -ExpandProperty ForwardingSMTPAddress

                if ($mailboxForwarding) {
                    Write-Output "  - Has mailbox-level forwarding to $mailboxForwarding."
                } else {
                    Write-Output "  - No mailbox-level forwarding."
                }
            } catch {
                Write-Output "  - Error retrieving mailbox-level forwarding for $($mailbox.UserPrincipalName)."
            }

            # Audit Logs
            try {
                $auditLogs = Search-MailboxAuditLog -Mailboxes $mailbox.UserPrincipalName -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)

                if ($auditLogs.Count -gt 0) {
                    Write-Output "  - Has $($auditLogs.Count) audit log entries in the past 7 days."
                    if ($Verbose) {
                        foreach ($log in $auditLogs) {
                            Write-Output "    - Operation: $($log.Operation), Date: $($log.CreationDate), User: $($log.UserId)"
                        }
                    }
                } else {
                    Write-Output "  - No recent audit log entries."
                }
            } catch {
                Write-Output "  - Error retrieving audit logs for $($mailbox.UserPrincipalName)."
            }

            # Custom Permissions
            try {
                $permissions = Get-MailboxPermission -Identity $mailbox.UserPrincipalName | Where-Object { $_.AccessRights -ne "FullAccess" -and $_.IsInherited -eq $false }

                if ($permissions.Count -gt 0) {
                    Write-Output "  - Has $($permissions.Count) custom permission(s) set."
                    if ($Verbose) {
                        foreach ($permission in $permissions) {
                            Write-Output "    - User: $($permission.User), Access Rights: $($permission.AccessRights)"
                        }
                    }
                } else {
                    Write-Output "  - No custom permissions set."
                }
            } catch {
                Write-Output "  - Error retrieving custom permissions for $($mailbox.UserPrincipalName)."
            }

            # Auto-Reply Settings
            try {
                $autoReplyConfig = Get-MailboxAutoReplyConfiguration -Identity $mailbox.UserPrincipalName

                if ($autoReplyConfig.AutoReplyState -ne "Disabled") {
                    Write-Output "  - Auto-reply is enabled."
                } else {
                    Write-Output "  - Auto-reply is disabled."
                }
            } catch {
                Write-Output "  - Error retrieving auto-reply settings for $($mailbox.UserPrincipalName)."
            }
        }
    }

    Disconnect-ExchangeOnline -Confirm:$false
}

# Export the function as a module
Export-ModuleMember -Function Invoke-MailboxCheck
