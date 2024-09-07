function Check-MailboxCompromise {
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

    .NOTES
    Author: Steven Spring
    Date: 2024-09-07
    #>

    param (
        [string]$ExchangeAdmin,
        [switch]$QuickRun
    )

    # Connect to Exchange
    $retryCount = 3
    $retryDelay = 5 # seconds
    $connected = $false

    for ($i = 0; $i -lt $retryCount; $i++) {
        try {
            Connect-ExchangeOnline -UserPrincipalName $ExchangeAdmin
            $connected = $true
            break
        } 
        catch {
            Write-Output "Error connecting to Exchange Online. Attempt $($i + 1) of $retryCount."
            Start-Sleep -Seconds $retryDelay
        }
    }

    if (-not $connected) {
        Write-Output "Failed to connect to Exchange Online after $retryCount attempts."
        return
    }

    $mailboxes = Get-Mailbox -ResultSize Unlimited

    foreach ($mailbox in $mailboxes) {
        Write-Output "=============================="
        Write-Output "User: $($mailbox.UserPrincipalName)"
        Write-Output "=============================="

        # Inbox Rules
        $inboxRules = Get-InboxRule -Mailbox $mailbox.UserPrincipalName -ShowHidden

        if ($inboxRules.Count -gt 0) {
            Write-Output "  - Has $($inboxRules.Count) rule(s):"
            foreach ($rule in $inboxRules) {
                Write-Output "    - Rule Name: $($rule.Name), Enabled: $($rule.Enabled), Priority: $($rule.Priority), Action: $($rule.Action)"
            }
        } else {
            Write-Output "  - No added rules."
        }

        # Forwarding Rules
        $forwardingRules = $inboxRules | Where-Object { $_.ForwardTo -ne $null -or $_.ForwardAsAttachmentTo -ne $null }
        
        if ($forwardingRules.Count -gt 0) {
            Write-Output "  - Has $($forwardingRules.Count) forwarding rule(s)."
        } else {
            Write-Output "  - No forwarding rules."
        }

        # Suspicious Login Activity
        $suspiciousLogins = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -UserIds $mailbox.UserPrincipalName -Operations "UserLoggedIn" | Where-Object { $_.ClientIP -notlike "KnownIPRange" }
        
        if ($suspiciousLogins.Count -gt 0) {
            Write-Output "  - Has $($suspiciousLogins.Count) suspicious login(s) in the past 7 days."
            foreach ($login in $suspiciousLogins) {
                Write-Output "    - IP: $($login.ClientIP), Date: $($login.CreationDate)"
            }
        } else {
            Write-Output "  - No suspicious logins in the past 7 days."
        }

        # Additional checks for full run
        if (-not $QuickRun) {
            # Delegates
            $delegates = Get-MailboxPermission -Identity $mailbox.UserPrincipalName | Where-Object { $_.AccessRights -eq "FullAccess" -and $_.IsInherited -eq $false }

            if ($delegates.Count -gt 0) {
                Write-Output "  - Has $($delegates.Count) delegate(s) with Full Access."
            } else {
                Write-Output "  - No delegates with Full Access."
            }

            # Mailbox Forwarding
            $mailboxForwarding = Get-Mailbox -Identity $mailbox.UserPrincipalName | Select-Object -ExpandProperty ForwardingSMTPAddress

            if ($mailboxForwarding) {
                Write-Output "  - Has mailbox-level forwarding to $mailboxForwarding."
            } else {
                Write-Output "  - No mailbox-level forwarding."
            }

           # Audit Logs
           $auditLogs = Search-MailboxAuditLog -Mailboxes $mailbox.UserPrincipalName -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)

           if ($auditLogs.Count -gt 0) {
               Write-Output "  - Has $($auditLogs.Count) audit log entries in the past 7 days."
               if ($Verbose) {
                   foreach ($log in $auditLogs) {
                       Write-Output "    - Operation: $($log.Operation), Date: $($log.CreationDate), User: $($log.UserId) 
                    }
                }
            } 
            else {
            Write-Output "  - No recent audit log entries."
            }

            $permissions = Get-MailboxPermission -Identity $mailbox.UserPrincipalName | Where-Object { $_.AccessRights -ne "FullAccess" -and $_.IsInherited -eq $false }

           if ($permissions.Count -gt 0) {
                Write-Output "  - Has $($permissions.Count) custom permission(s) set."
                if ($Verbose) {
                    foreach ($permission in $permissions) {
                        Write-Output "    - User: $($permission.User), Access Rights: $($permission.AccessRights)"
                    }
                }
            } 
            else {
                Write-Output "  - No custom permissions set."
            }

            # Auto-Reply Settings
            $autoReplyConfig = Get-MailboxAutoReplyConfiguration -Identity $mailbox.UserPrincipalName

            if ($autoReplyConfig.AutoReplyState -ne "Disabled") {
                Write-Output "  - Auto-reply is enabled."
            } else {
                Write-Output "  - Auto-reply is disabled."
            }
        }
    }

    Disconnect-ExchangeOnline -Confirm:$false
}

# Export the function as a module
Export-ModuleMember -Function Check-MailboxCompromise
