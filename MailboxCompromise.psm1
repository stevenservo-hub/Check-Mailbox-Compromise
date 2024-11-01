. .\Functions\definitions.ps1 # Import the function definitions

function Invoke-MailboxCheck {
    <#
    .SYNOPSIS
    Checks for potential signs of mailbox compromise.

    .DESCRIPTION
    This function connects to Exchange Online and checks mailboxes for inbox rules, suspicious login activity, forwarding rules, and other potential signs of compromise. It can perform a quick run or a full check based on the provided parameters.

    .PARAMETER Admin
    The User Principal Name (UPN) of the Exchange Online administrator.

    .PARAMETER QuickRun
    If specified, the function will only check inbox rules, suspicious login activity, and forwarding rules.
    
    .PARAMETER Verbose
    If specified, the function will list out all custom permissions and audit logs for each mailbox.
    
    .PARAMETER path
    Specify specific path to the log file. Default is C:\Windows\System32\Logs\MailboxCheck.log

    .PARAMETER User
    Specify a specific user to check. If not provided, all mailboxes will be checked.

    .PARAMETER PassReset
    If specified, the function will reset the password for the specified user.

    .PARAMETER RevokeSession    
    If specified, the function will revoke the user's refresh tokens.

    .PARAMETER EmailSearch
    Specify an email address to search for emails received from and responded to by the user.

    .PARAMETER ContentSearch  
    Specify a keyword to search for in the email content.
    
    .PARAMETER StartDate
    Specify the start date for the content search.
    
    .PARAMETER EndDate 
    Specify the end date for the content search.

    .EXAMPLE
    Check-MailboxCompromise -ExchangeAdmin "admin@example.com"

    .EXAMPLE
    Check-MailboxCompromise -ExchangeAdmin "admin@example.com" -QuickRun

    .EXAMPLE
    Check-MailboxCompromise -ExchangeAdmin "admin@example.com" -Verbose

    .EXAMPLE
    Check-MailboxCompromise -UniqUser "user@example.com" -ExchangeAdmin "admin@example.com" -Verbose

    .EXAMPLE
    Check-MailboxCompromise -UniqUser "user@example.com" -ExchangeAdmin "admin@example.com -PassReset

    .EXAMPLE
    Check-MailboxCompromise -UniqUser "user@example.com" -ExchangeAdmin "admin@example.com" -Verbose -path "C:\example\example.log"

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

    function AsciiArt {
        write-output "                                                                "                 
        write-output "                                                                "             
        write-output "        :-----------------:.            :++++++++++++++++++:    "        
        write-output "        :--------------------:         :+++++++++++++++++++++:  "         
        write-output "       .-----------------------:     .+++++++++++++++++++++++-  "         
        write-output "        -------------------------: .+++++++++++++++++++++++++-  "         
        write-output "        ---------------------------++++++++++++++++++++++++++-  "         
        write-output "       .---------------------------++++++++++++++++++++++++++-  "         
        write-output ":###############################=--++++++++++++++++++++++++++-  "         
        write-output "*###############################*--++++++++++++++++++++++++++-  "         
        write-output "*###############################*--++++++++++++++++++++++++++-  "         
        write-output "*##########*********############*--++++++++++++++++++++++++++-  "         
        write-output "##########.         .###########*--++++++++++++++++++++++++++   "         
        write-output "##########.  :*******###########*-=++++++++++++++++++++++++.    "         
        write-output "##########.  -##################*=+++++++++++++++++++++++:      "         
        write-output "##########.  .++++++#############++++++++++++++++++++++:        "         
        write-output "##########.         =##########%#++++++**#############-         "         
        write-output "##########.  -#################%#+++*###################.       "         
        write-output "##########.  -#################%#++*#####################*.     "         
        write-output "##########.   .......##########%#++########################*    "         
        write-output "##########.          ##########%#++##########################:  "         
        write-output "###############################%#++##########################+  "         
        write-output "###############################%#++##########################+  "         
        write-output "*##############################%#++##########################+  "         
        write-output " +##########################%%%%#++##########################+  "         
        write-output "       .%%%%%%%%%%%%%%%%%%%%%%%#*++##########################+  "         
        write-output "       .***********************++++##########################+  "         
        write-output "       .++++++++++++++++++++++++=.  -########################+  "         
        write-output "       .+++++++++++++++++++++++.      +######################+  "         
        write-output "        =++++++++++++++++++++:          *####################:  "         
        write-output "         .-+++++++++++++++=.              =################-    "         
    }
    
    param (
        [string]$Admin,
        [switch]$QuickRun,
        [switch]$Verbose,
        [string]$user,
        [string]$path,
        [switch]$PassReset,
        [switch]$revokesession,
        [string]$EmailSearch,
        [string]$ContentSearch,
        [datetime]$StartDate,
        [datetime]$EndDate
    )
    
   try {
            if (-not $Admin) {
                $Admin = Read-Host "Please enter the Exchange Admin UserPrincipalName"
            }
        
            if (-not $user) {
                $user = Read-Host "Please enter the unique user"
            }
        
            Connect-ExchangeOnline -UserPrincipalName $Admin -WarningAction SilentlyContinue
        
            # Call the reset-password function with the provided or prompted UniqUser
            Reset-Password -user $user -Admin $Admin
            
        } catch {
            write-output "an error occurred while attempting to connect to Exchange Online: $_"
        } finally { 
            Disconnect-ExchangeOnline -Confirm:$false
            exit
        }
    

    if ($revokeSession) {
        try {
            if (-not $Admin) {
                $Admin = Read-Host "Please enter the Exchange Admin UserPrincipalName"
            }
        
            if (-not $user) {
                $user = Read-Host "Please enter the unique user"
            }
        
            Connect-ExchangeOnline -UserPrincipalName $Admin -WarningAction SilentlyContinue
        
            # Call the revoke-session function with the provided or prompted UniqUser
            Revoke-Session -user $user -Admin $Admin
            
        } catch {
            write-output "an error occurred while attempting to connect to Azure Online: $_"
        } finally { 
            Disconnect-AzureAD -Confirm:$false
            exit
        }
    }

    if ($EmailSearch) {
        try {
            if (-not $Admin) {
                $Admin = Read-Host "Please enter the Exchange Admin UserPrincipalName"
            }
        
            if (-not $user) {
                $user = Read-Host "Please enter the unique user"
            }
        
            Connect-ExchangeOnline -UserPrincipalName $Admin -WarningAction SilentlyContinue
        
            # Call the email-search function with the provided or prompted UniqUser
            EmailSearch -UniqUser $user -EmailSearch $EmailSearch
            
        } catch {
            write-output "an error occurred while attempting to connect to Exchange Online: $_"
        } finally { 
            Disconnect-ExchangeOnline -Confirm:$false
            exit
        }
    }

    if ($ContentSearch) {
        try {
            if (-not $Admin) {
                $Admin = Read-Host "Please enter the Exchange Admin UserPrincipalName"
            }
        
            if (-not $user) {
                $user = Read-Host "Please enter the unique user"
            }
        
            Connect-ExchangeOnline -UserPrincipalName $Admin -WarningAction SilentlyContinue
        
            # Call the content-search function with the provided or prompted UniqUser
            ContentSearch -UniqUser $user -ContentSearch $ContentSearch -StartDate $StartDate -EndDate $EndDate
            
        } catch {
            write-output "an error occurred while attempting to connect to Exchange Online: $_"
        } finally { 
            Disconnect-ExchangeOnline -Confirm:$false
            exit
        }
    }

    # Error Handling and Retry Logic for Connection
    $retryCount = 3
    $retryDelay = 5 # seconds
    $connected = $false

    
    # Attempt to connect to Exchange Online with retry logic
    for ($i = 0; $i -lt $retryCount; $i++) {
        try {
            Connect-ExchangeOnline -UserPrincipalName $Admin -WarningAction SilentlyContinue
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

    # Get mailboxes. This is used to flag an individual mailbox if the user parameter is used.
    try {
        if ($user) {
            $mailboxes = Get-Mailbox -Identity $user
        } else {
            $mailboxes = Get-Mailbox -ResultSize Unlimited
        }
    } catch {
        Write-Host "An error occurred: $_"
    }
    
    $mailboxCount = $mailboxes.Count
    $mailboxIndex = 1
    AsciiArt
    #main loop
    foreach ($mailbox in $mailboxes) {
        
        Write-Output "====================================="
        Write-Output "User: $($mailbox.UserPrincipalName)"
        Write-Output "Mailbox $mailboxIndex of $mailboxCount"
        Write-Output "====================================="
        
        write-log -Message "User: $($mailbox.UserPrincipalName) Mailbox $mailboxIndex of $mailboxCount"
        # increment mailbox index
        $mailboxIndex++
        
        # Inbox Rules
        try {
            $inboxRules = Get-InboxRule -Mailbox $mailbox.UserPrincipalName

            if ($inboxRules.Count -gt 0) {
                Write-Output "  - Has $($inboxRules.Count) rule(s):"
                foreach ($rule in $inboxRules) {
                    Write-Output "    - Rule Name: $($rule.Name), Enabled: $($rule.Enabled), Priority: $($rule.Priority), Action: $($rule.Action)"
                    Write-Log -Message "Rule Name: $($rule.Name), Enabled: $($rule.Enabled), Priority: $($rule.Priority), Action: $($rule.Action)"
                }
            } else {
                Write-Output "  - No added rules."
            }
        } catch {
            Write-Output "  - Error retrieving inbox rules for $($mailbox.UserPrincipalName)."
            Write-Log -Message "Error retrieving inbox rules for $($mailbox.UserPrincipalName)."
        }

        # Forwarding Rules
        try {
            $forwardingRules = $inboxRules | Where-Object { $null -ne $_.ForwardTo -or $null -ne $_.ForwardAsAttachmentTo }
            
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
                    write-log -Message "Logins - IP: $($login.ClientIP), Date: $($login.CreationDate)"
                }
            } else {
                Write-Output "  - No suspicious logins in the past 7 days."
            }
        } catch {
            Write-Output "  - Error retrieving suspicious login activity for $($mailbox.UserPrincipalName)."
            write-log -Message "Error retrieving suspicious login activity for $($mailbox.UserPrincipalName)."
        }
        
        # Search for password changes in the Admin Audit Log
        try {
           $startDate = (Get-Date).AddDays(-30)  # Adjust the date range as needed
            $endDate = Get-Date
        
            $passwordChanges = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -Operations Set-MsolUserPassword, Set-AzureADUserPassword, Set-UserPassword
        
            if ($passwordChanges.Count -gt 0) {
                Write-Output " -  Password changes found:"
                foreach ($change in $passwordChanges) {
                    Write-Output "  - User: $($change.UserId), Date: $($change.CreationDate), Cmdlet: $($change.CmdletName)"
                    write-log -Message "Password Change - User: $($change.UserId), Date: $($change.CreationDate), Cmdlet: $($change.CmdletName)"
                }
            } else {
                Write-Output "  - No password changes found in the specified date range."
            }
        } catch {
            Write-Output "An error occurred while searching for password changes: $_"
            write-log -Message "An error occurred while searching for password changes: $_"
        }
        
        # Additional checks for full run
        if (-not $QuickRun) {
            # Delegates
            try {
                $delegates = Get-MailboxPermission -Identity $mailbox.UserPrincipalName | Where-Object { $_.AccessRights -eq "FullAccess" -and $_.IsInherited -eq $false }

                if ($delegates.Count -gt 0) {
                    Write-Output "  - Has $($delegates.Count) delegate(s) with Full Access."
                    if ($Verbose) {
                        foreach ($delegate in $delegates) {
                            Write-Output "    - Rights: $($delegate.AccessRights), Identity: $($delegate.Identity), User: $($delegate.User)"
                            write-log -Message "Delegate - Rights: $($delegate.AccessRights), Identity: $($delegate.Identity), User: $($delegate.User)"
                        }
                    }
                    } else {
                    Write-Output "  - No delegates with Full Access."
                }        
            } catch {
                Write-Output "  - Error retrieving delegates for $($mailbox.UserPrincipalName)."
                write-log -Message "Error retrieving delegates for $($mailbox.UserPrincipalName)."
            }
        
            # Mailbox Forwarding
            try {
                $mailboxForwarding = Get-Mailbox -Identity $mailbox.UserPrincipalName | Select-Object -ExpandProperty ForwardingSMTPAddress

                if ($mailboxForwarding) {
                    Write-Output "  - Has mailbox-level forwarding to $mailboxForwarding."
                    write-log -Message "Has mailbox-level forwarding to $mailboxForwarding."

                } else {
                    Write-Output "  - No mailbox-level forwarding."
                }
            } catch {
                Write-Output "  - Error retrieving mailbox-level forwarding for $($mailbox.UserPrincipalName)."
                write-log -Message "Error retrieving mailbox-level forwarding for $($mailbox.UserPrincipalName)."
            }

            # Audit Logs
            try {
                $auditLogs = Search-MailboxAuditLog -Mailboxes $mailbox.UserPrincipalName -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)

                if ($auditLogs.Count -gt 0) {
                    Write-Output "  - Has $($auditLogs.Count) audit log entries in the past 7 days."
                    if ($Verbose) {
                        foreach ($log in $auditLogs) {
                            Write-Output "    - Operation: $($log.Operation), Date: $($log.CreationDate), User: $($log.UserId)"
                            write-log -Message "Log - Operation: $($log.Operation), Date: $($log.CreationDate), User: $($log.UserId)"
                        }
                    }
                } else {
                    Write-Output "  - No recent audit log entries."
                }
            } catch {
                Write-Output "  - Error retrieving audit logs for $($mailbox.UserPrincipalName)."
                Write-Log -Message "Error retrieving audit logs for $($mailbox.UserPrincipalName)."
            }

            # Custom Permissions
            try {
                $permissions = Get-MailboxPermission -Identity $mailbox.UserPrincipalName | Where-Object { $_.AccessRights -ne "FullAccess" -and $_.IsInherited -eq $false }

                if ($permissions.Count -gt 0) {
                    Write-Output "  - Has $($permissions.Count) custom permission(s) set."
                    if ($Verbose) {
                        foreach ($permission in $permissions) {
                            Write-Output "    - User: $($permission.User), Access Rights: $($permission.AccessRights)"
                            write-log -Message "Permission - User: $($permission.User), Access Rights: $($permission.AccessRights)"
                        }
                    }
                } else {
                    Write-Output "  - No custom permissions set."
                }
            } catch {
                Write-Output "  - Error retrieving custom permissions for $($mailbox.UserPrincipalName)."
                write-log -Message "Error retrieving custom permissions for $($mailbox.UserPrincipalName)."
            }

            # Auto-Reply Settings
            try {
                $autoReplyConfig = Get-MailboxAutoReplyConfiguration -Identity $mailbox.UserPrincipalName

                if ($autoReplyConfig.AutoReplyState -ne "Disabled") {
                    Write-Output "  - Auto-reply is enabled."
                    write-log -Message "Auto-reply is enabled."
                } else {
                    Write-Output "  - Auto-reply is disabled."
                    Write-Log -Message "Auto-reply is disabled."
                }
            } catch {
                Write-Output "  - Error retrieving auto-reply settings for $($mailbox.UserPrincipalName)."
                write-log -Message "Error retrieving auto-reply settings for $($mailbox.UserPrincipalName)."
            }
        }
    } # end of main loop

# Gracefully disconnect from Exchange Online
Disconnect-ExchangeOnline -Confirm:$false
}

# Export the function as a module
Export-ModuleMember -Function Invoke-MailboxCheck
