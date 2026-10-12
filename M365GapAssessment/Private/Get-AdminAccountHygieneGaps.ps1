# Administrator account hygiene from CIS Microsoft 365 Foundations 1.1.1 and 1.1.4: administrators should be cloud-only accounts, and
# the accounts that hold standing admin roles should not carry licences with a mail / Office / Teams footprint.

# A service plan with one of these names means the licence gives the account applications (mailbox, SharePoint, Teams, Office apps).
# Only plans that are switched on count, so an admin on a full licence with those plans turned off still passes.
# EXCHANGE_S_FOUNDATION is excluded: it is the base directory plan that even the free Power Automate licence carries, and gives no mailbox.
$script:AdminAppFootprintPlanPattern = '^(EXCHANGE_S_(?!FOUNDATION)|SHAREPOINT|TEAMS1|MCO|OFFICESUBSCRIPTION|OFFICEMOBILE|YAMMER|SWAY|FORMS_PLAN|PROJECTWORKMANAGEMENT|BPOS_S_TODO|MICROSOFTBOOKINGS|WHITEBOARD|MICROSOFT_PLANNER|POWERAPPS_O365|FLOW_O365|STREAM_O365)'

function Test-AdministratorRoleName {
    # The benchmark's definition of an administrative role: any role named "...Administrator", plus Global Reader.
    param([string]$Name)
    $Name -like '*Administrator*' -or $Name -eq 'Global Reader'
}

function Get-LicenseAppFootprint {
    <#
    .SYNOPSIS
        For one user's license details, the SKUs that give the account applications and the enabled service plans that do so.
    #>
    param($LicenseDetails)
    foreach ($lic in @($LicenseDetails)) {
        if (-not $lic) { continue }
        $plans = @($lic.servicePlans | Where-Object { $_.servicePlanName -match $script:AdminAppFootprintPlanPattern -and "$($_.provisioningStatus)" -ne 'Disabled' })
        if ($plans.Count) { [pscustomobject]@{ Sku = [string]$lic.skuPartNumber; Plans = @($plans.servicePlanName | Sort-Object -Unique) } }
    }
}

function Get-AdminAccountHygieneGaps {
    <#
    .SYNOPSIS
        ENT-USR-007 (CIS 1.1.1, hybrid admin accounts) and ENT-USR-008 (CIS 1.1.4, admin accounts with an application licence).
    .DESCRIPTION
        Two collectors share one read of the role assignments. If the licence lookup fails only ENT-USR-008 is NotAssessed; if the
        role assignments cannot be read both are.
    #>
    [CmdletBinding()]
    param()

    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra ID' -Status 'Administrator account hygiene' -PercentComplete 33
    $shared = @{ Ready = $false }

    Invoke-Collector -Name 'Administrator accounts' -FindingIds 'ENT-USR-007' -Script {
        $active = @(Get-GraphPagedResult -Uri '/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal,roleDefinition' |
                Where-Object { Test-AdministratorRoleName $_.roleDefinition.displayName })
        $eligible = @(Get-GraphPagedResult -Uri '/v1.0/roleManagement/directory/roleEligibilitySchedules?$expand=principal,roleDefinition' |
                Where-Object { Test-AdministratorRoleName $_.roleDefinition.displayName })
        $isUser = { $_.principal.'@odata.type' -eq '#microsoft.graph.user' }
        $groups = @(($active + $eligible) | Where-Object { $_.principal.'@odata.type' -eq '#microsoft.graph.group' } | ForEach-Object { $_.principal.displayName } | Sort-Object -Unique)

        $assignments = @($active | Where-Object $isUser) + @($eligible | Where-Object $isUser)
        $userIds = @($assignments | ForEach-Object { $_.principalId } | Sort-Object -Unique)
        $users = @{}
        foreach ($id in $userIds) {
            $users[$id] = Invoke-GraphRequestWithRetry -Uri "/v1.0/users/$id`?`$select=id,userPrincipalName,displayName,onPremisesSyncEnabled"
        }
        $groupNote = if ($groups.Count) { " $($groups.Count) role-assigned group(s) were not expanded: $($groups -join ', ')." } else { '' }

        # Hand the role data to the licence check.
        $shared.Active = $active; $shared.Users = $users; $shared.GroupNote = $groupNote; $shared.Ready = $true

        # ENT-USR-007: administrators synced from on-premises Active Directory (active or eligible).
        $hybrid = @($assignments | Where-Object { $users[$_.principalId].onPremisesSyncEnabled -eq $true } |
                ForEach-Object { "$($users[$_.principalId].userPrincipalName) - $($_.roleDefinition.displayName)" } | Sort-Object -Unique)
        New-Finding -Id 'ENT-USR-007' -Status $(if ($hybrid.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $hybrid `
            -Detail "$($userIds.Count) user(s) hold administrator roles (active or eligible); $($hybrid.Count) assignment(s) belong to accounts synced from on-premises.$groupNote"
    }

    Invoke-Collector -Name 'Administrator licences' -FindingIds 'ENT-USR-008' -Script {
        if (-not $shared.Ready) { throw 'The administrator role assignments could not be read.' }
        # Accounts with a permanent active assignment that also hold an application licence. Accounts that are only eligible
        # (activated through PIM) are exempt, as the benchmark allows.
        $isUser = { $_.principal.'@odata.type' -eq '#microsoft.graph.user' }
        $standing = @($shared.Active | Where-Object $isUser | Where-Object { $_.assignmentType -eq 'Assigned' } | ForEach-Object { $_.principalId } | Sort-Object -Unique)
        $licensed = foreach ($id in $standing) {
            $details = @(Get-GraphPagedResult -Uri "/v1.0/users/$id/licenseDetails")
            $footprint = @(Get-LicenseAppFootprint -LicenseDetails $details)
            if ($footprint.Count) { "$($shared.Users[$id].userPrincipalName) - $(($footprint | ForEach-Object { "$($_.Sku): $($_.Plans -join ', ')" }) -join '; ')" }
        }
        New-Finding -Id 'ENT-USR-008' -Status $(if (@($licensed).Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($licensed) `
            -Detail "$($standing.Count) account(s) have a permanent active administrator assignment; $(@($licensed).Count) of them hold a licence with mail, Office, SharePoint or Teams enabled. Admin accounts should use a licence without applications (for example Entra ID P1 or P2), or be eligible-only through PIM.$($shared.GroupNote)"
    }
}
