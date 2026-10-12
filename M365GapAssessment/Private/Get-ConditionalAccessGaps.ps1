# Conditional Access policy checks that follow CIS Microsoft 365 Foundations 5.2.2.x. Each check looks for at least one ENABLED policy
# with the shape the benchmark asks for. Report-only and disabled policies never count. Exclusions are not judged (a break-glass
# exclusion is expected), but they are named in the detail so a reviewer can confirm only documented accounts are excluded.

# The directory roles CIS asks to protect "at a minimum". They are looked up by name in the tenant's role templates at run time, so
# no role id is hard-coded.
$script:CaAdminRoleNames = @(
    'Application Administrator', 'Authentication Administrator', 'Billing Administrator', 'Cloud Application Administrator',
    'Conditional Access Administrator', 'Exchange Administrator', 'Global Administrator', 'Global Reader', 'Helpdesk Administrator',
    'Password Administrator', 'Privileged Authentication Administrator', 'Privileged Role Administrator', 'Security Administrator',
    'SharePoint Administrator', 'User Administrator'
)
# Authentication strength combinations that CIS accepts as phishing-resistant.
$script:CaPhishingResistantCombinations = @('windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor')
# Exchange Online, SharePoint Online and Teams: the resources token protection must cover.
$script:CaTokenProtectionApps = @('00000002-0000-0ff1-ce00-000000000000', '00000003-0000-0ff1-ce00-000000000000', 'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe')

function Get-CaValues {
    # Non-empty entries of a Graph list property; safe on $null, a single value or an array.
    param($Value)
    @($Value | Where-Object { $null -ne $_ -and "$_" -ne '' })
}

function Test-CaUsersAll { param($Policy) (Get-CaValues $Policy.conditions.users.includeUsers) -contains 'All' }
function Test-CaAppsAll { param($Policy) (Get-CaValues $Policy.conditions.applications.includeApplications) -contains 'All' }
function Test-CaBlocks { param($Policy) (Get-CaValues $Policy.grantControls.builtInControls) -contains 'block' }

function Get-CaTransferMethods {
    # transferMethods is a flags enum; Graph serialises several values as one comma-separated string ("deviceCodeFlow,authenticationTransfer").
    param($Policy)
    @("$($Policy.conditions.authenticationFlows.transferMethods)" -split '[,\s]+' | Where-Object { $_ })
}

function Test-CaSignInFrequency {
    # Sign-in frequency enabled and no longer than MaxHours (or "every time").
    param($Policy, [Parameter(Mandatory)][double]$MaxHours)
    $f = $Policy.sessionControls.signInFrequency
    if (-not $f -or -not $f.isEnabled) { return $false }
    if ("$($f.frequencyInterval)" -eq 'everyTime') { return $true }
    $v = [double]$f.value
    $hours = if ("$($f.type)" -eq 'days') { $v * 24 } else { $v }
    $v -gt 0 -and $hours -le $MaxHours
}

function Get-CaMissingAdminRoles {
    # Names of the required admin roles a policy does not include. A policy that includes All users covers every role.
    param($Policy, [Parameter(Mandatory)][hashtable]$RoleIdByName)
    if (Test-CaUsersAll $Policy) { return @() }
    $included = Get-CaValues $Policy.conditions.users.includeRoles
    @($RoleIdByName.Keys | Where-Object { $RoleIdByName[$_] -notin $included } | Sort-Object)
}

function Get-CaExclusionNote {
    param($Policy)
    $u = $Policy.conditions.users
    $parts = @()
    $n = (Get-CaValues $u.excludeUsers).Count; if ($n) { $parts += "$n user(s)" }
    $n = (Get-CaValues $u.excludeGroups).Count; if ($n) { $parts += "$n group(s)" }
    $n = (Get-CaValues $u.excludeRoles).Count; if ($n) { $parts += "$n role(s)" }
    $n = (Get-CaValues $Policy.conditions.applications.excludeApplications).Count; if ($n) { $parts += "$n app(s)" }
    if ($parts) { " [excludes $($parts -join ', ')]" } else { '' }
}

function Format-CaPolicies {
    param($Policies)
    (@($Policies) | ForEach-Object { "$($_.displayName)$(Get-CaExclusionNote $_)" }) -join '; '
}

function Get-ConditionalAccessGaps {
    <#
    .SYNOPSIS
        Conditional Access checks derived from CIS 5.2.2.x (all-user MFA, admin session and strength, registration device, blocked
        authentication flows, reauthentication, geographic block, token protection).
    #>
    [CmdletBinding()]
    param()

    # --- Controls for all users and all resources --------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra policy' -Status 'Conditional Access controls' -PercentComplete 48
    Invoke-Collector -Name 'Conditional Access: all-user controls' -FindingIds 'ENT-CA-010', 'ENT-CA-013', 'ENT-CA-014', 'ENT-CA-015', 'ENT-CA-017', 'ENT-CA-018' -Script {
        $enabled = @(Get-ConditionalAccessPolicies | Where-Object { $_.state -eq 'enabled' })

        # ENT-CA-010: MFA for all users on all resources.
        $mfaAll = @($enabled | Where-Object { (Test-CaUsersAll $_) -and (Test-CaAppsAll $_) -and (Test-PolicyEnforcesMfa -Policy $_) })
        $mfaRejected = @($enabled | Where-Object { (Test-CaUsersAll $_) -and (Test-CaAppsAll $_) -and (Test-PolicyMentionsMfa -Policy $_) -and -not (Test-PolicyEnforcesMfa -Policy $_) })
        $detail = if ($mfaAll.Count) { "Enforced by: $(Format-CaPolicies $mfaAll)" } else { 'No enabled Conditional Access policy requires MFA or an authentication strength for all users on all resources.' }
        if (-not $mfaAll.Count -and $mfaRejected.Count) { $detail += " Not counted because MFA is only one of several alternatives (operator OR): $($mfaRejected.displayName -join ', ')." }
        if (-not $mfaAll.Count -and (Get-SecurityDefaultsState) -eq $true) {
            $detail += ' Security Defaults is on and applies MFA, but it is not a Conditional Access policy, which is what the benchmark asks for.'
        }
        New-Finding -Id 'ENT-CA-010' -Status $(if ($mfaAll.Count) { 'Pass' } else { 'Gap' }) -Detail $detail

        # ENT-CA-013: a compliant (or hybrid-joined) device is required to register security information.
        $register = @($enabled | Where-Object {
                $b = Get-CaValues $_.grantControls.builtInControls
                (Test-CaUsersAll $_) -and ((Get-CaValues $_.conditions.applications.includeUserActions) -contains 'urn:user:registersecurityinfo') -and
                ($b -contains 'compliantDevice') -and (@($b | Where-Object { $_ -notin 'compliantDevice', 'domainJoinedDevice' }).Count -eq 0) -and
                ($null -eq $_.grantControls.authenticationStrength) -and ($b.Count -eq 1 -or $_.grantControls.operator -eq 'OR')
            })
        New-Finding -Id 'ENT-CA-013' -Status $(if ($register.Count) { 'Pass' } else { 'Gap' }) `
            -Detail $(if ($register.Count) { "Enforced by: $(Format-CaPolicies $register)" } else { 'No enabled policy for the "register security information" user action requires a compliant device (optionally hybrid joined) for all users.' })

        # ENT-CA-014 / ENT-CA-018: device code flow and authentication transfer blocked.
        foreach ($flow in @(
                @{ Id = 'ENT-CA-014'; Method = 'deviceCodeFlow'; Label = 'the device code sign-in flow' },
                @{ Id = 'ENT-CA-018'; Method = 'authenticationTransfer'; Label = 'authentication transfer' })) {
            $blocking = @($enabled | Where-Object { (Test-CaUsersAll $_) -and (Test-CaAppsAll $_) -and (Test-CaBlocks $_) -and ((Get-CaTransferMethods $_) -contains $flow.Method) })
            New-Finding -Id $flow.Id -Status $(if ($blocking.Count) { 'Pass' } else { 'Gap' }) `
                -Detail $(if ($blocking.Count) { "Blocked by: $(Format-CaPolicies $blocking)" } else { "No enabled policy blocks $($flow.Label) for all users on all resources." })
        }

        # ENT-CA-015: periodic reauthentication of 7 days or less for all users. Risk-based policies are ignored, as the benchmark does.
        $reauth = @($enabled | Where-Object {
                (Test-CaUsersAll $_) -and (Test-CaAppsAll $_) -and -not (Test-HasItems $_.conditions.signInRiskLevels) -and
                -not (Test-HasItems $_.conditions.userRiskLevels) -and (Test-CaSignInFrequency -Policy $_ -MaxHours 168)
            })
        New-Finding -Id 'ENT-CA-015' -Status $(if ($reauth.Count) { 'Pass' } else { 'Gap' }) `
            -Detail $(if ($reauth.Count) { "Enforced by: $(Format-CaPolicies $reauth)" } else { 'No enabled policy sets a sign-in frequency of 7 days or less (or every time) for all users on all resources.' })

        # ENT-CA-017: token protection for sign-in sessions on Exchange, SharePoint and Teams (Windows desktop clients).
        $tokenPolicies = @($enabled | Where-Object { $_.sessionControls.secureSignInSession.isEnabled })
        $tokenOk = @($tokenPolicies | Where-Object {
                $apps = Get-CaValues $_.conditions.applications.includeApplications
                $appsCovered = ($apps -contains 'All') -or (@($script:CaTokenProtectionApps | Where-Object { $_ -notin $apps }).Count -eq 0)
                $clients = @(Get-CaValues $_.conditions.clientAppTypes)   # @() keeps a single value an array, so [0] is the value, not its first character
                $platforms = Get-CaValues $_.conditions.platforms.includePlatforms
                $appsCovered -and ($clients.Count -eq 1 -and $clients[0] -eq 'mobileAppsAndDesktopClients') -and (($platforms -contains 'windows') -or ($platforms -contains 'all'))
            })
        $tokenDetail = if ($tokenOk.Count) { "Enforced by: $(Format-CaPolicies $tokenOk)" }
        elseif ($tokenPolicies.Count) { "Token protection is used by $($tokenPolicies.displayName -join ', ') but does not cover Exchange Online, SharePoint Online and Teams for Windows desktop clients only." }
        else { 'No enabled policy requires token protection for sign-in sessions.' }
        New-Finding -Id 'ENT-CA-017' -Status $(if ($tokenOk.Count) { 'Pass' } else { 'Gap' }) -Detail $tokenDetail
    }

    # --- Controls for administrators ------------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra policy' -Status 'Conditional Access administrator controls' -PercentComplete 50
    Invoke-Collector -Name 'Conditional Access: administrator controls' -FindingIds 'ENT-CA-011', 'ENT-CA-012' -Script {
        $templates = @(Get-GraphPagedResult -Uri '/v1.0/directoryRoleTemplates?$select=id,displayName')
        $roleId = @{}
        foreach ($name in $script:CaAdminRoleNames) {
            $t = $templates | Where-Object { $_.displayName -eq $name } | Select-Object -First 1
            if ($t) { $roleId[$name] = [string]$t.id }
        }
        $unknown = @($script:CaAdminRoleNames | Where-Object { -not $roleId.ContainsKey($_) })
        if ($unknown.Count) { throw "These directory roles were not found in the tenant's role templates: $($unknown -join ', ')." }

        $enabled = @(Get-ConditionalAccessPolicies | Where-Object { $_.state -eq 'enabled' })
        $adminAllApps = @($enabled | Where-Object { (Test-CaAppsAll $_) -and (Get-CaMissingAdminRoles -Policy $_ -RoleIdByName $roleId).Count -eq 0 })

        # ENT-CA-011: sign-in frequency of 4 hours or less and no persistent browser session for administrators.
        $session = @($adminAllApps | Where-Object {
                (Test-CaSignInFrequency -Policy $_ -MaxHours 4) -and $_.sessionControls.persistentBrowser.isEnabled -and "$($_.sessionControls.persistentBrowser.mode)" -eq 'never'
            })
        $sessionDetail = if ($session.Count) { "Enforced by: $(Format-CaPolicies $session)" } else {
            $near = @($enabled | Where-Object { (Test-CaAppsAll $_) -and ($_.sessionControls.signInFrequency.isEnabled -or $_.sessionControls.persistentBrowser.isEnabled) -and (Get-CaMissingAdminRoles -Policy $_ -RoleIdByName $roleId).Count -lt $roleId.Count })
            $text = 'No enabled policy covering the administrator roles on all resources sets a sign-in frequency of 4 hours or less together with a never-persistent browser session.'
            if ($near.Count) { $text += " Session controls exist but do not meet this for administrators: $($near.displayName -join ', ')." }
            $text
        }
        New-Finding -Id 'ENT-CA-011' -Status $(if ($session.Count) { 'Pass' } else { 'Gap' }) -Detail $sessionDetail

        # ENT-CA-012: phishing-resistant authentication strength for administrators.
        $strongPolicies = @($adminAllApps | Where-Object { $null -ne $_.grantControls.authenticationStrength -and (Test-PolicyEnforcesMfa -Policy $_) })
        $resistant = @(); $unreadable = @(); $weak = @()
        foreach ($p in $strongPolicies) {
            $combos = Get-CaValues $p.grantControls.authenticationStrength.allowedCombinations
            if (-not $combos.Count) { $unreadable += $p.displayName }
            elseif (@($combos | Where-Object { $_ -notin $script:CaPhishingResistantCombinations }).Count -eq 0) { $resistant += $p }
            else { $weak += $p.displayName }
        }
        if ($resistant.Count) {
            New-Finding -Id 'ENT-CA-012' -Status Pass -Detail "Enforced by: $(Format-CaPolicies $resistant)"
        }
        elseif ($unreadable.Count) {
            New-Finding -Id 'ENT-CA-012' -Status NotAssessed -Detail "The allowed methods of the authentication strength could not be read for: $($unreadable -join ', ')."
        }
        else {
            $text = 'No enabled policy requires a phishing-resistant authentication strength (Windows Hello for Business, FIDO2 or certificate-based) for the administrator roles on all resources.'
            if ($weak.Count) { $text += " Authentication strengths that also allow weaker methods: $($weak -join ', ')." }
            New-Finding -Id 'ENT-CA-012' -Status Gap -Detail $text
        }
    }

    # --- Geographic access control ------------------------------------------------------------------------
    Invoke-Collector -Name 'Conditional Access: geographic block' -FindingIds 'ENT-CA-016' -Script {
        $locations = @(Get-GraphPagedResult -Uri '/v1.0/identity/conditionalAccess/namedLocations')
        # Country locations have no trusted flag and count as untrusted; IP locations are trusted only when marked so.
        $untrusted = @($locations | Where-Object { -not $_.isTrusted } | ForEach-Object { [string]$_.id })
        $enabled = @(Get-ConditionalAccessPolicies | Where-Object { $_.state -eq 'enabled' })
        $geo = @($enabled | Where-Object {
                $include = Get-CaValues $_.conditions.locations.includeLocations
                $exclude = Get-CaValues $_.conditions.locations.excludeLocations
                (Test-CaUsersAll $_) -and (Test-CaAppsAll $_) -and (Test-CaBlocks $_) -and $exclude.Count -gt 0 -and
                (($include -contains 'All') -or (@($include | Where-Object { $_ -in $untrusted }).Count -gt 0))
            })
        New-Finding -Id 'ENT-CA-016' -Status $(if ($geo.Count) { 'Pass' } else { 'Gap' }) `
            -Detail $(if ($geo.Count) { "Blocked outside the excluded locations by: $(Format-CaPolicies $geo)" } else { 'No enabled policy blocks all users on all resources from untrusted locations while excluding trusted ones (for example everywhere except the countries you operate in).' })
    }
}
