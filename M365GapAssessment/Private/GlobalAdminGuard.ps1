# Guard against running a read-only assessment with a Global Administrator account by accident, or from a script that was written
# to do so without anyone choosing it. Global Reader is enough for every check, and a Global Administrator token is a far more
# valuable thing to expose. A person is asked to confirm; a session that cannot ask is stopped unless -AllowGlobalAdministrator
# was passed on purpose.

$script:GlobalAdminAcknowledged = $null

function Test-InteractiveSession {
    <#
    .SYNOPSIS
        $true when a person can answer a prompt: an interactive host with input that is not redirected or piped.
    #>
    [CmdletBinding()]
    param()
    [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
}

function Read-GlobalAdminConfirmation {
    # Separate from the guard so tests can supply an answer instead of reading the keyboard.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Prompt)
    Read-Host $Prompt
}

function Get-SignedInDirectoryRoles {
    <#
    .SYNOPSIS
        The display names of the directory roles the signed-in user currently holds (active assignments only; a role that is
        eligible in PIM but not activated does not appear).
    #>
    [CmdletBinding()]
    param()
    @(Get-GraphPagedResult -Uri '/v1.0/me/memberOf/microsoft.graph.directoryRole?$select=displayName' | ForEach-Object { $_.displayName })
}

function Confirm-GlobalAdministratorUse {
    <#
    .SYNOPSIS
        Called when the signed-in account holds Global Administrator. Allows the run only if the person confirms, or
        -Allow was passed deliberately; otherwise disconnects and throws so nothing is assessed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Account,
        [Parameter(Mandatory)][string]$TenantId,
        [switch]$Allow
    )

    $key = "$TenantId|$Account"
    if ($script:GlobalAdminAcknowledged -eq $key) { return }   # already confirmed for this sign-in

    $stop = {
        param($message)
        Disconnect-MgGraph | Out-Null
        $script:AssessmentContext = $null
        throw $message
    }

    if ($Allow) {
        Write-Warning "Signed in as '$Account', which holds the Global Administrator role (allowed by -AllowGlobalAdministrator). This tool only reads data: Global Reader is enough."
        $script:GlobalAdminAcknowledged = $key
        return
    }

    $nonInteractive = "Signed in as '$Account', which holds the Global Administrator role, in a session that cannot ask for confirmation (non-interactive or redirected input). Nothing was assessed. Use a Global Reader account, or pass -AllowGlobalAdministrator to run as Global Administrator on purpose."
    if (-not (Test-InteractiveSession)) { & $stop $nonInteractive }

    Write-Warning "You are signed in as '$Account', which holds the Global Administrator role. This assessment only reads data: Global Reader is enough, and a Global Administrator token is a much more valuable target if it is exposed or a script misbehaves."
    try { $answer = Read-GlobalAdminConfirmation -Prompt 'Continue as Global Administrator? [y/N]' }
    catch { & $stop $nonInteractive }

    if ("$answer".Trim() -match '^(y|yes)$') {
        $script:GlobalAdminAcknowledged = $key
        return
    }
    & $stop "Cancelled: '$Account' holds the Global Administrator role and was not confirmed. Sign in with a Global Reader account, answer 'y' to continue, or pass -AllowGlobalAdministrator."
}
