function Test-TenantIdentifier {
    <#
    .SYNOPSIS
        True when the value is a tenant GUID or a plain domain name (contoso.onmicrosoft.com). Rejects anything else
        before it reaches a sign-in call, a folder name or a URL.
    #>
    [CmdletBinding()]
    param([string]$Value)
    $Value -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$' -or
    $Value -match '^(?=.{4,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
}

function Read-TenantIdentifier {
    <#
    .SYNOPSIS
        Prompts for one or more tenants (comma separated) instead of relying on a value stored in a script or file.
    #>
    [CmdletBinding()]
    param()
    if (-not [Environment]::UserInteractive) { throw 'No -TenantId supplied and the session is not interactive; pass -TenantId explicitly.' }
    $answer = Read-Host 'Tenant ID or primary domain to assess (comma separate for several)'
    $tenants = @($answer -split '[,;\s]+' | Where-Object { $_ })
    if (-not $tenants.Count) { throw 'No tenant supplied.' }
    foreach ($t in $tenants) { if (-not (Test-TenantIdentifier $t)) { throw "'$t' is not a tenant GUID or a domain name." } }
    $tenants
}

function Protect-ExportPath {
    <#
    .SYNOPSIS
        Restricts a report folder to the current user (700 folder / 600 files) on macOS and Linux. Reports hold tenant IDs,
        user principal names and security gaps, so they should not be world-readable on a shared machine.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if ($IsWindows) { return }
    try {
        if ([IO.File].GetMethod('SetUnixFileMode', [type[]]@([string], [IO.UnixFileMode]))) {
            [IO.File]::SetUnixFileMode($Path, [IO.UnixFileMode]'UserRead,UserWrite,UserExecute')
            foreach ($f in Get-ChildItem -LiteralPath $Path -File) { [IO.File]::SetUnixFileMode($f.FullName, [IO.UnixFileMode]'UserRead,UserWrite') }
            return
        }
    }
    catch { }
    if (Get-Command chmod -ErrorAction SilentlyContinue) {
        & chmod 700 $Path
        Get-ChildItem -LiteralPath $Path -File | ForEach-Object { & chmod 600 $_.FullName }
    }
}
