function Resolve-DnsRecordValue {
    <#
    .SYNOPSIS
        Cross-platform DNS lookup. Uses Resolve-DnsName where it exists (Windows); otherwise DNS-over-HTTPS (JSON API).
        Returns an array of record strings (TXT joined, MX exchange host, CNAME target); empty when the name has no such record.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('TXT', 'MX', 'CNAME')][string]$Type,
        [string]$DohEndpoint = 'https://cloudflare-dns.com/dns-query'
    )

    if ($null -eq $script:UseNativeDns) { $script:UseNativeDns = [bool](Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) }

    if ($script:UseNativeDns) {
        try { $records = @(Resolve-DnsName -Name $Name -Type $Type -DnsOnly -ErrorAction Stop) } catch { return @() }
        switch ($Type) {
            'TXT' { return @($records | Where-Object { $_.Type -eq 'TXT' } | ForEach-Object { $_.Strings -join '' }) }
            'MX' { return @($records | Where-Object { $_.Type -eq 'MX' } | ForEach-Object { $_.NameExchange }) }
            'CNAME' { return @($records | Where-Object { $_.Type -eq 'CNAME' } | ForEach-Object { $_.NameHost }) }
        }
    }

    $typeCode = @{ TXT = 16; MX = 15; CNAME = 5 }[$Type]
    $uri = '{0}?name={1}&type={2}' -f $DohEndpoint, [uri]::EscapeDataString($Name), $Type
    $response = Invoke-RestMethod -Uri $uri -Headers @{ Accept = 'application/dns-json' } -TimeoutSec 15 -ErrorAction Stop
    # Note: inside a switch, $_ is rebound to the switch value, so read the record into $data first.
    @($response.Answer | Where-Object { $_.type -eq $typeCode } | ForEach-Object {
            $data = [string]$_.data
            switch ($Type) {
                'TXT' { ($data -replace '"\s*"', '').Trim('"') }
                'MX' { ($data -split '\s+')[-1].TrimEnd('.') }
                'CNAME' { $data.TrimEnd('.') }
            }
        })
}

function Get-EmailDnsGaps {
    <#
    .SYNOPSIS
        SPF, DMARC and DKIM checks for the tenant's verified custom email domains.
    #>
    [CmdletBinding()]
    param([string]$DohEndpoint = 'https://cloudflare-dns.com/dns-query')

    $ids = 'EML-001', 'EML-002', 'EML-003'
    Write-Progress -Id 2 -ParentId 1 -Activity 'Email security' -Status 'Listing verified domains' -PercentComplete 5

    $domains = $null
    Invoke-Collector -Name 'Verified domains' -FindingIds $ids -Script {
        $all = @(Get-GraphPagedResult -Uri '/v1.0/domains?$select=id,isVerified,supportedServices')
        $script:emailDomains = @($all | Where-Object { $_.isVerified -and $_.id -notmatch '\.onmicrosoft\.com$' -and ($_.supportedServices -contains 'Email') } | ForEach-Object { $_.id } | Sort-Object)
    }   # on failure this emits NotAssessed findings and leaves $script:emailDomains unset
    $domains = $script:emailDomains
    $script:emailDomains = $null
    if ($null -eq $domains) { return }

    if (-not $domains.Count) {
        foreach ($id in $ids) { New-Finding -Id $id -Status Pass -Detail 'No verified custom email domains (only *.onmicrosoft.com).' }
        Write-Progress -Id 2 -ParentId 1 -Activity 'Email security' -Completed
        return
    }

    # --- SPF ----------------------------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Email security' -Status 'SPF' -PercentComplete 25
    Invoke-Collector -Name 'SPF' -FindingIds 'EML-001' -Script {
        $issues = foreach ($d in $domains) {
            $spf = @(Resolve-DnsRecordValue -Name $d -Type TXT -DohEndpoint $DohEndpoint | Where-Object { $_ -match '^\s*v=spf1\b' })
            if ($spf.Count -eq 0) { "$d - no SPF record" }
            elseif ($spf.Count -gt 1) { "$d - multiple SPF records (invalid)" }
            elseif ($spf[0] -match '\s[+?]all\b') { "$d - permissive terminal mechanism ($($Matches[0].Trim()))" }
            elseif ($spf[0] -notmatch '\s[-~]all\b') { "$d - no terminal 'all' mechanism" }
        }
        New-Finding -Id 'EML-001' -Status $(if (@($issues).Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($issues) `
            -Detail "$($domains.Count) domain(s) checked: $($domains -join ', ')"
    }

    # --- DMARC --------------------------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Email security' -Status 'DMARC' -PercentComplete 55
    Invoke-Collector -Name 'DMARC' -FindingIds 'EML-002' -Script {
        $issues = foreach ($d in $domains) {
            $record = @(Resolve-DnsRecordValue -Name "_dmarc.$d" -Type TXT -DohEndpoint $DohEndpoint | Where-Object { $_ -match '^\s*v=DMARC1' })
            $source = $d
            if (-not $record.Count) {
                # A subdomain inherits the organisational domain's policy when that parent is also a verified domain.
                $parent = ($d -split '\.', 2)[1]
                if ($parent -in $domains) {
                    $record = @(Resolve-DnsRecordValue -Name "_dmarc.$parent" -Type TXT -DohEndpoint $DohEndpoint | Where-Object { $_ -match '^\s*v=DMARC1' })
                    $source = $parent
                }
            }
            if (-not $record.Count) { "$d - no DMARC record" }
            elseif ($record[0] -match 'p\s*=\s*none') { "$d - policy p=none (monitoring only; from $source)" }
        }
        New-Finding -Id 'EML-002' -Status $(if (@($issues).Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($issues)
    }

    # --- DKIM (Exchange Online selectors; only domains whose MX points at EOP) ----------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Email security' -Status 'DKIM' -PercentComplete 80
    Invoke-Collector -Name 'DKIM' -FindingIds 'EML-003' -Script {
        $checked = 0
        $issues = foreach ($d in $domains) {
            $mx = @(Resolve-DnsRecordValue -Name $d -Type MX -DohEndpoint $DohEndpoint)
            if (-not ($mx | Where-Object { $_ -match 'mail\.protection\.outlook\.com$' })) { continue }
            $checked++
            $sel = @('selector1', 'selector2') | Where-Object { @(Resolve-DnsRecordValue -Name "$_._domainkey.$d" -Type CNAME -DohEndpoint $DohEndpoint).Count }
            if (-not @($sel).Count) { "$d - no Exchange Online DKIM selector records (selector1/selector2._domainkey)" }
        }
        New-Finding -Id 'EML-003' -Status $(if (@($issues).Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($issues) `
            -Detail "$checked domain(s) route mail through Exchange Online Protection and were evaluated."
    }
    Write-Progress -Id 2 -ParentId 1 -Activity 'Email security' -Completed
}
