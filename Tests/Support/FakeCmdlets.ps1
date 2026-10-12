# Fake Exchange / compliance cmdlets for offline collector tests. Dot-source from BeforeAll AFTER importing the module.
#
# Set-FakeCmdlets defines each named cmdlet as a function inside the module, returning the value given for it (a scriptblock is
# invoked instead, so `{ throw 'forbidden' }` simulates a refused call). Calling it again first REMOVES the previous fakes, so a
# cmdlet that is not in the new table is genuinely absent (Get-Command fails), which is how a missing licence looks in practice.

function script:Set-FakeCmdlets {
    param([hashtable]$Data = @{})
    InModuleScope M365GapAssessment -Parameters @{ D = $Data } {
        # Never pass an empty name: "Function:\" is the whole function table, and Remove-Item would offer to delete all of it.
        foreach ($old in @($script:FakeCmdletNames | Where-Object { $_ -match '^[\w-]+$' })) { Remove-Item -Path "Function:\$old" -ErrorAction SilentlyContinue }
        $script:FakeCmdletNames = @()
        $script:FakeCmdlets = $D
        foreach ($name in $D.Keys) {
            Invoke-Expression ("function script:$name { param([Parameter(ValueFromRemainingArguments = `$true)]`$Rest) " +
                "`$v = `$script:FakeCmdlets['$name']; if (`$v -is [scriptblock]) { & `$v } else { `$v } }")
            $script:FakeCmdletNames += $name
        }
    }
}

# Runs a command string in the module with the fake cmdlets in place; returns findings keyed by ID.
function script:Invoke-WithCmdlets {
    param([hashtable]$Data, [Parameter(Mandatory)][string]$Command)
    Set-FakeCmdlets -Data $Data
    $findings = InModuleScope M365GapAssessment -Parameters @{ C = $Command } { & ([scriptblock]::Create("$C 3>`$null")) }
    $byId = @{}
    foreach ($f in @($findings)) { if ($f.FindingId) { $byId[$f.FindingId] = $f } }
    $byId
}
