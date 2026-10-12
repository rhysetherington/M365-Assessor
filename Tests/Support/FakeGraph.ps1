# Fake Microsoft Graph layer for offline collector tests. Dot-source from BeforeAll AFTER importing the module.
#
# Replaces Invoke-GraphRequestWithRetry and Get-GraphPagedResult inside the module with a fixture-driven fake.
# A fixture is a list of { Match, Data }: the first entry whose Match text appears in the requested URI wins.
# Data may be a scriptblock (it is invoked, so `{ throw 'forbidden' }` simulates a Graph error).
# Requests with no matching entry throw, which collectors report as NotAssessed.

function script:J($Json) { $Json | ConvertFrom-Json }

function script:Enable-FakeGraph {
    InModuleScope M365GapAssessment {
        $script:Fixture = @()
        function script:Resolve-Fixture {
            param($Uri)
            foreach ($e in $script:Fixture) {
                if ($Uri.Contains($e.Match)) { if ($e.Data -is [scriptblock]) { return (& $e.Data) } else { return $e.Data } }
            }
            throw "No fixture for $Uri"
        }
        function script:Invoke-GraphRequestWithRetry { param($Uri, $Headers, $MaxRetries) Resolve-Fixture $Uri }
        function script:Get-GraphPagedResult {
            param($Uri, $Headers, $MaxItems)
            $r = Resolve-Fixture $Uri
            if ($null -ne $r.value) { @($r.value) } else { $r }
        }
    }
}

# Builds a fixture list from an ordered hashtable of Match -> Data.
function script:ConvertTo-Fixture {
    param([System.Collections.IDictionary]$Table)
    @($Table.Keys | ForEach-Object { [pscustomobject]@{ Match = $_; Data = $Table[$_] } })
}

# Runs a command string inside the module with the given fixture; warnings are suppressed. Returns findings keyed by ID.
function script:Invoke-WithFixture {
    param([object[]]$Fixture, [Parameter(Mandatory)][string]$Command)
    $findings = InModuleScope M365GapAssessment -Parameters @{ F = $Fixture; C = $Command } {
        $script:Fixture = $F
        Reset-CollectorCache   # per-run caches must not leak between tests
        & ([scriptblock]::Create("$C 3>`$null"))
    }
    $byId = @{}
    foreach ($f in @($findings)) { if ($f.FindingId) { $byId[$f.FindingId] = $f } }
    $byId
}
