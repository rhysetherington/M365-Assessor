@{
    Severity     = @('Error', 'Warning')
    # Rules switched off on purpose, each with the reason. Everything else must be clean (CI fails on any warning).
    ExcludeRules = @(
        # Collector parameters are read inside the script blocks handed to Invoke-Collector, which the analyzer cannot see
        # into; it reports them as unused although they are not.
        'PSReviewUnusedParameter'
        # Established public and internal names (Get-EntraIDGaps, Set-AcceptedRisk, ...). Renaming them would break callers.
        'PSUseSingularNouns'
        # New-Finding, New-AssessmentHtml, Start-ExchangeSession and similar build objects or strings or open read-only
        # sessions in memory. They change no system state, so -WhatIf/-Confirm would be meaningless.
        'PSUseShouldProcessForStateChangingFunctions'
        # Deliberate best-effort lookups (optional metadata, cache clean-up, permission tightening) where failure must not
        # stop an assessment. Anything that affects a result is reported as NotAssessed instead.
        'PSAvoidUsingEmptyCatchBlock'
        # Coloured header of the interactive details prompt, shown only in an interactive session.
        'PSAvoidUsingWriteHost'
    )
}
