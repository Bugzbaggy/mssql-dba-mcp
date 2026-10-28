<#
.SYNOPSIS
    On-node validation of the weekly health report's node-only code paths.

.DESCRIPTION
    Everything else in this solution can be validated remotely. These paths cannot:

      * the shared-memory connection by COMPUTERNAME. The weekly job runs with
        HEALTHCHECK_OS_LOCAL=1 and connects to $env:COMPUTERNAME rather than the node's own
        routable IP, because a TCP loopback to the box's own address under a domain service
        account trips the Windows loopback NTLM check and is rejected as anonymous (SQL 18452).
        Only a run ON the node exercises it.
      * the six os/fw checks (disk, power plan, firewall, computer system, operating system,
        service-account privileges). Remotely they are skipped by design - SMB/445 is usually
        firewalled between the runner and the nodes - so they can only be graded on the node.
      * Invoke-SqlAssessment under WINDOWS auth. The report deliberately skips the assessment
        under SQL auth so no password reaches a child process command line, which means the
        credential-free path only ever runs here.
      * the PowerShell host version. ConvertFrom-Json does not enumerate a JSON array through
        a pipeline on Windows PowerShell 5.1 (it does on 7), and the report's grading depends
        on getting that right.

    READ-ONLY. It runs Get-/Test-/Measure- cmdlets and Invoke-SqlAssessment, creates nothing,
    changes nothing, and needs no arguments. Run it in a normal PowerShell window on the node.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-HealthCheckOnNode.ps1
#>
[CmdletBinding()]
param([int] $TimeoutSec = 120)

$ErrorActionPreference = 'Continue'
$fail = 0
function Say($ok, $label, $detail) {
    $mark = if ($ok -eq 'ok') { '  ok ' } elseif ($ok -eq 'warn') { ' WARN' } else { ' FAIL' }
    $col  = if ($ok -eq 'ok') { 'Green' } elseif ($ok -eq 'warn') { 'Yellow' } else { 'Red' }
    if ($ok -eq 'fail') { $script:fail++ }
    Write-Host ("{0} {1,-44} {2}" -f $mark, $label, $detail) -ForegroundColor $col
}

Write-Host "== host ==" -ForegroundColor Cyan
Write-Host ("  computer      : {0}" -f $env:COMPUTERNAME)
Write-Host ("  powershell    : {0}" -f $PSVersionTable.PSVersion)
if ($PSVersionTable.PSVersion.Major -eq 5) {
    Say 'ok' 'PowerShell host' '5.1 - the version the scheduled task uses'
} else {
    Say 'warn' 'PowerShell host' "$($PSVersionTable.PSVersion) - the scheduled task runs powershell.exe (5.1); results may differ"
}

# ConvertFrom-Json enumeration, the trap the grading depends on.
$j = '[{"S":"High"},{"S":"Medium"},{"S":"Low"}]'
$v = $j | ConvertFrom-Json          # assign FIRST, then wrap - @(pipeline) yields 1 on 5.1
$n = @($v).Count
Say $(if ($n -eq 3) { 'ok' } else { 'fail' }) 'ConvertFrom-Json enumeration' "assign-then-wrap gives $n (want 3); @(pipeline) gives $(@($j | ConvertFrom-Json).Count)"

Write-Host ""
Write-Host "== modules ==" -ForegroundColor Cyan
$dbt = (Get-Module -ListAvailable -Name dbatools  | Sort-Object Version -Descending | Select-Object -First 1)
$sqm = (Get-Module -ListAvailable -Name SqlServer | Sort-Object Version -Descending | Select-Object -First 1)
Say $(if ($dbt) { 'ok' } else { 'fail' }) 'dbatools present'  $(if ($dbt) { "v$($dbt.Version)" } else { 'NOT INSTALLED - the report cannot run' })
Say $(if ($sqm) { 'ok' } else { 'warn' }) 'SqlServer present' $(if ($sqm) { "v$($sqm.Version)" } else { 'absent - the assessment check will report skipped' })

Write-Host ""
Write-Host "== shared-memory connection by COMPUTERNAME ==" -ForegroundColor Cyan
Import-Module dbatools -ErrorAction Stop
Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true | Out-Null
$server = $null
try {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $server = Connect-DbaInstance -SqlInstance $env:COMPUTERNAME -TrustServerCertificate -ErrorAction Stop
    $sw.Stop()
    Say 'ok' 'Connect-DbaInstance $env:COMPUTERNAME' ("{0} ({1}) in {2}s" -f $server.Name, $server.VersionString, [Math]::Round($sw.Elapsed.TotalSeconds, 1))
} catch {
    Say 'fail' 'Connect-DbaInstance $env:COMPUTERNAME' ($_.Exception.Message -replace '\s+', ' ')
    Write-Host "  (18452 'login is from an untrusted domain' here means the loopback NTLM check - do NOT switch to the node's IP, that is what causes it)" -ForegroundColor DarkGray
}

if ($server) {
    Write-Host ""
    Write-Host "== the six checks that ONLY run on the node ==" -ForegroundColor Cyan
    $osChecks = @(
        @{ n = 'Disk space';                      c = { Get-DbaDiskSpace   -ComputerName $env:COMPUTERNAME -EnableException -WarningAction SilentlyContinue } },
        @{ n = 'Power plan';                      c = { Test-DbaPowerPlan  -ComputerName $env:COMPUTERNAME -EnableException -WarningAction SilentlyContinue } },
        @{ n = 'Computer system';                 c = { Get-DbaComputerSystem   -ComputerName $env:COMPUTERNAME -EnableException -WarningAction SilentlyContinue } },
        @{ n = 'Operating system';                c = { Get-DbaOperatingSystem  -ComputerName $env:COMPUTERNAME -EnableException -WarningAction SilentlyContinue } },
        @{ n = 'Service account privileges';      c = { Get-DbaPrivilege        -ComputerName $env:COMPUTERNAME -EnableException -WarningAction SilentlyContinue } },
        @{ n = 'Firewall rules';                  c = { Get-DbaFirewallRule -SqlInstance $server -EnableException -WarningAction SilentlyContinue } }
    )
    foreach ($k in $osChecks) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $r = & $k.c
            $sw.Stop()
            $cnt = $(if ($null -eq $r) { 0 } else { @($r).Count })
            Say $(if ($cnt -gt 0) { 'ok' } else { 'warn' }) $k.n ("{0} row(s) in {1}s" -f $cnt, [Math]::Round($sw.Elapsed.TotalSeconds, 1))
        } catch {
            $sw.Stop()
            Say 'fail' $k.n (($_.Exception.Message -replace '\s+', ' ').Substring(0, [Math]::Min(110, ($_.Exception.Message -replace '\s+', ' ').Length)))
        }
    }
}

Write-Host ""
Write-Host "== Invoke-SqlAssessment under Windows auth (the allow-list, in a clean child) ==" -ForegroundColor Cyan
if (-not $sqm) {
    Say 'warn' 'assessment' 'SqlServer module absent - the check reports skipped, which is correct, not a failure'
} else {
    # The assessment runs in a CHILD powershell.exe because the SqlServer module loads its own
    # SMO and dbatools 2.x bundles a different build - importing both into one runspace is a
    # documented assembly conflict. This mirrors what the report does, including -EncodedCommand.
    $rules = 'AutoStartProcs,BackupTables,CompareRunConfigured,DeprecatedFeatures,ErrorLog823,ErrorLog824,ErrorLog825,ErrorLog832,ErrorLog833,ErrorLog845,ErrorLog1105,ErrorLog3041,ErrorLog3271,ErrorLog9002,ErrorLog17884,ErrorLog17887,ErrorLog17888,ErrorLog17890,ErrorLog18056,ErrorLog35201,ErrorLog35206,ErrorLog41142,ErrorLog41144,HighCPUUsage,PageFileAutoManaged,PageFileAutoManagedAllDrives,PageFileLess10FreeSpace,PageFileNotConfigured,PageLifeExpectancy,ScanStartupProcs,SysAdminDefaultDatabase,SystemHealth,TempDBFilesInitialSize,WeakPassword'
    $body = @"
`$ErrorActionPreference='Stop'
try {
  Import-Module SqlServer -ErrorAction Stop -WarningAction SilentlyContinue
  `$checks = '$rules' -split ','
  `$srv = Get-SqlInstance -ServerInstance `$env:COMPUTERNAME -ErrorAction Stop -WarningAction SilentlyContinue
  try { `$srv.ConnectionContext.StatementTimeout = 100 } catch {}
  `$res = Invoke-SqlAssessment -InputObject `$srv -Check `$checks -FlattenOutput -ErrorAction Stop -WarningAction SilentlyContinue 3>`$null
  if (`$null -eq `$res) { ConvertTo-Json -Compress -InputObject @(); exit 0 }
  @(`$res) | Select-Object CheckId,Severity,Message,HelpLink,RulesetVersion | ConvertTo-Json -Depth 3 -Compress
} catch { ConvertTo-Json -Compress -InputObject @(@{ __sa_error = `$_.Exception.Message }) }
"@
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
    $raw = & powershell.exe -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand $b64 2>&1
    $sw.Stop()
    $secs = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
    $json = (@($raw) | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | Out-String).Trim()
    if (-not $json) {
        Say 'fail' 'assessment child' "no output after ${secs}s"
    } elseif ($json -eq '[]') {
        Say 'ok' 'assessment child' "clean - no findings, in ${secs}s"
    } else {
        $o = $json | ConvertFrom-Json          # assign first; @(pipeline) does not enumerate on 5.1
        $d = @($o)
        if ($d[0].__sa_error) {
            Say 'fail' 'assessment child' ("error: " + $d[0].__sa_error)
        } else {
            $hi  = @($d | Where-Object { "$($_.Severity)" -in 'Critical', 'High' }).Count
            $med = @($d | Where-Object { "$($_.Severity)" -eq 'Medium' }).Count
            $verdict = if ($hi) { 'fail' } elseif ($med) { 'attention' } else { 'pass' }
            $within = if ($secs -lt 120) { 'within' } else { 'OVER' }
            Say $(if ($secs -lt 120) { 'ok' } else { 'fail' }) 'assessment child' ("$($d.Count) finding(s), verdict '$verdict', ${secs}s ($within the 120s per-check budget)")
            foreach ($r in $d | Sort-Object { switch ("$($_.Severity)") { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } default { 3 } } }) {
                $m = "$($r.Message)" -replace '\s+', ' '
                Write-Host ("        [{0,-11}] {1,-28} {2}" -f $r.Severity, $r.CheckId, $m.Substring(0, [Math]::Min(90, $m.Length))) -ForegroundColor DarkGray
            }
        }
    }
}

Write-Host ""
Write-Host ("FAILURES: {0}" -f $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail -eq 0) { Write-Host "All node-only paths validated. The remaining checks are already validated remotely." -ForegroundColor Green }
