<#
.SYNOPSIS
    Validates the dbatools-cmdlet catalog checks against REAL cmdlet output on real nodes.

.DESCRIPTION
    Exists because two earlier ad-hoc harnesses produced confident WRONG conclusions about the
    nodes they tested, and both were the harness rather than the product:

      1. Connecting without the arguments the generated script actually uses. The real script
         connects with -Database, -ApplicationIntent ReadOnly, -TrustServerCertificate and
         -ConnectTimeout. Omit -Database and a connection that carries a failover partner fails
         with "Use of key 'Failover Partner' requires the key 'Initial Catalog' to be present" -
         which reads as an unreachable node and is not. Omit -ApplicationIntent ReadOnly and the
         AG does not route to a readable replica, so SMO marks the non-readable copies
         inaccessible and Get-DbaLastGoodCheckDb aborts the WHOLE check with "The database <x>
         is not accessible". That reproduces on any node holding non-readable copies and looks
         exactly like a coverage hole in the most important Recoverability check. With the real
         arguments, every node returns rows.

      2. Not recycling the worker runspace after a per-check timeout. The engine's own
         Invoke-CheckWithTimeout disposes the runspace and builds a new one; a harness that only
         throws leaves a poisoned connection, and every later check fails with "The wait
         operation timed out". One stall can then cost well over an hour because
         [powershell]::Stop() blocks until the underlying SMO call returns.

    So: connect exactly as the script does, bound each check exactly as the engine does, and
    recycle on timeout exactly as the engine does. Anything else measures the harness.

    What it reports per check:
      * did the cmdlet run, how long, how many rows, and the real property names
      * do the properties the EVALUATOR reads actually exist on those rows - an evaluator testing
        a property no row carries is silently always-false and can never fire
      * does the evaluator THROW with the production try/catch REMOVED - production wraps every
        evaluator in `try { ... } catch { 'ok' }`, so a throwing evaluator is indistinguishable
        from a legitimate 'ok'

    READ-ONLY: every catalog check is a Get-/Test-/Measure- cmdlet by construction.

.EXAMPLE
    .\Test-HealthCheckCmdlets.ps1 -Node region1-node1 -Database AppCatalog `
        -ChecksJson .\cmdlet_checks.json -OutJson .\result.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Node,
    [Parameter(Mandatory)] [string] $ChecksJson,
    [string] $Database   = 'AppCatalog',
    [string] $OutJson,
    [string] $CredTarget = 'SqlServerFleet',
    [int]    $TimeoutSec = 120,
    [int]    $ConnectTimeoutSec = 15,
    [int]    $GradeCap   = 2000
)
$ErrorActionPreference = 'Stop'

# -- credential from Windows Credential Manager (never echoed) ----------------
$sig = @'
using System;
using System.Runtime.InteropServices;
public class CredNativeHCC {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct CREDENTIAL { public UInt32 Flags; public UInt32 Type; public IntPtr TargetName; public IntPtr Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten; public UInt32 CredentialBlobSize; public IntPtr CredentialBlob;
    public UInt32 Persist; public UInt32 AttributeCount; public IntPtr Attributes; public IntPtr TargetAlias; public IntPtr UserName; }
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern bool CredReadW(string target, UInt32 type, UInt32 flags, out IntPtr cred);
}
'@
if (-not ('CredNativeHCC' -as [type])) { Add-Type -TypeDefinition $sig }
$ptr = [IntPtr]::Zero
if (-not [CredNativeHCC]::CredReadW($CredTarget, 1, 0, [ref]$ptr)) { throw "credential '$CredTarget' not found" }
$cc   = [Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type][CredNativeHCC+CREDENTIAL])
$user = [Runtime.InteropServices.Marshal]::PtrToStringUni($cc.UserName)
$pass = [Runtime.InteropServices.Marshal]::PtrToStringUni($cc.CredentialBlob, $cc.CredentialBlobSize / 2)
$cred = New-Object System.Management.Automation.PSCredential($user, (ConvertTo-SecureString $pass -AsPlainText -Force))

Import-Module dbatools -ErrorAction Stop
Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true | Out-Null
Write-Host ("dbatools {0}  PS {1}" -f (Get-Module dbatools).Version, $PSVersionTable.PSVersion)

# EXACTLY the connection buildHealthCheckScript emits. Do not simplify this line.
function New-HcConnection {
    Connect-DbaInstance -SqlInstance "$Node,1433" -Database $Database -ApplicationIntent ReadOnly `
        -TrustServerCertificate -ConnectTimeout $ConnectTimeoutSec -SqlCredential $cred -ErrorAction Stop
}
$server = New-HcConnection
Write-Host ("connected: {0} ({1})  db={2} intent=ReadOnly" -f $server.Name, $server.VersionString, $Database)

# Per-check wall clock, and a runspace that is REBUILT on timeout - same as the engine.
$script:pool = $null
function New-Pool {
    $r = [runspacefactory]::CreateRunspace(); $r.Open()
    $r.SessionStateProxy.SetVariable('server', $script:server)
    $r
}
$script:server = $server
$script:pool = New-Pool
function Invoke-Bounded([string]$code, [int]$sec) {
    $ps = [powershell]::Create(); $ps.Runspace = $script:pool
    [void]$ps.AddScript("Import-Module dbatools -ErrorAction SilentlyContinue; " + $code)
    $async = $ps.BeginInvoke()
    if (-not $async.AsyncWaitHandle.WaitOne($sec * 1000)) {
        # Do NOT block on $ps.Stop(): it waits for the underlying SMO call to return, which is
        # how a single stalled check can cost well over an hour. Abandon the runspace and build a
        # fresh one so the NEXT check starts from a clean connection.
        try { $script:pool.Dispose() } catch {}
        $script:server = New-HcConnection
        $script:pool = New-Pool
        throw "exceeded per-check wall-clock timeout of ${sec}s (runspace recycled)"
    }
    try { return $ps.EndInvoke($async) } finally { try { $ps.Dispose() } catch {} }
}

$checks  = Get-Content $ChecksJson -Raw | ConvertFrom-Json
# Both cmdlet checks (target 'sql') and DMV checks (target 'dmv'). They are invoked differently
# but graded identically, and the catalog moves checks between the two - "Recent error log" was a
# cmdlet until Get-DbaErrorLog was measured taking most of an hour on a node with a large error log,
# and became a bounded DMV read.
$sqlOnly = @($checks | Where-Object { $_.target -eq 'sql' -or $_.target -eq 'dmv' })
Write-Host ("running {0} check(s): {1} cmdlet, {2} dmv" -f $sqlOnly.Count,
    @($sqlOnly | Where-Object { $_.target -eq 'sql' }).Count,
    @($sqlOnly | Where-Object { $_.target -eq 'dmv' }).Count)
Write-Host ""

$out = @()
foreach ($c in $sqlOnly) {
    if ($c.target -eq 'dmv') {
        # Same shape the generator emits for a dmv check: the query is single-quoted, so its own
        # single quotes must be doubled exactly as sq() does.
        $q = $c.extra -replace "'", "''"
        $code = "Invoke-DbaQuery -SqlInstance `$server -Query '$q' -As PSObject -EnableException -WarningAction SilentlyContinue 3>`$null | Select-Object -First $GradeCap"
    } else {
        $extra = if ($c.extra) { ' ' + $c.extra } else { '' }
        $code  = "{0} -SqlInstance `$server{1} -EnableException -WarningAction SilentlyContinue 3>`$null | Select-Object -First {2}" -f $c.command, $extra, $GradeCap
    }
    $rec = [ordered]@{
        label = $c.label; command = $c.command; graded = [bool]$c.evalPs
        ran = $false; rows = 0; seconds = 0.0; error = $null
        props = @(); evalProps = @(); missingProps = @()
        status = $null; unwrappedThrew = $false; unwrappedError = $null; unwrappedStatus = $null
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $d = Invoke-Bounded $code $TimeoutSec
        $sw.Stop(); $rec.seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
        $rec.ran = $true
        $rec.rows = $(if ($null -eq $d) { 0 } else { @($d).Count })
        if ($rec.rows -gt 0) { $rec.props = @(@($d)[0].PSObject.Properties.Name) }
    } catch {
        $sw.Stop(); $rec.seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
        $rec.error = ($_.Exception.Message -replace '\s+', ' ')
        $d = $null
    }

    if ($c.evalPs) {
        # Every $_.X the evaluator reads...
        $names = [regex]::Matches($c.evalPs, '\$_\.([A-Za-z_][A-Za-z0-9_]*)') | ForEach-Object { $_.Groups[1].Value }
        # ...minus the ones it BUILDS itself. Several evaluators project the source rows into a
        # local [pscustomobject]@{ Q=...; AB=... } and then read $_.Q / $_.AB off that. Those names
        # are never expected on the source rows, and counting them produced a confident false
        # "evaluator reads absent properties" on a check that is in fact correct (Resource
        # Governor, on every node). Only a name the evaluator does NOT define is a real absence.
        $defined = [regex]::Matches($c.evalPs, '(?:@\{|;)\s*([A-Za-z_][A-Za-z0-9_]*)\s*=') | ForEach-Object { $_.Groups[1].Value }
        $rec.evalProps = @($names | Sort-Object -Unique | Where-Object { $defined -notcontains $_ })
        if ($rec.rows -gt 0) {
            $have = @{}
            foreach ($row in @($d)) { foreach ($pn in $row.PSObject.Properties.Name) { $have[$pn] = $true } }
            $rec.missingProps = @($rec.evalProps | Where-Object { -not $have.ContainsKey($_) })
        }
        $wrapped = [scriptblock]::Create("param(`$d) " + '$(try { if ($null -eq $d) {''empty''} else { ' + $c.evalPs + ' } } catch { ''ok'' })')
        try { $rec.status = & $wrapped $d } catch { $rec.status = "<harness:$($_.Exception.Message)>" }
        $bare = [scriptblock]::Create("param(`$d) " + '$(if ($null -eq $d) {''empty''} else { ' + $c.evalPs + ' })')
        try { $rec.unwrappedStatus = & $bare $d }
        catch { $rec.unwrappedThrew = $true; $rec.unwrappedError = ($_.Exception.Message -replace '\s+', ' ') }
    }

    $flag = if ($rec.error) { 'ERR ' } elseif ($rec.unwrappedThrew) { 'THROW' } elseif ($rec.missingProps.Count) { 'PROP' } else { '    ' }
    $col  = if ($rec.error -or $rec.unwrappedThrew -or $rec.missingProps.Count) { 'Red' } else { 'Green' }
    $note = if ($rec.error) { $rec.error }
            elseif ($rec.unwrappedThrew) { 'evaluator THREW: ' + $rec.unwrappedError }
            elseif ($rec.missingProps.Count) { 'evaluator reads absent propertie(s): ' + ($rec.missingProps -join ', ') }
            else { '' }
    Write-Host ("{0} {1,-44} {2,6}s rows={3,-6} status={4,-10} {5}" -f $flag, $c.label.Substring(0, [Math]::Min(44, $c.label.Length)), $rec.seconds, $rec.rows, $rec.status, $note.Substring(0, [Math]::Min(70, $note.Length))) -ForegroundColor $col
    $out += [pscustomobject]$rec
}

try { $script:pool.Dispose() } catch {}
if ($OutJson) { $out | ConvertTo-Json -Depth 5 | Set-Content -Path $OutJson -Encoding UTF8 }
Write-Host ""
Write-Host ("ran {0}/{1}   errored {2}   evaluator threw {3}   absent-property {4}" -f
    @($out | Where-Object ran).Count, $out.Count,
    @($out | Where-Object error).Count,
    @($out | Where-Object unwrappedThrew).Count,
    @($out | Where-Object { $_.missingProps.Count }).Count)
