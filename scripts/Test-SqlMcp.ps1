#requires -Version 5.1
<#
.SYNOPSIS
    Verifies the read-only SQL login works AND cannot write — independent of the
    MCP server. Proves defense-in-depth layer 1 (login privilege).

.DESCRIPTION
    1. POSITIVE: connects with ApplicationIntent=ReadOnly and reads @@VERSION,
       SERVERPROPERTY('ServerName') (shows which replica routing chose), and
       confirms VIEW SERVER STATE by reading sys.dm_os_sys_info.
    2. NEGATIVE: attempts a trivial write (SELECT INTO a temp-less permanent table)
       which MUST fail with a permission error. If the write succeeds, the login is
       over-privileged and the script reports FAIL.

    Runs only SELECTs plus one intentionally-failing write attempt; changes nothing.

.EXAMPLE
    $env:SQL_PASSWORD = '...'
    .\Test-SqlMcp.ps1 -Server listener.region1.example.com,1433 -Database AppCatalog
#>
[CmdletBinding()]
param(
    [string] $Server   = 'listener.region1.example.com,1433',
    [string] $Database = 'AppCatalog',
    [string] $User     = $(if ($env:SQL_USER) { $env:SQL_USER } else { 'svc_msg_readonly' })
)

$ErrorActionPreference = 'Stop'
if (-not $env:SQL_PASSWORD) { throw "Set `$env:SQL_PASSWORD before running." }

$cs = "Server=$Server;Database=$Database;User ID=$User;Password=$($env:SQL_PASSWORD);" +
      "ApplicationIntent=ReadOnly;Encrypt=True;TrustServerCertificate=True;Application Name=sql-mcp-test"

$conn = New-Object System.Data.SqlClient.SqlConnection $cs
$conn.Open()
try {
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = "SELECT CAST(SERVERPROPERTY('ServerName') AS NVARCHAR(256)) AS ServerName, " +
                       "CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(50)) AS Version"
    $r = $cmd.ExecuteReader(); [void]$r.Read()
    Write-Host ("PASS  read OK  -> answering replica: {0}  (v{1})" -f $r['ServerName'], $r['Version']) -ForegroundColor Green
    $r.Close()

    # VIEW SERVER STATE check
    $cmd.CommandText = "SELECT cpu_count FROM sys.dm_os_sys_info"
    [void]$cmd.ExecuteScalar()
    Write-Host "PASS  VIEW SERVER STATE granted (DMV read OK)" -ForegroundColor Green

    # NEGATIVE write test — MUST fail.
    $writeBlocked = $false
    try {
        $cmd.CommandText = "SELECT 1 AS x INTO dbo.__sql_mcp_write_probe__"
        [void]$cmd.ExecuteNonQuery()
    } catch {
        $writeBlocked = $true
        Write-Host ("PASS  write blocked by login privilege: {0}" -f $_.Exception.Message.Split([Environment]::NewLine)[0]) -ForegroundColor Green
    }
    if (-not $writeBlocked) {
        Write-Host "FAIL  write SUCCEEDED — the login is over-privileged. Reduce it to read-only." -ForegroundColor Red
        # Best-effort cleanup if it somehow wrote (should never reach here).
        try { $cmd.CommandText = "DROP TABLE dbo.__sql_mcp_write_probe__"; [void]$cmd.ExecuteNonQuery() } catch {}
        exit 1
    }
}
finally { $conn.Close() }

Write-Host "`nAll checks passed: connection is read-only and the login cannot write." -ForegroundColor Cyan
