#
# Name:     rubrik-report.ps1
# Author:   pmilano1 (Peter J. Milanese)
# Use case: Custom report for XPO, credentials maintained upon first login. 
#           Remove .creds in local directorty if auth is broken. 
# Ex: .\rubrik-report.ps1 -rubrik [FDQN|IP Address for Rubrik Cluster] 

param (
    [string]$rubrik = $(Read-Host -Prompt 'Input your Rubrik IP or Hostname')
)

# Static hash of object information - not currently used
$objtype = @{
    "VmwareVirtualMachine" = @{"url" = "v1/vmware/vm/{0}/snapshot"; "array" = "data" }
    "Mssql"                = @{"url" = "v1/mssql/db/{0}/snapshot"; "array" = "data" }
    "LinuxFileset"         = @{"url" = "v1/fileset/{0}"; "array" = "snapshot" }
    "WindowsFileset"       = @{"url" = "v1/fileset/{0}"; "array" = "snapshot" }
    "ShareFileset"         = @{"url" = "v1/fileset/{0}"; "array" = "snapshot" }
    "NasFileset"           = @{"url" = "v1/fileset/{0}"; "array" = "snapshot" }
    "AixFileset"           = @{"url" = "v1/fileset/{0}"; "array" = "snapshot" }
    "ManagedVolume"        = @{"url" = "internal/managed_volume/{0}/snapshot"; "array" = "data" }
    "OracleDatabase"       = @{"url" = "internal/oracle/db/{0}/snapshot"; "array" = "data" }
}

# Time factors to help calculate longest retentions based on year
$timeFactor = @{
    "hourly"    = 8760
    "daily"     = 365
    "weekly"    = 52
    "quarterly" = 4
    "monthly"   = 12
    "yearly"    = 1
}

$slacache = @{}

# Fields from Report to keep in the output
$selected = ( "Location", "ObjectName", "SlaDomain", "ObjectType", "LocalStorage", "ArchiveStorage")

# Force TLS1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Bypass cert verification
if (-not("dummy" -as [type])) {
    add-type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class Dummy {
    public static bool ReturnTrue(object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors) { return true; }
    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(Dummy.ReturnTrue);
    }
}
"@
}
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = [dummy]::GetDelegate()

# Static Variables
$limit = 100
$object_report_name = "Object Protection Summary"

# Check for Credentials and prompt if need be
New-Item -ItemType Directory -Force -Path "$($PSScriptRoot)\.creds" | out-null
$Credential = ''
$CredentialFile = "$($PSScriptRoot)\.creds\$($rubrik).cred"
if (Test-Path $CredentialFile) {
    $Credential = Import-CliXml -Path $CredentialFile
}
else {
    $Credential = Get-Credential
    $Credential | Export-CliXml -Path $CredentialFile
}

# Setup Auth Header
$auth = [System.Text.Encoding]::UTF8.GetBytes(("{0}:{1}" -f $Credential.UserName.ToString(), ([Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)))))
$auth = [System.Convert]::ToBase64String($auth)
$headers = @{
    Authorization = "Basic {0}" -f $auth
    Accept        = 'application/json'
}


#  This will get the max retention of a SLA. It also maintains a cache to eliminate redundant calls.
function get_retention  ($rubrik, $slaName) {
    if ($slacache.keys -notcontains $slaName) {
        $uri = [uri]::EscapeUriString("https://$($rubrik)/api/v2/sla_domain?name=$($slaName)&primary_cluster_id=local")
        $r = Invoke-RestMethod -Headers $headers -Method GET -Uri $uri 
        if ($r.total -gt "0") {
            foreach ($sla in $r.data) {
                $longest = 0
                $longestFrequency = ""
                if ($slaName -eq $sla.name) {
                    $retentions = $sla.frequencies | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
                    foreach ($f in $retentions) {
                        if (($sla.frequencies.$f.retention / $timeFactor.$f) -gt $longest) {
                            $longestFrequency = $f
                        }
                    }
                }
                $slacache[$slaName] = "$($sla.frequencies.$longestFrequency.retention) $($longestFrequency)"
            }
        }
        else {
            $slacache[$slaName] = 0
        }
        return $slacache[$slaName]
    }
    else {
        return $slacache[$slaName]
    }
}

# Function to get all objects
function get-rubrik-objects ($rubrik, $object_report_id) {
    $out = @{}
    $out.rd = @()
    $payload = @{
        "limit" = $limit
    }
    $uri = [uri]::EscapeUriString("https://$($rubrik)/api/internal/report/$($object_report_id)/table")
    $hasMore = $true
    while ($hasMore -eq $true) {
        if ($null -ne $cursor) {
            $payload['cursor'] = $cursor
        }
        $rr = Invoke-RestMethod -Headers $headers -Method POST -Uri $($uri) -Body $(convertto-json $payload) 
        $cursor = $rr.cursor
        $hasMore = $rr.hasMore
        $out.rc = $rr.columns
        $out.rd += $rr.dataGrid
    }
    return ($out)
}

# Get the report ID to looking Objects from
try {
    $uri = [uri]::EscapeUriString("https://$($rubrik)/api/internal/report?name=$($object_report_name)")
    $object_report_list = Invoke-RestMethod -Headers $headers -Method GET -Uri $uri 
    foreach ($object_report in $object_report_list.data) {
        if ($object_report_name -eq $object_report.name) {
            $object_report_id = $object_report.id
        }
    }
}
catch {
    write-host "Failed to call $($uri)"
    write-host "Got : $($_.Exception)"
}

# Establish the hash of objects from the report
if ($object_report_id) {
    $rr = get-rubrik-objects $rubrik $object_report_id $SLA
}

# Setup and output the header columns
# Defaults
$c = $selected
# Added Columns
$c += "Retention"
$co = '"{0}"' -f ($c -join '","')
Write-Host $co

# Loop the report results, merge in the last archive data, output as csv 
foreach ($l in $rr.rd) {
    if ($objtype.Keys -notcontains $l[$rr.rc.indexOf('ObjectType')]) { continue }
    $ro = @()
    foreach ($f in $selected) {
        $ro += $l[$($rr.rc.indexOf($f))]
    }
    $ro += get_retention $rubrik $l[$($rr.rc.indexOf("SlaDomain"))]
    $ro = '"{0}"' -f ($ro -join '","')
    Write-Host $ro
}
exit