  #======================================#
  # THA - THREAT HUNTING ANALYTICS SUITE #
  #       HASH ANALYTICS MODULE          #
  # LogRhythm Sales Engineering          #
  # marcos.schejtman@logrhythm.com       #
  # v0.1  --  May, 2018                  #
  #======================================#

# Copyright 2018 LogRhythm Inc.   
# Licensed under the BSD License.
# Author: Marcos Schejtman <marcos.schejtman@logrhythm.com>

#HASH_RUNDLL=dd81d91ff3b0763c392422865c9ac12e
#HASH_WANNACRY=db349b97c37d22f5ea1d1841e3c89eb4

<#

SYNOPSIS:
    
    Collection of Threat Analytics Integrations with LogRhythm using APIS or Scraping the WebPage
    Automate the full response to Threat Attacks using hashes (In this Module) and creating cases

USAGE:

    Selecting A Specific Hash Provider:
    PS C:\> .\SRP-ThreatAnalyticsSuiteHashes.ps1 -ConfigFile THAHashSuite.ini -HashValue db349b97c37d22f5ea1d1841e3c89eb4 -OTX

        Available switches for providers:
            -OTX (Alienvault OTX), -VT (Virus Total), -MW (Malwarees), -TH (Total Hash), -ALL
    
    Adding a Specific Alarm to a Case (You need to add LogRhythm Case Support in the INI File):
    PS C:\> .\SRP-ThreatAnalyticsSuiteHashes.ps1 -ConfigFile THAHashSuite.ini -HashValue db349b97c37d22f5ea1d1841e3c89eb4 -OTX -AlarmID 666

    Force the Case creation no matter the Threat Hunting provider result:
    PS C:\> .\SRP-ThreatAnalyticsSuiteHashes.ps1 -ConfigFile THAHashSuite.ini -HashValue db349b97c37d22f5ea1d1841e3c89eb4 -OTX -ForceCase


    ************************************************************

    Review the ini File to validate all possible configurations for this suite

#>

[CmdLetBinding()]
param( 
    [Parameter(Mandatory = $true)]
    [string]$ConfigFile,
    [Parameter(Mandatory = $true)]
    [string]$HashValue,
    [string]$AlarmID,
    [switch]$ALL,
    [switch]$OTX,
    [switch]$VT,
    [switch]$TH,
    [switch]$MW,
    [switch]$ForceCase
)


# ================================================================================
# Utils Functions
# ================================================================================
function Get-IniContent 
{
    [CmdletBinding()]
    param
    (
          [ValidateNotNullOrEmpty()]  
          [ValidateScript({(Test-Path $_) -and ((Get-Item $_).Extension -eq ".ini")})]  
          [Parameter(ValueFromPipeline=$True,Mandatory=$True)]  
          [string]$FilePath 
    )
    $ini = @{}  
    switch -regex -file $FilePath  
    {  
        "^\[(.+)\]$" # Section  
        {  
            $section = $matches[1]  
            $ini[$section] = @{}  
            $CommentCount = 0  
        }  
        "^(;.*)$" # Comment  
        {  
            if (!($section))  
            {  
                $section = "No-Section"  
                $ini[$section] = @{}  
            }  
            $value = $matches[1]  
            $CommentCount = $CommentCount + 1  
            $name = "Comment" + $CommentCount  
            $ini[$section][$name] = $value  
        }   
        "(.+?)\s*=\s*(.*)" # Key  
        {  
            if (!($section))  
            {  
                $section = "No-Section"  
                $ini[$section] = @{}  
            }  
            $name,$value = $matches[1..2]  
            $ini[$section][$name] = $value  
        }  
    }  
    return $ini
}

function Get-TablesContent 
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.Commands.HtmlWebResponseObject] $WebRequest,
        [Parameter(Mandatory = $true)]
        [int] $TableNumber,
        [Parameter(Mandatory = $true)]
        [int] $BadParser,
        [Parameter(Mandatory = $true)]
        [int] $ExtraColumns,
        [Parameter(Mandatory = $false)]
        [int] $GetHTML
    )

    ## Extract the tables out of the web request
    $tables = @($WebRequest.ParsedHtml.getElementsByTagName("TABLE"))
    $table = $tables[$TableNumber]
    $titles = @()
    $rows = @($table.Rows)
    ## Go through all of the rows in the table
    foreach($row in $rows)
    {
        $cells = @($row.Cells)
        ## If we've found a table header, remember its titles
        if($cells[0].tagName -eq "TH" -and $BadParser -eq 0)
        {
            $titles = @($cells | % { ("" + $_.InnerText).Trim() })
            continue
        }
        ## If we haven't found any table headers, make up names "P1", "P2", etc.

        if(-not $titles)
        {
            $titles = @(1..($cells.Count + 2) | % { "P$_" })
        }

        ## Now go through the cells in the the row. For each, try to find the
        ## title that represents that column and create a hashtable mapping those
        ## titles to content
        $resultObject = [Ordered] @{}
        for($counter = 0; $counter -lt ($cells.Count + $ExtraColumns) ; $counter++)
        {
            $title = $titles[$counter]
            if(-not $title) { continue }
            if($title -eq "Result")
            {
                $tmpvar = ("" + $cells[$counter].InnerHTML).Trim()
                if ($tmpvar -match "alt=`"clean`"") 
                {
                    $resultObject[$title] = "Clean"
                }
                elseif ($tmpvar -match "type-unsupported") 
                {
                    $resultObject[$title] = "Unsupported"
                }
                else 
                {
                    $resultObject[$title] = $tmpvar
                }
            }
            else 
            {
                if ($GetHTML -eq 1)
                {
                    $resultObject[$title] = ("" + $cells[$counter].InnerHTML).Trim()
                }
                else 
                {
                    $resultObject[$title] = ("" + $cells[$counter].InnerText).Trim()
                }
            }
        }
        ## And finally cast that hashtable to a PSCustomObject
        [PSCustomObject] $resultObject
    }
}

function Print-HTResult 
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [PSObject] $HTResult,
        [Parameter(Mandatory = $true)]
        [string] $Provider,
        [Parameter(Mandatory = $false)]
        [bool] $Secundary,
        [Parameter(Mandatory = $false)]
        [string] $Spaces,
        [Parameter(Mandatory = $false)]
        [string] $Mode,
        [Parameter(Mandatory = $false)]
        [PSObject] $Filter
    )

    if ($Secundary) 
    {
        Write-Output "`n$Spaces===============     $Provider     ==============="
    }
    else 
    {
        Write-Output "`n$Spaces===============     $Provider Results     ==============="
    }
    
    $subcategoriesArray = @()
    $namesArray = @()
    foreach ($member in $HTResult.PSObject.Properties)
    { 
        if ($Mode)
        {
            if ($Mode.ToUpper() -eq "EXCLUDED" -and $Filter -contains $member.Name)
            {
                continue
            }
            if ($Mode.ToUpper() -eq "INCLUDED" -and !($Filter -contains $member.Name))
            {
                continue
            }
        }
        if ($member.Value -and $member.Value.GetType().Name -eq "Object[]")
        {
            Write-Output "$Spaces$($member.Name) ="
            foreach ($element in $member.Value) 
            {
                Write-Output "$Spaces     $element"
            }
        }
        elseif ($member.Value -and $member.Value.GetType().Name -ne "PSCustomObject")
        {
            #TODO: REMOVE THAT, just for debug 
            Write-Output "$Spaces$($member.Name) = $($member.Value)"
        }
        elseif ($member.Name -eq "decompiler")
        {
            continue
        }
        elseif (!$member.Value)
        {
            Write-Output "$Spaces$($member.Name) = $($member.Value)"
        }
        else
        {
            $subcategoriesArray+= ,$member.Value
            $namesArray+= ,$member.Name
            continue
        }
    }
    for ($i=0;$i -lt $subcategoriesArray.Count; $i++) 
    {
	    Print-HTResult -HTResult $subcategoriesArray[$i] -Provider $namesArray[$i] -Secundary $true -Spaces "$($Spaces)     " -Mode $FilterMode -Filter $SubModules
    }
}

function Out2File-HTResult 
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [PSObject] $HTResult,
        [Parameter(Mandatory = $true)]
        [string] $Provider,
        [Parameter(Mandatory = $true)]
        [string] $FilePath,
        [Parameter(Mandatory = $false)]
        [bool] $Secundary,
        [Parameter(Mandatory = $false)]
        [string] $Spaces,
        [Parameter(Mandatory = $false)]
        [string] $Mode,
        [Parameter(Mandatory = $false)]
        [PSObject] $Filter
    )

    if ($Secundary) 
    {
        Out-File -FilePath $FilePath -Append -InputObject "`n$Spaces===============     $Provider     ==============="
    }
    else 
    {
        Out-File -FilePath $FilePath -Append -Width 1500 -InputObject  "`n$Spaces===============     $Provider Results     ==============="
    }
    
    $subcategoriesArray = @()
    $namesArray = @()
    foreach ($member in $HTResult.PSObject.Properties)
    { 
        if ($Mode)
        {
            if ($Mode.ToUpper() -eq "EXCLUDED" -and $Filter -contains $member.Name)
            {
                continue
            }
            if ($Mode.ToUpper() -eq "INCLUDED" -and !($Filter -contains $member.Name))
            {
                continue
            }
        }

        if ($member.Value -and $member.Value.GetType().Name -eq "Object[]")
        {
            Write-Output "$Spaces$($member.Name) ="
            foreach ($element in $member.Value) 
            {
                Write-Output "$Spaces     $element"
            }
        }
        elseif ($member.Value -and $member.Value.GetType().Name -ne "PSCustomObject")
        {
            Out-File -FilePath $FilePath -Append -Width 1500 -InputObject  "$Spaces$($member.Name) = $($member.Value)"
        }
        elseif ($member.Name -eq "decompiler")
        {
            continue
        }
        elseif (!$member.Value)
        {
            Out-File -FilePath $FilePath -Append -Width 1500 -InputObject  "$Spaces$($member.Name) = $($member.Value)"
        }
        #TODO
        #Continue the stuff then invoke after it's over. In the mean Time Add to another Object
        else
        {
            $subcategoriesArray+= ,$member.Value
            $namesArray+= ,$member.Name
            continue
        }
    }
    for ($i=0;$i -lt $subcategoriesArray.Count; $i++) 
    {
	    Out2File-HTResult -HTResult $subcategoriesArray[$i] -Provider $namesArray[$i] -FilePath $FilePath -Secundary $true -Spaces "$($Spaces)     " -Mode $FilterMode -Filter $SubModules
    }
}


# ================================================================================
# Analysis Functions
# ================================================================================
function VirusTotalAnalysis
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [PSObject] $iniContent,
        [Parameter(Mandatory = $true)]
        [string] $HashValue,
        [Parameter(Mandatory = $true)]
        [string] $userAgent,
        [Parameter(Mandatory = $false)]
        [bool] $file,
        [Parameter(Mandatory = $false)]
        [string] $filepath,
        [Parameter(Mandatory = $false)]
        [ref] $result

    )
    $FilterMode = [string]$iniContent[“VIRUSTOTAL”][“FilterMode”]
    $VTAPIKey = $iniContent[“VIRUSTOTAL”][“APIKEY”]

    $virusTotal = Invoke-RestMethod -Method Get -UserAgent $userAgent -Uri https://www.virustotal.com/vtapi/v2/file/report?apikey=$($VTAPIKey)`&resource=$($HashValue)

    if ($FilterMode.ToUpper() -eq "INCLUDED" -or $FilterMode.ToUpper() -eq "EXCLUDED")
    {
        $SubModules = ([string]$iniContent[“VIRUSTOTAL”][“Module”]).Split(',',[System.StringSplitOptions]::RemoveEmptyEntries)
        Print-HTResult -HTResult $virusTotal -Provider "Virus Total" -Mode $FilterMode -Filter $SubModules
        if($file)
        {
            Out2File-HTResult -HTResult $virusTotal -Provider "Virus Total" -Mode $FilterMode -Filter $SubModules -FilePath $filepath
        }
    }
    else
    {
        Print-HTResult -HTResult $virusTotal -Provider "Virus Total"
        if($file)
        {
            Out2File-HTResult -HTResult $virusTotal -Provider "Virus Total" -FilePath $filepath
        }
    }

    if ([int]$virusTotal.positives -gt 10)
    {
        $result.Value = $true
    }
}

function OTXAnalysis
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [PSObject] $iniContent,
        [Parameter(Mandatory = $true)]
        [string] $HashValue,
        [Parameter(Mandatory = $true)]
        [string] $userAgent,
        [Parameter(Mandatory = $false)]
        [bool] $file,
        [Parameter(Mandatory = $false)]
        [string] $filepath,
        [Parameter(Mandatory = $false)]
        [ref] $result
    )
    $FilterMode = [string]$iniContent[“OTX”][“FilterMode”]
    $alienJSON = Invoke-RestMethod -Method Get -UserAgent $userAgent -Uri https://otx.alienvault.com/otxapi/indicator/file/analysis/$($HashValue)
    #Print-HTResult -HTResult $alienJSON -Provider "OTX"

    if ($FilterMode.ToUpper() -eq "INCLUDED" -or $FilterMode.ToUpper() -eq "EXCLUDED")
    {
        $SubModules = ([string]$iniContent[“OTX”][“Module”]).Split(',',[System.StringSplitOptions]::RemoveEmptyEntries)
        Print-HTResult -HTResult $alienJSON -Provider "OTX" -Mode $FilterMode -Filter $SubModules
        if($file)
        {
            Out2File-HTResult -HTResult $alienJSON -Provider "OTX" -Mode $FilterMode -Filter $SubModules -FilePath $filepath
        }
        
    }
    else
    {
        Print-HTResult -HTResult $alienJSON -Provider "OTX"
        if($file)
        {
            Out2File-HTResult -HTResult $alienJSON -Provider "OTX" -FilePath $filepath
        }
    }
    try 
    {
        if ($alienJSON.analysis.plugins.adobemalwareclassifier.results.alerts[0] -contains "detected" -or    
        $alienJSON.analysis.plugins.adobemalwareclassifier.results.alerts[0] -contains "infected")
        {
            $result.Value = $true
        }
    } 
    catch{}
    try 
    {
        if ($alienJSON.analysis.plugins.avast.results.alerts[0] -contains "detected" -or    
        $alienJSON.analysis.plugins.avast.results.alerts[0] -contains "infected")
        {
            $result.Value = $true
        }
    } 
    catch{}
    try 
    {
        if ( $alienJSON.analysis.plugins.clamav.results.alerts[0] -contains "detected" -or    
        $alienJSON.analysis.plugins.clamav.results.alerts[0] -contains "infected")
        {
            $result.Value = $true
        }
    } 
    catch{}
    try 
    {
        if ([int]$alienJSON.analysis.plugins.cuckoo.result.virustotal.positives -gt 10)
        {
            $result.Value = $true
        }
    } 
    catch{}    
}

function MalwaresAnalysis
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [PSObject] $iniContent,
        [Parameter(Mandatory = $true)]
        [string] $HashValue,
        [Parameter(Mandatory = $true)]
        [string] $userAgent,
        [Parameter(Mandatory = $false)]
        [bool] $file,
        [Parameter(Mandatory = $false)]
        [string] $filepath,
        [Parameter(Mandatory = $false)]
        [ref] $result
    )
    $FilterMode = [string]$iniContent[“MALWARES”][“FilterMode”]
    $MWAPIKey = $iniContent[“MALWARES”][“APIKEY”]
    $Providers = ([string]$iniContent[“MALWARES”][“Providers”]).Split(',',[System.StringSplitOptions]::RemoveEmptyEntries)

    $Body = @{
        api_key = $($MWAPIKey)
        hash = $($HashValue)
    }

    # Start Submodules Validation
    $areSubModules = $false
    if ($FilterMode.ToUpper() -eq "INCLUDED" -or $FilterMode.ToUpper() -eq "EXCLUDED")
    {
        $SubModules = ([string]$iniContent[“MALWARES”][“Module”]).Split(',',[System.StringSplitOptions]::RemoveEmptyEntries)
        $areSubModules = $true
    }
    # End of Validation

    if ($Providers -contains "ALL" -or $Providers -contains "STATIC")
    {
        $malwares = Invoke-RestMethod -Method Get -UserAgent $userAgent -Body $Body -Uri https://www.malwares.com/api/v2/file/staticinfo
        if ($areSubModules)
        {
            Print-HTResult -HTResult $malwares -Provider "MALWARES STATIC" -Mode $FilterMode -Filter $SubModules
            if($file)
            {
                Out2File-HTResult -HTResult $malwares -Provider "MALWARES STATIC" -Mode $FilterMode -Filter $SubModules -FilePath $filepath
            }
        }
        else
        {
            Print-HTResult -HTResult $malwares -Provider "MALWARES STATIC"
            if($file)
            {
                Out2File-HTResult -HTResult $malwares -Provider "MALWARES STATIC" -FilePath $filepath
            }
        }
    }

    if ($Providers -contains "ALL" -or $Providers -contains "MWS")
    {
        $malwares = Invoke-RestMethod -Method Get -UserAgent $userAgent -Body $Body -Uri https://www.malwares.com/api/v2/file/mwsinfo
        if ($areSubModules)
        {
            Print-HTResult -HTResult $malwares -Provider "MALWARES MWS" -Mode $FilterMode -Filter $SubModules
            if($file)
            {
                Out2File-HTResult -HTResult $malwares -Provider "MALWARES MWS" -Mode $FilterMode -Filter $SubModules -FilePath $filepath
            }
        }
        else
        {
            Print-HTResult -HTResult $malwares -Provider "MALWARES MWS"
            if($file)
            {
                Out2File-HTResult -HTResult $malwares -Provider "MALWARES MWS" -FilePath $filepath
            }
        }
        try 
        {
            if ([int]$malwares.virustotal.positives -gt 10)
            {
                $result.Value = $true
            }
        }
        catch{}
    }

    if ($Providers -contains "ALL" -or $Providers -contains "BEHAVIOR")
    {
        $malwares = Invoke-RestMethod -Method Get -UserAgent $userAgent -Body $Body -Uri https://www.malwares.com/api/v2/file/behaviorinfo
        if ($areSubModules)
        {
            Print-HTResult -HTResult $malwares -Provider "MALWARES BEHAVIOR" -Mode $FilterMode -Filter $SubModules
            if($file)
            {
                Out2File-HTResult -HTResult $malwares -Provider "MALWARES BEHAVIOR" -Mode $FilterMode -Filter $SubModules -FilePath $filepath
            }
        }
        else
        {
            Print-HTResult -HTResult $malwares -Provider "MALWARES BEHAVIOR"
            if($file)
            {
                Out2File-HTResult -HTResult $malwares -Provider "MALWARES BEHAVIOR" -FilePath $filepath
            }
        }
    }
}

function TotalHashAnalysis
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string] $HashValue,
        [Parameter(Mandatory = $true)]
        [string] $userAgent,
        [Parameter(Mandatory = $false)]
        [bool] $file,
        [Parameter(Mandatory = $false)]
        [string] $filepath,
        [Parameter(Mandatory = $false)]
        [ref] $result
    )
    #GET HASH TOTAL_HASH (Change the value after hash)
    $hash = Invoke-WebRequest -Method Get -MaximumRedirection 5 -UserAgent $userAgent -Uri https://totalhash.cymru.com/search/?hash:$($Hashvalue)
    $tbs = Get-TablesContent $hash -TableNumber 0 -BadParser 0 -ExtraColumns 0 | Select-Object -First 1 
    $hash = Invoke-WebRequest -Method Get -MaximumRedirection 5 -UserAgent $userAgent -Uri https://totalhash.cymru.com/analysis/?$($tbs.SHA1)

    Write-Output "##### Total HASH Results #####"
    Write-Output "===== File Information ====="
    Get-TablesContent $hash -TableNumber 0 -BadParser 1 -ExtraColumns 0 | Format-Table -Auto
    Write-Output "`n===== Analysis Details ====="
    Get-TablesContent $hash -TableNumber 1 -BadParser 1 -ExtraColumns 1 | Format-Table -Auto

    if ($file)
    {
        Out-File -FilePath $filepath -Append  -InputObject "##### Total HASH Results #####"
        Out-File -FilePath $filepath -Append  -InputObject "===== File Information ====="
        Get-TablesContent $hash -TableNumber 0 -BadParser 1 -ExtraColumns 0 | Format-Table -Auto | Out-File -FilePath $filepath -Append 
        Out-File -FilePath $filepath -Append  -InputObject "`n===== Analysis Details ====="
        Get-TablesContent $hash -TableNumber 1 -BadParser 1 -ExtraColumns 1 | Format-Table -Auto | Out-File -FilePath $filepath -Append 
    }

}


# ================================================================================
# LogRhythm Case Functions 
# ================================================================================

#force TLS v1.2 required by caseAPI
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Ignore invalid SSL certification warning
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
function CreateLogRhythmCase
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [PSObject] $iniContent,
        [Parameter(Mandatory = $true)]
        [string] $HashValue,
        [Parameter(Mandatory = $true)]
        [string] $userAgent,
        [Parameter(Mandatory = $true)]
        [string] $caseName,
        [Parameter(Mandatory = $true)]
        [string] $casePriority,
        [Parameter(Mandatory = $true)]
        [string] $caseSummary
    )
    $LRAPIKey = [string]$iniContent[“THASUITE”][“CaseAPIKey”]
    $LogRhythmURL = [string]$iniContent[“THASUITE”][“LogRhythmURL”]
    $LogRhythmCaseURI = "/lr-case-api/cases/"
    $caseURL = $LogRhythmURL + $LogRhythmCaseURI

    $token = "Bearer $LRAPIKey"

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-type", "application/json")
    $headers.Add("Authorization", $token)

    # CREATE CASE
    $payload = "{ `"name`": `"$caseName`", `"priority`": $casePriority, `"summary`": `"$caseSummary`" }"
    $caseResponse = Invoke-RestMethod -Uri $caseURL -headers $headers -Method POST -body $payload -UserAgent $userAgent
    $caseNumber = $caseResponse.id

    return $caseNumber
}

#force TLS v1.2 required by caseAPI
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Ignore invalid SSL certification warning
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
function AddEvidence2LogRhythmCase
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [PSObject] $iniContent,
        [Parameter(Mandatory = $true)]
        [string] $userAgent,
        [Parameter(Mandatory = $true)]
        [string] $caseNumber,
        [Parameter(Mandatory = $true)]
        [string] $note
    )
    $LRAPIKey = [string]$iniContent[“THASUITE”][“CaseAPIKey”]
    $LogRhythmURL = [string]$iniContent[“THASUITE”][“LogRhythmURL”]
    $LogRhythmCaseURI = "/lr-case-api/cases/"
    $caseURL = $LogRhythmURL + $LogRhythmCaseURI

    $noteurl = $caseURL + "$($caseNumber)/evidence/note/"

    $token = "Bearer $LRAPIKey"
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-type", "application/json")
    $headers.Add("Authorization", $token)

    # UPDATE CASE
    $payload = @{}
    $payload["text"] = $note
    $jsonPayload = ConvertTo-Json -InputObject $payload

    $response = Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $jsonPayload -UserAgent $userAgent

}

#force TLS v1.2 required by caseAPI
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Ignore invalid SSL certification warning
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
function AddAlarm2LogRhythmCase
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [PSObject] $iniContent,
        [Parameter(Mandatory = $true)]
        [string] $userAgent,
        [Parameter(Mandatory = $true)]
        [string] $caseNumber,
        [Parameter(Mandatory = $true)]
        [string] $AlarmID
    )
    $LRAPIKey = [string]$iniContent[“THASUITE”][“CaseAPIKey”]
    $LogRhythmURL = [string]$iniContent[“THASUITE”][“LogRhythmURL”]
    $LogRhythmCaseURI = "/lr-case-api/cases/"
    $caseURL = $LogRhythmURL + $LogRhythmCaseURI

    $noteurl = $caseURL + "$($caseNumber)/evidence/alarms"

    $token = "Bearer $LRAPIKey"
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-type", "application/json")
    $headers.Add("Authorization", $token)

    $AlarmsArray = @()
    $namesArray+= ,[int]$AlarmID
    $request = @{}
    $request.Add("alarmNumbers",$namesArray)

    # UPDATE CASE
    $payload = ConvertTo-Json -InputObject $request
    $response = Invoke-RestMethod -uri $noteurl -headers $headers -Method POST -body $payload -UserAgent $userAgent
}


# ================================================================================
# LogRhythm SRP Main Function 
# ================================================================================
$iniContent = Get-IniContent -FilePath $ConfigFile
$userAgent = $iniContent[“THASUITE”][“UserAgent”]
$CreateAlarm = $iniContent[“THASUITE”][“CreateAlarm”]
$AlarmFile = $iniContent[“THASUITE”][“AlarmFile”]
$CreateCase = $iniContent[“THASUITE”][“CreateCase”]
$CaseStatus = $iniContent[“THASUITE”][“CaseStatus”]


# ================================================================================
# Parameters Validation
# ================================================================================
if (!$userAgent -or $userAgent -eq "CHANGE_THIS")
{
    $userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0"
}

if (!$CreateCase -or ([string]$CreateCase).ToUpper() -eq "CHANGE_THIS" -or ([string]$CreateCase).ToUpper() -eq "FALSE" )
{
    $case = $false
}
else
{
    $case = $true
}
if (!$CaseStatus -or ([string]$CaseStatus).ToUpper() -ne "CREATED")
{
    $casePriority = 3
}
else 
{
    $casePriority = 1
}
$uuid = [GUID]::NewGuid()


# ================================================================================
# Threat Hunting Request (Bool references based on data collected)
# ================================================================================
$danger = $false
if($All -or $VT)
{
    VirusTotalAnalysis -iniContent $iniContent -HashValue $HashValue -userAgent $userAgent -file $case -filepath "$($uuid.Guid)_VT" -result ([ref]$danger)
}

if($All -or $OTX)
{
    OTXAnalysis -iniContent $iniContent -HashValue $HashValue -userAgent $userAgent  -file $case -filepath "$($uuid.Guid)_OTX" -result ([ref]$danger)
}

if($All -or $MW)
{
    MalwaresAnalysis -iniContent $iniContent -HashValue $HashValue -userAgent $userAgent -file $case -filepath "$($uuid.Guid)_MW" -result ([ref]$danger)
}

if($All -or $TH)
{
    TotalHashAnalysis -HashValue $HashValue -userAgent $userAgent -file $case -filepath "$($uuid.Guid)_MW" -result ([ref]$danger)
}

 # ================================================================================
 # LogRhythm Integration
 # ================================================================================
if ($ForceCase -or ($case -and $danger))
{
    # Define the Case Data
    $caseName = "Hash found to be Dangerous"
    if ($danger)
    {
        $caseSummary = "Hash $($HashValue) has been investigated in the selected Threat Hunting providers and it's been marked as dangerous or infected"
    }
    else
    {
        $caseSummary = "Hash $($HashValue) has been requested to be investigated"
    }
    $caseNumber = CreateLogRhythmCase -iniContent $iniContent -HashValue $HashValue -userAgent $userAgent -caseName $caseName -casePriority $casePriority -caseSummary $caseSummary
    if($All -or $VT)
    {
        $note = Get-Content "$($uuid.Guid)_VT" -Raw
        AddEvidence2LogRhythmCase -iniContent $iniContent -userAgent $userAgent -caseNumber $caseNumber -note $note
    }

    if($All -or $OTX)
    {
        $note = Get-Content "$($uuid.Guid)_OTX" -Raw
        AddEvidence2LogRhythmCase -iniContent $iniContent -userAgent $userAgent -caseNumber $caseNumber -note $note
    }

    if($All -or $MW)
    {
        $note = Get-Content "$($uuid.Guid)_MW" -Raw
        AddEvidence2LogRhythmCase -iniContent $iniContent -userAgent $userAgent -caseNumber $caseNumber -note $note
    }

#    if($All -or $TH)
#    {
#        $note = Get-Content "$($uuid.Guid)_TH" -Raw
#        Write-Host "IS MALWARE: $($caseSummary)"
#        #AddEvidence2LogRhythmCase -iniContent $iniContent -userAgent $userAgent -caseNumber $caseNumber -note $notek
#    }

    if ($AlarmID)
    {
        AddAlarm2LogRhythmCase -iniContent $iniContent -userAgent $userAgent -caseNumber $caseNumber -AlarmID $AlarmID
    }
}


# ================================================================================
# Cleanup the mess if we need to
# ================================================================================
If (Test-Path "$($uuid.Guid)_VT")
{
	Remove-Item "$($uuid.Guid)_VT"
}
If (Test-Path "$($uuid.Guid)_OTX")
{
	Remove-Item "$($uuid.Guid)_OTX"
}
If (Test-Path "$($uuid.Guid)_MW")
{
	Remove-Item "$($uuid.Guid)_MW"
}
#If (Test-Path "$($uuid.Guid)_TH")
#{
#	Remove-Item "$($uuid.Guid)_TH"
#}