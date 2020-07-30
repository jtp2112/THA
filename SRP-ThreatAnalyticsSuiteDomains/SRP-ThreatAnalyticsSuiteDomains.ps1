  #======================================#
  # THA - THREAT HUNTING ANALYTICS SUITE #
  #   DOMAIN/HOSTNAME ANALYTICS MODULE   #
  # LogRhythm Sales Engineering          #
  # marcos.schejtman@logrhythm.com       #
  # v0.1  --  May, 2018                  #
  #======================================#

# Copyright 2018 LogRhythm Inc.   
# Licensed under the BSD License.
#Author: Marcos Schejtman <marcos.schejtman@logrhythm.com>

#GOOD_DOMAIN=logrhythm.com
#BAD_DOMAIN=above.e-rezerwacje24.pl

<#

SYNOPSIS:
    
    Collection of Threat Analytics Integrations with LogRhythm using APIS or Scraping the WebPage
    Automate the full response to Threat Attacks using domains (In this Module) and creating cases

USAGE:

    Selecting A Specific Domain Provider:
    PS C:\> .\SRP-ThreatAnalyticsSuiteDomains.ps1 -ConfigFile THADomainSuite.ini -Domain above.e-rezerwacje24.pl -OTX

        Available switches for providers:
            -OTX (Alienvault OTX), -VT (Virus Total), -MW (Malwarees) -ALL
    
    If you want to review HOSTNAMES instead of Dommains use the swith -Hostname, otherwise Domain is assume:
    PS C:\> .\SRP-ThreatAnalyticsSuiteDomains.ps1 -ConfigFile THADomainSuite.ini -Domain above.e-rezerwacje24.pl -OTX -Hostname

    Adding a Specific Alarm to a Case (You need to add LogRhythm Case Support in the INI File):
    PS C:\> .\SRP-ThreatAnalyticsSuiteDomains.ps1 -ConfigFile THADomainSuite.ini -Domain above.e-rezerwacje24.pl -OTX -AlarmID 666

    Force the Case creation no matter the Threat Hunting provider result:
    PS C:\> .\SRP-ThreatAnalyticsSuiteDomains.ps1 -ConfigFile THADomainSuite.ini -Domain above.e-rezerwacje24.pl -OTX -ForceCase


    ************************************************************

    Review the ini File to validate all possible configurations for this suite

#>

#TODO: ADD A switch parameter so we can identify between host or domain
[CmdLetBinding()]
param( 
    [Parameter(Mandatory = $true)]
    [string]$ConfigFile,
    [Parameter(Mandatory = $true)]
    [string]$Domain,
    [string]$AlarmID,
    [switch]$ALL,
    [switch]$OTX,
    [switch]$VT,
    [switch]$TH,
    [switch]$MW,
    [switch]$Hostname,
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
        [string] $Domain,
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

    $virusTotal = Invoke-RestMethod -Method Get -UserAgent $userAgent -Uri https://www.virustotal.com/vtapi/v2/domain/report?apikey=$($VTAPIKey)`&domain=$($Domain)

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
    try
    {
        $test = @{}
        $test.Count
        if ($virusTotal.detected_urls.Count -gt 0)
        {
            $result.Value = $true
        }
    }
    catch{}
}

function OTXAnalysis
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [PSObject] $iniContent,
        [Parameter(Mandatory = $true)]
        [string] $Domain,
        [Parameter(Mandatory = $true)]
        [string] $userAgent,
        [Parameter(Mandatory = $false)]
        [switch] $isHost,
        [Parameter(Mandatory = $false)]
        [bool] $file,
        [Parameter(Mandatory = $false)]
        [string] $filepath,
        [Parameter(Mandatory = $false)]
        [ref] $result
    )

    $OTXURL=""

    # Start Submodules Validation
    $FilterMode = [string]$iniContent[“OTX”][“FilterMode”]
    $areSubModules = $false
    if ($FilterMode.ToUpper() -eq "INCLUDED" -or $FilterMode.ToUpper() -eq "EXCLUDED")
    {
        $SubModules = ([string]$iniContent[“OTX”][“Module”]).Split(',',[System.StringSplitOptions]::RemoveEmptyEntries)
        $areSubModules = $true
    }

    if ($isHost)
    {
        $OTXURL = "https://otx.alienvault.com/otxapi/indicator/hostname/"
    }
    else
    {
        $OTXURL = "https://otx.alienvault.com/otxapi/indicator/domain/"
    }

    # End of Validation
    $Providers = ([string]$iniContent[“OTX”][“Providers”]).Split(',',[System.StringSplitOptions]::RemoveEmptyEntries)

    if ($Providers -contains "ALL" -or $Providers -contains "GENERAL")
    {
        $alienJSON = Invoke-RestMethod -Method Get -UserAgent $userAgent -Body $Body -Uri "$($OTXURL)/general/$($Domain)"
        if ($areSubModules)
        {
            Print-HTResult -HTResult $alienJSON -Provider "OTX GENERAL" -Mode $FilterMode -Filter $SubModules
            if($file)
            {
                Out2File-HTResult -HTResult $alienJSON -Provider "OTX GENERAL" -Mode $FilterMode -Filter $SubModules -FilePath $file
            }
        }
        else
        {
            Print-HTResult -HTResult $alienJSON -Provider "OTX GENERAL"
            if($file)
            {
                Out2File-HTResult -HTResult $alienJSON -Provider "OTX GENERAL" -FilePath $file
            }
        }
        if([int]$alienJSON.pulse_info.count -gt 0)
        {
            $result.Value = $true
        }
    }
    if ($Providers -contains "ALL" -or $Providers -contains "GEO")
    {
        $alienJSON = Invoke-RestMethod -Method Get -UserAgent $userAgent -Body $Body -Uri "$($OTXURL)geo/$($Domain)"
        if ($areSubModules)
        {
            Print-HTResult -HTResult $alienJSON -Provider "OTX GEOLOCALIZATION" -Mode $FilterMode -Filter $SubModules
            if($file)
            {
                Out2File-HTResult -HTResult $alienJSON -Provider "OTX GEOLOCALIZATION" -Mode $FilterMode -Filter $SubModules -FilePath $file
            }
        }
        else
        {
            Print-HTResult -HTResult $alienJSON -Provider "OTX GEOLOCALIZATION"
            if($file)
            {
                Out2File-HTResult -HTResult $alienJSON -Provider "OTX GEOLOCALIZATION" -FilePath $file
            }
        }
    }
    if ($Providers -contains "ALL" -or $Providers -contains "URL_LIST")
    {
        $alienJSON = Invoke-RestMethod -Method Get -UserAgent $userAgent -Body $Body -Uri "$($OTXURL)url_list/$($Domain)"
        if ($areSubModules)
        {
            Print-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN URL LIST" -Mode $FilterMode -Filter $SubModules
            if($file)
            {
                Out2File-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN URL LIST" -Mode $FilterMode -Filter $SubModules -FilePath $file
            }
        }
        else
        {
            Print-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN URL LIST"
            if($file)
            {
                Out2File-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN URL LIST" -FilePath $file
            }
        }
    }
    if ($Providers -contains "ALL" -or $Providers -contains "PASSIVE_DNS")
    {
        $alienJSON = Invoke-RestMethod -Method Get -UserAgent $userAgent -Body $Body -Uri "$($OTXURL)passive_dns/$($Domain)"
        if ($areSubModules)
        {
            Print-HTResult -HTResult $alienJSON -Provider "OTX PASSIVE DNS" -Mode $FilterMode -Filter $SubModules
            if($file)
            {
                Out2File-HTResult -HTResult $alienJSON -Provider "OTX PASSIVE DNS" -Mode $FilterMode -Filter $SubModules -FilePath $file
            }
        }
        else
        {
            Print-HTResult -HTResult $alienJSON -Provider "OTX PASSIVE DNS"
            if($file)
            {
                Out2File-HTResult -HTResult $alienJSON -Provider "OTX PASSIVE DNS" -FilePath $file
            }
        }
    }
    if ($Providers -contains "ALL" -or $Providers -contains "MALWARE")
    {
        $alienJSON = Invoke-RestMethod -Method Get -UserAgent $userAgent -Body $Body -Uri "$($OTXURL)malware/$($Domain)"
        if ($areSubModules)
        {
            Print-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN MALWARE" -Mode $FilterMode -Filter $SubModules
            if($file)
            {
                Out2File-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN MALWARE" -Mode $FilterMode -Filter $SubModules -FilePath $file
            }
        }
        else
        {
            Print-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN MALWARE"
            if($file)
            {
                Out2File-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN MALWARE" -FilePath $file
            }
        }
    }
    if ($Providers -contains "ALL" -or $Providers -contains "WHOIS")
    {
        $alienJSON = Invoke-RestMethod -Method Get -UserAgent $userAgent -Body $Body -Uri "$($OTXURL)whois/$($Domain)"
        if ($areSubModules)
        {
            Print-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN WHOIS" -Mode $FilterMode -Filter $SubModules
            if($file)
            {
                Out2File-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN WHOIS" -Mode $FilterMode -Filter $SubModules -FilePath $file
            }
        }
        else
        {
            Print-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN WHOIS"
            if($file)
            {
                Out2File-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN WHOIS" -FilePath $file
            }
        }
    }
    if ($Providers -contains "ALL" -or $Providers -contains "HTTP_SCANS")
    {
        $alienJSON = Invoke-RestMethod -Method Get -UserAgent $userAgent -Body $Body -Uri "$($OTXURL)http_scans/$($Domain)"
        if ($areSubModules)
        {
            Print-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN HTTP SCANS" -Mode $FilterMode -Filter $SubModules
            if($file)
            {
                Out2File-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN HTTP SCANS" -Mode $FilterMode -Filter $SubModules -FilePath $file
            }
        }
        else
        {
            Print-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN HTTP SCANS"
            if($file)
            {
                Out2File-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN HTTP SCANS" -FilePath $file
            }
        }
    }
    if ($Providers -contains "ALL" -or $Providers -contains "COMMENTS")
    {
        $alienJSON = Invoke-RestMethod -Method Get -UserAgent $userAgent -Body $Body -Uri "$($OTXURL)$($Domain)/comments"
        if ($areSubModules)
        {
            Print-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN COMMENTS" -Mode $FilterMode -Filter $SubModules
            if($file)
            {
                Out2File-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN COMMENTS" -Mode $FilterMode -Filter $SubModules -FilePath $file
            }
        }
        else
        {
            Print-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN COMMENTS"
            if($file)
            {
                Out2File-HTResult -HTResult $alienJSON -Provider "OTX DOMAIN COMMENTS" -FilePath $file
            }
        }
    }
}

function MalwaresAnalysis
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [PSObject] $iniContent,
        [Parameter(Mandatory = $true)]
        [string] $Domain,
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
        hostname  = $($Domain)
    }

    # Start Submodules Validation
    $areSubModules = $false
    if ($FilterMode.ToUpper() -eq "INCLUDED" -or $FilterMode.ToUpper() -eq "EXCLUDED")
    {
        $SubModules = ([string]$iniContent[“MALWARES”][“Module”]).Split(',',[System.StringSplitOptions]::RemoveEmptyEntries)
        $areSubModules = $true
    }
    # End of Validation
    $malwares = Invoke-RestMethod -Method Get -UserAgent $userAgent -Body $Body -Uri https://www.malwares.com/api/v2/hostname/info
    if ($areSubModules)
    {
        Print-HTResult -HTResult $malwares -Provider "MALWARES DOMAIN" -Mode $FilterMode -Filter $SubModules
        if($file)
        {
            Out2File-HTResult -HTResult $malwares -Provider "MALWARES DOMAIN" -Mode $FilterMode -Filter $SubModules -FilePath $filepath
        }
    }
    else
    {
        Print-HTResult -HTResult $malwares -Provider "MALWARES DOMAIN"
        if($file)
        {
            Out2File-HTResult -HTResult $malwares -Provider "MALWARES DOMAIN" -FilePath $filepath
        }
    }
    if([int]$malwares.detected_url.total -gt 0)
    {
        $result.Value = $true
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
    VirusTotalAnalysis -iniContent $iniContent -Domain $Domain -userAgent $userAgent -file $case -filepath "$($uuid.Guid)_VT" -result ([ref]$danger)
}

if($All -or $OTX)
{
    if ($Hostname)
    {
        OTXAnalysis -iniContent $iniContent -Domain $Domain -userAgent $userAgent  -file $case -filepath "$($uuid.Guid)_OTX" -result ([ref]$danger) -isHost
    }
    else
    {
        OTXAnalysis -iniContent $iniContent -Domain $Domain -userAgent $userAgent  -file $case -filepath "$($uuid.Guid)_OTX" -result ([ref]$danger)
    }
}

if($All -or $MW)
{
    MalwaresAnalysis -iniContent $iniContent -Domain $Domain -userAgent $userAgent -file $case -filepath "$($uuid.Guid)_MW" -result ([ref]$danger)
}

 # ================================================================================
 # LogRhythm Integration
 # ================================================================================
if ($ForceCase -or ($case -and $danger))
{
    # Define the Case Data
    if ($Hostname)
    {
        $caseName = "Host $($Domain) found to be Dangerous"
        if ($danger)
        {
            $caseSummary = "Host $($Domain) has been investigated in the selected Threat Hunting providers and it's been marked as dangerous or infected"
        }
        else
        {
            $caseSummary = "Host $($Domain) has been requested to be investigated"
        }
    }
    else
    {
        $caseName = "Domain $($Domain) found to be Dangerous"
        if ($danger)
        {
            $caseSummary = "Domain $($Domain) has been investigated in the selected Threat Hunting providers and it's been marked as dangerous or infected"
        }
        else
        {
            $caseSummary = "Domain $($Domain) has been requested to be investigated"
        }
    }

    $caseNumber = CreateLogRhythmCase -iniContent $iniContent -userAgent $userAgent -caseName $caseName -casePriority $casePriority -caseSummary $caseSummary
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
