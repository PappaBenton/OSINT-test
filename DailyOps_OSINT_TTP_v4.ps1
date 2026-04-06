#requires -Version 5.1

<#
.SYNOPSIS
Simplified Daily Ops OSINT extraction prep script.

.DESCRIPTION
Self-contained script that runs from the same directory as a Daily Ops .msg file.
No external config, modules, or prompt files are required.

What it does:
1. Opens the first .msg file in the working directory using Outlook COM.
2. Trims the email body at the FYSA marker.
3. Extracts OSINT titles and URLs from the message body.
4. Saves URL lists and logs for troubleshooting.
5. Fetches each URL using browser-like headers, per-site session cookies, and an HttpClient fallback.
6. Saves each OSINT page as raw HTML only.
7. Saves email attachments into the same analyst-facing folder as the OSINT HTML files.
8. Generates one ASCII-sanitized AI prompt file.
9. Writes manifests and failure reports without stopping on individual errors.

PREREQUISITES
- Outlook installed locally.
- This script and the target .msg file are in the same directory.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch { }

# -----------------------------
# Configuration
# -----------------------------
$marker = '(U) FYSA:'
$basePath = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$rootOut = Join-Path $basePath "DailyOps_Extracted_$timestamp"
$readyOut = Join-Path $rootOut 'Ready for TTP Extractions'
$logFile = Join-Path $rootOut 'run.log'
$urlListTxt = Join-Path $rootOut 'osint-title-link.txt'
$urlListCsv = Join-Path $rootOut 'osint-title-link.csv'
$urlListJson = Join-Path $rootOut 'osint-title-link.json'
$attachmentIndexCsv = Join-Path $rootOut 'attachments-index.csv'
$failedUrlsCsv = Join-Path $rootOut 'failed-urls.csv'
$failedAttachmentsCsv = Join-Path $rootOut 'failed-attachments.csv'
$manifestJson = Join-Path $rootOut 'ai-manifest.json'
$promptPath = Join-Path $rootOut 'AI prompt for TTP extractions.txt'
$minDelaySeconds = 2
$maxDelaySeconds = 5

$browserHeaders = @{
    'User-Agent'      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
    'Accept'          = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
    'Accept-Language' = 'en-US,en;q=0.9'
    'Accept-Encoding' = 'gzip, deflate, br'
    'Connection'      = 'keep-alive'
    'Cache-Control'   = 'no-cache'
    'Pragma'          = 'no-cache'
    'Upgrade-Insecure-Requests' = '1'
    'DNT'             = '1'
}
# -----------------------------

# -----------------------------
# Helpers
# -----------------------------
function Initialize-OutputFolders {
    New-Item -ItemType Directory -Force -Path $rootOut, $readyOut | Out-Null
    "" | Set-Content -Path $logFile -Encoding UTF8
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    Add-Content -Path $logFile -Value $line
}

function Remove-InvalidFileNameChars {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $pattern = "[{0}]" -f [Regex]::Escape($invalidChars)
    $clean = ($Name -replace $pattern, '_').Trim()
    $clean = $clean -replace '\s+', ' '
    $clean = $clean.Trim().TrimEnd('.', ' ')

    if ($clean.Length -gt 120) {
        $clean = $clean.Substring(0,120)
    }

    if ([string]::IsNullOrWhiteSpace($clean)) {
        return 'untitled'
    }

    if ($clean -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
        $clean = "_$clean"
    }

    return $clean
}

function Get-UniquePath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $Path
    }

    $dir = Split-Path -Path $Path -Parent
    $base = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    $ext = [System.IO.Path]::GetExtension($Path)
    $i = 1

    do {
        $candidate = Join-Path $dir ("{0} ({1}){2}" -f $base, $i, $ext)
        $i++
    } while (Test-Path -LiteralPath $candidate)

    return $candidate
}

function Save-TextFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [AllowEmptyCollection()][AllowEmptyString()][object[]]$Content
    )

    $target = Get-UniquePath -Path $Path

    if ($null -eq $Content) {
        $Content = @()
    }

    $normalized = foreach ($line in $Content) {
        if ($null -eq $line) { '' } else { [string]$line }
    }

    Set-Content -Path $target -Value $normalized -Encoding UTF8 -ErrorAction Stop
    return $target
}

function Get-RandomDelaySeconds {
    return (Get-Random -Minimum $minDelaySeconds -Maximum ($maxDelaySeconds + 1))
}

function Convert-ToPlainAscii {
    param([string]$Text)

    if ($null -eq $Text) { return '' }

    $Text = $Text.Replace([char]0x2018, "'").Replace([char]0x2019, "'")
    $Text = $Text.Replace([char]0x201C, '"').Replace([char]0x201D, '"')
    $Text = $Text.Replace([char]0x2013, '-').Replace([char]0x2014, '-')
    $Text = $Text -creplace '\P{IsBasicLatin}', ''
    return $Text
}

function Test-BlockedContent {
    param([string]$Html)

    if ([string]::IsNullOrWhiteSpace($Html)) {
        return 'Empty response body'
    }

    $patterns = @(
        '403\s+ERROR',
        'The request could not be satisfied',
        'Generated by cloudfront',
        'Request blocked',
        'Access Denied',
        'Just a moment\.\.\.',
        'cf-browser-verification',
        'cf-chl-',
        'Cloudflare',
        'captcha',
        'enable javascript and cookies',
        'attention required'
    )

    foreach ($pattern in $patterns) {
        if ($Html -match $pattern) {
            return "Matched block/challenge indicator: $pattern"
        }
    }

    return $null
}

function Invoke-SessionRequest {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][hashtable]$Sessions,
        [Parameter(Mandatory)][hashtable]$BaseHeaders
    )

    $uri = [Uri]$Url
    $siteKey = '{0}://{1}' -f $uri.Scheme, $uri.Host

    if (-not $Sessions.ContainsKey($siteKey)) {
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        try {
            Invoke-WebRequest -Uri $siteKey -Headers $BaseHeaders -WebSession $session -MaximumRedirection 3 -ErrorAction SilentlyContinue | Out-Null
        }
        catch {}
        $Sessions[$siteKey] = $session
    }

    $session = $Sessions[$siteKey]
    $headers = $BaseHeaders.Clone()
    $headers['Referer'] = $siteKey

    return Invoke-WebRequest -Uri $Url -Headers $headers -WebSession $session -MaximumRedirection 5 -ErrorAction Stop
}

function Invoke-HttpClientFallback {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][System.Net.Http.HttpClient]$Client
    )

    $uri = [Uri]$Url
    $siteKey = '{0}://{1}' -f $uri.Scheme, $uri.Host

    if ($Client.DefaultRequestHeaders.Contains('Referer')) {
        $Client.DefaultRequestHeaders.Remove('Referer') | Out-Null
    }
    $Client.DefaultRequestHeaders.Add('Referer', $siteKey)

    $resp = $Client.GetAsync($Url).Result
    if (-not $resp.IsSuccessStatusCode) {
        throw "HttpClient fallback failed: HTTP $([int]$resp.StatusCode) $($resp.StatusCode)"
    }

    return $resp.Content.ReadAsStringAsync().Result
}
# -----------------------------

# -----------------------------
# Main Execution
# -----------------------------
$outlook = $null
$namespace = $null
$mailItem = $null
$client = $null
$failedUrls = @()
$failedAttachments = @()
$attachmentIndex = @()
$manifest = @()
$results = @()
$sessions = @{}

try {
    Initialize-OutputFolders
    Write-Log -Level INFO -Message 'Initialized output folders.'

    $msgFile = Get-ChildItem -Path $basePath -Filter *.msg | Select-Object -First 1
    if (-not $msgFile) {
        throw 'No .msg file found in directory.'
    }

    Write-Log -Level INFO -Message "Processing MSG file: $($msgFile.Name)"

    $outlook = New-Object -ComObject Outlook.Application
    $namespace = $outlook.GetNamespace('MAPI')
    $mailItem = $namespace.OpenSharedItem($msgFile.FullName)

    $body = $mailItem.Body
    $idx = $body.IndexOf($marker)
    if ($idx -ge 0) {
        $body = $body.Substring(0, $idx + $marker.Length)
        Write-Log -Level INFO -Message 'Trimmed body at FYSA marker.'
    }

    $pattern = '^\s*\*\s+(?<Title>.+?)\s*<(?<Url>https?://[^>]+)>'
    $matches = [regex]::Matches($body, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline)

    $osintItems = foreach ($m in $matches) {
        [PSCustomObject]@{
            Title = $m.Groups['Title'].Value.Trim()
            URL   = $m.Groups['Url'].Value.Trim()
        }
    }

    if ($osintItems.Count -eq 0) {
        Write-Log -Level WARN -Message 'No OSINT URLs found.'
    }

    Save-TextFile -Path $urlListTxt -Content ($osintItems | ForEach-Object { "OSINT - $($_.Title) - $($_.URL)" }) | Out-Null
    $osintItems | Export-Csv -Path $urlListCsv -NoTypeInformation -Encoding UTF8
    $osintItems | ConvertTo-Json -Depth 3 | Set-Content -Path $urlListJson -Encoding UTF8
    Write-Log -Level INFO -Message 'Saved URL lists.'

    Add-Type -AssemblyName System.Net.Http
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.UseCookies = $true
    $handler.CookieContainer = [System.Net.CookieContainer]::new()
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd($browserHeaders['User-Agent'])
    $client.DefaultRequestHeaders.Accept.ParseAdd($browserHeaders['Accept'])
    $client.DefaultRequestHeaders.AcceptLanguage.ParseAdd($browserHeaders['Accept-Language'])

    foreach ($item in $osintItems) {
        $safeTitle = Remove-InvalidFileNameChars -Name $item.Title
        $htmlPath = Get-UniquePath -Path (Join-Path $readyOut ("OSINT - $safeTitle.html"))

        $result = [PSCustomObject]@{
            Title    = $item.Title
            Url      = $item.URL
            HtmlFile = ''
            Method   = $null
            Success  = $false
            Error    = $null
            Blocked  = $false
            BlockReason = ''
        }
        $results += $result

        $delay = Get-RandomDelaySeconds
        Write-Log -Level INFO -Message "Sleeping $delay second(s) before request: $($item.URL)"
        Start-Sleep -Seconds $delay

        $html = $null
        $methodUsed = $null

        try {
            Write-Log -Level INFO -Message "Fetching via session request: $($item.URL)"
            $response = Invoke-SessionRequest -Url $item.URL -Sessions $sessions -BaseHeaders $browserHeaders
            $html = [string]$response.Content
            $methodUsed = 'Invoke-WebRequest'
        }
        catch {
            $firstErr = $_.Exception.Message
            Write-Log -Level WARN -Message "Session request failed for $($item.URL): $firstErr"

            try {
                Write-Log -Level INFO -Message "Retrying via HttpClient fallback: $($item.URL)"
                $html = Invoke-HttpClientFallback -Url $item.URL -Client $client
                $methodUsed = 'HttpClient'
            }
            catch {
                $finalErr = $_.Exception.Message
                $msg = "All fetch methods failed for $($item.URL): $finalErr"
                Write-Log -Level ERROR -Message $msg
                $failedUrls += [PSCustomObject]@{
                    Title = $item.Title
                    URL   = $item.URL
                    Error = $msg
                }
                $result.Method = 'Failed'
                $result.Success = $false
                $result.Error = $msg
                $manifest += [PSCustomObject]@{
                    Title   = $item.Title
                    URL     = $item.URL
                    HtmlFile = ''
                    Method  = 'Failed'
                    Status  = 'Failed'
                    Blocked = $false
                    BlockReason = ''
                }
                continue
            }
        }

        try {
            Set-Content -Path $htmlPath -Value $html -Encoding UTF8
            $result.HtmlFile = $htmlPath
            $result.Method = $methodUsed
            $result.Success = $true
            $result.Error = $null

            $blockReason = Test-BlockedContent -Html $html
            if ($blockReason) {
                $result.Blocked = $true
                $result.BlockReason = $blockReason
                Write-Log -Level WARN -Message "Possible block/challenge content detected for $($item.URL): $blockReason"
            }

            $manifest += [PSCustomObject]@{
                Title   = $item.Title
                URL     = $item.URL
                HtmlFile = $htmlPath
                Method  = $methodUsed
                Status  = 'Success'
                Blocked = $result.Blocked
                BlockReason = $result.BlockReason
            }

            Write-Log -Level INFO -Message "Saved HTML file ($methodUsed): $($item.URL)"
        }
        catch {
            $msg = "Save failure for $($item.URL): $($_.Exception.Message)"
            Write-Log -Level ERROR -Message $msg
            $failedUrls += [PSCustomObject]@{
                Title = $item.Title
                URL   = $item.URL
                Error = $msg
            }
            $result.Method = $methodUsed
            $result.Success = $false
            $result.Error = $msg
        }
    }

    if ($failedUrls.Count -gt 0) {
        $failedUrls | Export-Csv -Path $failedUrlsCsv -NoTypeInformation -Encoding UTF8
    }

    Write-Log -Level INFO -Message 'Processed all URLs.'

    foreach ($attachment in $mailItem.Attachments) {
        try {
            $fileName = Remove-InvalidFileNameChars -Name $attachment.FileName
            $filePath = Get-UniquePath -Path (Join-Path $readyOut ("Source - $fileName"))
            $attachment.SaveAsFile($filePath)

            $attachmentIndex += [PSCustomObject]@{
                FileName = [System.IO.Path]::GetFileName($filePath)
                Path     = $filePath
                Size     = $attachment.Size
            }

            Write-Log -Level INFO -Message "Saved attachment: $fileName"
        }
        catch {
            Write-Log -Level ERROR -Message "Failed attachment: $($attachment.FileName) - $($_.Exception.Message)"
            $failedAttachments += [PSCustomObject]@{
                FileName = $attachment.FileName
                Error    = $_.Exception.Message
            }
        }
    }

    if ($attachmentIndex.Count -gt 0) {
        $attachmentIndex | Export-Csv -Path $attachmentIndexCsv -NoTypeInformation -Encoding UTF8
    }

    if ($failedAttachments.Count -gt 0) {
        $failedAttachments | Export-Csv -Path $failedAttachmentsCsv -NoTypeInformation -Encoding UTF8
    }

    Write-Log -Level INFO -Message 'Processed attachments.'

    $manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestJson -Encoding UTF8
    Write-Log -Level INFO -Message 'Generated AI manifest.'

    $preparedFiles = Get-ChildItem -Path $readyOut -File | Select-Object -ExpandProperty Name | Sort-Object
    $fileListText = if ($preparedFiles.Count -gt 0) {
        ($preparedFiles | ForEach-Object { "- $_" }) -join [Environment]::NewLine
    } else {
        '- No files were prepared successfully.'
    }

    $failureNote = @()
    if ($failedUrls.Count -gt 0) { $failureNote += "URL failures: $($failedUrls.Count)" }
    if ($failedAttachments.Count -gt 0) { $failureNote += "Attachment failures: $($failedAttachments.Count)" }
    $failureNoteText = if ($failureNote.Count -gt 0) { $failureNote -join '; ' } else { 'No extraction failures were recorded during prep.' }

    $prompt = @"
I will upload one or more cyber-intelligence documents. These may be PDFs, Word files, plain text, or multi-block scraped exports. Analyze each file or block independently and extract MITRE ATT&CK Enterprise v17.1 techniques and sub-techniques.
Absolutely DO NOT include ANY technique that falls under Reconnaissance (TA0043) or Resource Development (TA0042).
This includes ALL of the following T-codes (full blacklist):
HARD BLACKLIST - DO NOT USE THESE TECHNIQUES
Reconnaissance - TA0043
These techniques must never appear in your output:
T1595 - Active Scanning
T1592 - Gather Victim Host Information
T1589 - Gather Victim Identity Information
T1590 - Gather Victim Network Information
T1591 - Gather Victim Organization Information
T1598 - Phishing for Information
T1597 - Search Closed Sources
T1596 - Search Open Technical Databases
T1593 - Search Open Websites/Domains
T1681 - Search Threat Vendor Data
T1594 - Search Victim-Owned Websites
Resource Development - TA0042
These techniques must never appear in your output:
T1650 - Acquire Access
T1583 - Acquire Infrastructure
T1586 - Compromise Accounts
T1584 - Compromise Infrastructure
T1587 - Develop Capabilities
T1585 - Establish Accounts
T1588 - Obtain Capabilities
T1608 - Stage Capabilities
If your extraction logic identifies any of the above T-codes, you must silently discard them and not include them in any section of the output.
1. DOCUMENT AND BLOCK HANDLING
URL Block Format
A single uploaded text file may contain several blocks:
URL: <CTI URL>
Content:
<full article text or HTML content>
Treat each block as a separate document.
A blank line or another URL starts the next block.
Use the URL as the document name.
Multiple Files
If multiple files are uploaded:
Process each independently.
Output results in order.
No Filename?
Invent a concise filename of 5 words or fewer.
2. PRE-PROCESSING REQUIREMENTS
Document Counting
Before processing, count all documents or blocks.
Prepend each output with:
(X of Y) <Document Name>
Scrape Integrity Warning
If content appears truncated, corrupted, or HTML artifact-heavy:
Possible incomplete or corrupted scrape detected - please verify source content.
3. MITRE ATTACK EXTRACTION RULES
Strict ATTACK Version
Use ATTACK v17.1 Enterprise only.
Validate every technique ID and name.
Map deprecated entries to v17.1 or exclude them.
Exclude Mobile and ICS.
Mandatory Exclusions
NEVER include any tactic under TA0043 or TA0042.
NEVER include any T-code listed in the hard blacklist.
Inference
You MAY infer techniques from context.
Every technique must have defensible evidence.
Deduplicate
Each technique appears only once per document.
4. OUTPUT FORMAT
For each document or block:
(X of Y) <Document Name or URL>

Total Techniques: <number>

- Attack Id: TXXXX[.XXX], Name: <Canonical Name>
- Attack Id: TYYYY[.YYY], Name: <Canonical Name>
Then list the T-codes:
T-codes: TXXXX, TYYYY, TZZZZ
Human Readable Details
Filename: <document or URL>
ATTACK Version: v17.1 Enterprise
Total Techniques: <number>
For each technique or sub-technique:
Attack Id: TXXXX[.XXX], Name: <Canonical Name>
Tactic(s): <Enterprise tactics except Reconnaissance and Resource Development>
Evidence: "<Short quote or precise paraphrase>"
Confidence: High, Medium, or Low
Inferred: Yes or No
No Content Case
Total Techniques: 0
No content available.
5. INTERNAL VALIDATION
You must internally verify:
All technique IDs validated against ATTACK v17.1.
No Reconnaissance or Resource Development techniques appear.
No blacklisted T-codes appear.
Confidence levels are justified.
Inference flags are correct.
No duplicates.
Deprecated entries are mapped or excluded.
Final accuracy self-check completed.

6. FILES PROVIDED
The following files were generated from today's Daily Ops .msg extraction. Process all uploaded files in order.
These files are located in the folder named Ready for TTP Extractions.

Files:
$fileListText

7. EXTRACTION NOTES
$failureNoteText
If a page appears to be a block, challenge page, or incomplete scrape based on the HTML content, treat that source cautiously.
"@

    $prompt = Convert-ToPlainAscii -Text $prompt
    Save-TextFile -Path $promptPath -Content $prompt | Out-Null
    Write-Log -Level INFO -Message 'Generated ASCII-sanitized AI prompt.'

    Write-Log -Level INFO -Message 'Script completed successfully.'

    $successCount = ($results | Where-Object { $_.Success }).Count
    $failCount = ($results | Where-Object { -not $_.Success }).Count

    Write-Host ''
    Write-Host 'Article fetch summary:' -ForegroundColor Cyan
    Write-Host "  Successful: $successCount"
    Write-Host "  Failed:     $failCount"
    Write-Host ''
    Write-Host "Ready folder: $readyOut" -ForegroundColor Green
    Write-Host "Prompt file:  $promptPath" -ForegroundColor Green

    if ($client -ne $null) {
        $client.Dispose()
    }
}
catch {
    Write-Log -Level ERROR -Message "Fatal error: $($_.Exception.Message)"
    throw
}
finally {
    if ($mailItem -ne $null) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($mailItem) }
    if ($namespace -ne $null) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($namespace) }
    if ($outlook -ne $null) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($outlook) }
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}
