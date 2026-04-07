#requires -Version 5.1

<#
.SYNOPSIS
Safe-merge Daily Ops OSINT extraction prep script.

.DESCRIPTION
Built from the v4.2 stable fetch path with isolated add-ons:
- temp MSG open workaround
- fixed ASCII conversion
- challenge-aware tagging as metadata only
- MSRC CVE enrichment only after a normal fetch succeeds

Design goal:
Do not alter the shared request path that was working for most links.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch { }

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
$maxFileNameLength = 120
$maxUrlLengthForPrompt = 2000

$browserHeaders = @{
    'User-Agent'                 = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
    'Accept'                     = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
    'Accept-Language'            = 'en-US,en;q=0.9'
    'Accept-Encoding'            = 'gzip, deflate, br'
    'Connection'                 = 'keep-alive'
    'Cache-Control'              = 'no-cache'
    'Pragma'                     = 'no-cache'
    'Upgrade-Insecure-Requests'  = '1'
    'DNT'                        = '1'
}

function Initialize-OutputFolders {
    New-Item -ItemType Directory -Force -Path $rootOut, $readyOut | Out-Null
    Set-Content -Path $logFile -Value @() -Encoding UTF8
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
    Add-Content -Path $logFile -Value $line -Encoding UTF8
}

function Remove-InvalidFileNameChars {
    param([Parameter(Mandatory)][string]$Name)

    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $pattern = "[{0}]" -f [Regex]::Escape($invalidChars)
    $clean = ($Name -replace $pattern, '_').Trim()
    $clean = $clean -replace '\s+', ' '
    $clean = $clean.Trim().TrimEnd('.', ' ')

    if ($clean.Length -gt $maxFileNameLength) {
        $clean = $clean.Substring(0, $maxFileNameLength)
    }

    if ([string]::IsNullOrWhiteSpace($clean)) { return 'untitled' }
    if ($clean -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') { $clean = "_$clean" }
    return $clean
}

function Get-UniquePath {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $Path }

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
        [Parameter(Mandatory)][string]$Path,
        [AllowEmptyCollection()][AllowEmptyString()][object[]]$Content
    )

    $target = Get-UniquePath -Path $Path
    if ($null -eq $Content) { $Content = @() }

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
    $Text = $Text.Replace([string][char]0x2026, '...')
    $Text = $Text -creplace '[^\x09\x0A\x0D\x20-\x7E]', ''
    return $Text
}

function Html-Encode {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $Text = $Text.Replace('&', '&amp;')
    $Text = $Text.Replace('<', '&lt;')
    $Text = $Text.Replace('>', '&gt;')
    $Text = $Text.Replace('"', '&quot;')
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

function Get-ChallengeTag {
    param([string]$Url,[string]$Html)

    $uri = [Uri]$Url
    $host = $uri.Host.ToLowerInvariant()
    $reason = Test-BlockedContent -Html $Html

    if ($reason) {
        return [PSCustomObject]@{
            ChallengeLikely = $true
            ChallengeType   = 'ChallengeOrInterstitial'
            ChallengeReason = $reason
        }
    }

    if ($host -like '*.darkreading.com' -or $host -eq 'darkreading.com') {
        if ($Html -match 'Please wait|Checking your browser|Verifying you are human|enable javascript|loading\.\.\.|setTimeout|countdown|window\.location') {
            return [PSCustomObject]@{
                ChallengeLikely = $true
                ChallengeType   = 'LikelyTimedBrowserGate'
                ChallengeReason = 'Dark Reading content appears gated by timed/browser challenge behavior.'
            }
        }
    }

    return [PSCustomObject]@{
        ChallengeLikely = $false
        ChallengeType   = ''
        ChallengeReason = ''
    }
}

function Test-IsMsrcCveUrl {
    param([string]$Url)
    return ($Url -match '^https://msrc\.microsoft\.com/update-guide/vulnerability/(?<Cve>CVE-\d{4}-\d+)$')
}

function Get-MsrcCveFromUrl {
    param([string]$Url)
    $m = [regex]::Match($Url, '^https://msrc\.microsoft\.com/update-guide/vulnerability/(?<Cve>CVE-\d{4}-\d+)$', 'IgnoreCase')
    if ($m.Success) { return $m.Groups['Cve'].Value.ToUpperInvariant() }
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
    $headers = @{}
    foreach ($key in $BaseHeaders.Keys) {
        $headers[$key] = $BaseHeaders[$key]
    }
    $headers['Referer'] = $siteKey

    return Invoke-WebRequest -Uri $Url -Headers $headers -WebSession $session -MaximumRedirection 5 -ErrorAction Stop
}

function Initialize-HttpClient {
    Add-Type -AssemblyName System.Net.Http

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.UseCookies = $true
    $handler.CookieContainer = [System.Net.CookieContainer]::new()
    $handler.AllowAutoRedirect = $true

    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(60)

    [void]$client.DefaultRequestHeaders.TryAddWithoutValidation('User-Agent', $browserHeaders['User-Agent'])
    [void]$client.DefaultRequestHeaders.TryAddWithoutValidation('Accept', $browserHeaders['Accept'])
    [void]$client.DefaultRequestHeaders.TryAddWithoutValidation('Accept-Language', $browserHeaders['Accept-Language'])
    [void]$client.DefaultRequestHeaders.TryAddWithoutValidation('Cache-Control', $browserHeaders['Cache-Control'])
    [void]$client.DefaultRequestHeaders.TryAddWithoutValidation('Pragma', $browserHeaders['Pragma'])
    [void]$client.DefaultRequestHeaders.TryAddWithoutValidation('DNT', $browserHeaders['DNT'])

    return [PSCustomObject]@{ Client = $client; Handler = $handler }
}

function Invoke-HttpClientFallback {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][System.Net.Http.HttpClient]$Client
    )

    $uri = [Uri]$Url
    $siteKey = '{0}://{1}' -f $uri.Scheme, $uri.Host

    if ($Client.DefaultRequestHeaders.Contains('Referer')) {
        [void]$Client.DefaultRequestHeaders.Remove('Referer')
    }
    [void]$Client.DefaultRequestHeaders.TryAddWithoutValidation('Referer', $siteKey)

    $resp = $Client.GetAsync($Url).GetAwaiter().GetResult()
    if (-not $resp.IsSuccessStatusCode) {
        throw "HttpClient fallback failed: HTTP $([int]$resp.StatusCode) $($resp.ReasonPhrase)"
    }

    return $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
}

function Get-MsrcApiData {
    param([Parameter(Mandatory)][string]$Cve,[Parameter(Mandatory)][System.Net.Http.HttpClient]$Client)

    $candidateUrls = @(
        "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/$Cve",
        "https://api.msrc.microsoft.com/cvrf/v2.0/Updates('$Cve')",
        "https://api.msrc.microsoft.com/update-guide/v2.0/en-US/vulnerability/$Cve"
    )

    foreach ($apiUrl in $candidateUrls) {
        try {
            $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $apiUrl)
            [void]$req.Headers.TryAddWithoutValidation('Accept', 'application/json')
            $resp = $Client.SendAsync($req).GetAwaiter().GetResult()
            if ($resp.IsSuccessStatusCode) {
                $json = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                if (-not [string]::IsNullOrWhiteSpace($json)) {
                    return [PSCustomObject]@{ ApiUrl = $apiUrl; RawJson = $json }
                }
            }
        }
        catch {
            continue
        }
    }

    return $null
}

function Build-MsrcHtmlWrapper {
    param(
        [Parameter(Mandatory)][string]$Cve,
        [Parameter(Mandatory)][string]$OriginalUrl,
        [Parameter()][string]$PageHtml,
        [Parameter()][object]$ApiData
    )

    $title = Html-Encode $Cve
    $urlEncoded = Html-Encode $OriginalUrl
    $pagePreview = ''
    $apiSection = ''

    if (-not [string]::IsNullOrWhiteSpace($PageHtml)) {
        $snippet = $PageHtml
        if ($snippet.Length -gt 5000) { $snippet = $snippet.Substring(0,5000) }
        $pagePreview = "<h2>Fetched Page Preview</h2><pre>$(Html-Encode $snippet)</pre>"
    }

    if ($ApiData -and $ApiData.RawJson) {
        $raw = $ApiData.RawJson
        if ($raw.Length -gt 25000) { $raw = $raw.Substring(0,25000) }
        $apiUrlEncoded = Html-Encode $ApiData.ApiUrl
        $apiSection = @"
<h2>MSRC API Data</h2>
<p>Source API: <code>$apiUrlEncoded</code></p>
<pre>$(Html-Encode $raw)</pre>
"@
    }
    else {
        $apiSection = '<h2>MSRC API Data</h2><p>No API data was retrieved for this CVE during script execution.</p>'
    }

    return @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MSRC CVE Wrapper - $title</title>
<style>
body { font-family: Arial, sans-serif; margin: 24px; line-height: 1.5; }
pre { white-space: pre-wrap; word-break: break-word; background: #f3f3f3; padding: 12px; border: 1px solid #ccc; }
code { background: #f3f3f3; padding: 2px 4px; }
</style>
</head>
<body>
<h1>MSRC CVE Wrapper - $title</h1>
<p>Original URL: <a href="$urlEncoded">$urlEncoded</a></p>
<p>This wrapper was generated because the public MSRC vulnerability page may be JavaScript-rendered and not fully represented by a raw HTML fetch.</p>
$apiSection
$pagePreview
</body>
</html>
"@
}

function New-ManifestEntry {
    param(
        [string]$Title,
        [string]$Url,
        [string]$HtmlFile,
        [string]$Method,
        [string]$Status,
        [bool]$Blocked,
        [string]$BlockReason,
        [bool]$ChallengeLikely,
        [string]$ChallengeType,
        [string]$ChallengeReason,
        [bool]$IsMsrcCve,
        [string]$MsrcCve,
        [bool]$MsrcApiUsed,
        [string]$Notes
    )

    [PSCustomObject]@{
        Title            = $Title
        URL              = $Url
        HtmlFile         = $HtmlFile
        Method           = $Method
        Status           = $Status
        Blocked          = $Blocked
        BlockReason      = $BlockReason
        ChallengeLikely  = $ChallengeLikely
        ChallengeType    = $ChallengeType
        ChallengeReason  = $ChallengeReason
        IsMsrcCve        = $IsMsrcCve
        MsrcCve          = $MsrcCve
        MsrcApiUsed      = $MsrcApiUsed
        Notes            = $Notes
    }
}

function Safe-JsonOut {
    param([Parameter(Mandatory)]$Object,[Parameter(Mandatory)][string]$Path)
    $Object | ConvertTo-Json -Depth 8 | Set-Content -Path $Path -Encoding UTF8
}

$outlook = $null
$namespace = $null
$mailItem = $null
$httpClientPackage = $null
$client = $null
$tempMsgPath = $null
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
    if (-not $msgFile) { throw 'No .msg file found in directory.' }

    Write-Log -Level INFO -Message ("Processing MSG file: {0}" -f $msgFile.Name)

    $outlook = New-Object -ComObject Outlook.Application
    $namespace = $outlook.GetNamespace('MAPI')

    $tempMsgPath = Join-Path $env:TEMP ("DailyOps_{0}.msg" -f ([guid]::NewGuid().ToString()))
    Copy-Item -LiteralPath $msgFile.FullName -Destination $tempMsgPath -Force
    Write-Log -Level INFO -Message ("Created temp MSG copy: {0}" -f $tempMsgPath)

    $mailItem = $namespace.OpenSharedItem($tempMsgPath)

    $body = [string]$mailItem.Body
    $idx = $body.IndexOf($marker)
    if ($idx -ge 0) {
        $body = $body.Substring(0, $idx + $marker.Length)
        Write-Log -Level INFO -Message 'Trimmed body at FYSA marker.'
    }

    $pattern = '^\s*\*\s+(?<Title>.+?)\s*<(?<Url>https?://[^>]+)>'
    $matches = [regex]::Matches(
        $body,
        $pattern,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline
    )

    $osintItems = foreach ($m in $matches) {
        $title = [string]$m.Groups['Title'].Value.Trim()
        $url = [string]$m.Groups['Url'].Value.Trim()
        if ($url.Length -gt $maxUrlLengthForPrompt) { $url = $url.Substring(0, $maxUrlLengthForPrompt) }
        [PSCustomObject]@{ Title = $title; URL = $url }
    }

    if (($osintItems | Measure-Object).Count -eq 0) {
        Write-Log -Level WARN -Message 'No OSINT URLs found.'
    }

    Save-TextFile -Path $urlListTxt -Content ($osintItems | ForEach-Object { "OSINT - $($_.Title) - $($_.URL)" }) | Out-Null
    $osintItems | Export-Csv -Path $urlListCsv -NoTypeInformation -Encoding UTF8
    Safe-JsonOut -Object $osintItems -Path $urlListJson
    Write-Log -Level INFO -Message 'Saved URL lists.'

    $httpClientPackage = Initialize-HttpClient
    $client = $httpClientPackage.Client

    foreach ($item in $osintItems) {
        $safeTitle = Remove-InvalidFileNameChars -Name $item.Title
        $htmlPath = Get-UniquePath -Path (Join-Path $readyOut ("OSINT - $safeTitle.html"))
        $isMsrcCve = Test-IsMsrcCveUrl -Url $item.URL
        $msrcCve = if ($isMsrcCve) { Get-MsrcCveFromUrl -Url $item.URL } else { '' }

        $result = [PSCustomObject]@{
            Title           = $item.Title
            Url             = $item.URL
            HtmlFile        = ''
            Method          = $null
            Success         = $false
            Error           = $null
            Blocked         = $false
            BlockReason     = ''
            ChallengeLikely = $false
            ChallengeType   = ''
            ChallengeReason = ''
            IsMsrcCve       = $isMsrcCve
            MsrcCve         = $msrcCve
            MsrcApiUsed     = $false
        }
        $results += $result

        $delay = Get-RandomDelaySeconds
        Write-Log -Level INFO -Message ("Sleeping {0} second(s) before request: {1}" -f $delay, $item.URL)
        Start-Sleep -Seconds $delay

        $html = $null
        $methodUsed = $null
        $notes = ''

        try {
            Write-Log -Level INFO -Message ("Fetching via session request: {0}" -f $item.URL)
            $response = Invoke-SessionRequest -Url $item.URL -Sessions $sessions -BaseHeaders $browserHeaders
            $html = [string]$response.Content
            $methodUsed = 'Invoke-WebRequest'
        }
        catch {
            $firstErr = $_.Exception.Message
            Write-Log -Level WARN -Message ("Session request failed for {0}: {1}" -f $item.URL, $firstErr)

            try {
                Write-Log -Level INFO -Message ("Retrying via HttpClient fallback: {0}" -f $item.URL)
                $html = Invoke-HttpClientFallback -Url $item.URL -Client $client
                $methodUsed = 'HttpClient'
            }
            catch {
                $finalErr = $_.Exception.Message
                $msg = "All fetch methods failed for $($item.URL): $finalErr"
                Write-Log -Level ERROR -Message $msg
                $failedUrls += [PSCustomObject]@{ Title = $item.Title; URL = $item.URL; Error = $msg }
                $result.Method = 'Failed'
                $result.Success = $false
                $result.Error = $msg
                $manifest += New-ManifestEntry -Title $item.Title -Url $item.URL -HtmlFile '' -Method 'Failed' -Status 'Failed' -Blocked $false -BlockReason '' -ChallengeLikely $false -ChallengeType '' -ChallengeReason '' -IsMsrcCve $isMsrcCve -MsrcCve $msrcCve -MsrcApiUsed $false -Notes ''
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
                Write-Log -Level WARN -Message ("Possible block/challenge content detected for {0}: {1}" -f $item.URL, $blockReason)
            }

            $challengeTag = Get-ChallengeTag -Url $item.URL -Html $html
            $result.ChallengeLikely = $challengeTag.ChallengeLikely
            $result.ChallengeType = $challengeTag.ChallengeType
            $result.ChallengeReason = $challengeTag.ChallengeReason
            if ($result.ChallengeLikely) {
                Write-Log -Level WARN -Message ("Challenge-aware tag applied for {0}: {1}" -f $item.URL, $result.ChallengeReason)
            }

            if ($isMsrcCve) {
                try {
                    Write-Log -Level INFO -Message ("Attempting isolated MSRC enrichment for {0}" -f $msrcCve)
                    $apiData = Get-MsrcApiData -Cve $msrcCve -Client $client
                    $wrappedHtml = Build-MsrcHtmlWrapper -Cve $msrcCve -OriginalUrl $item.URL -PageHtml $html -ApiData $apiData
                    Set-Content -Path $htmlPath -Value $wrappedHtml -Encoding UTF8
                    if ($apiData -ne $null) {
                        $result.MsrcApiUsed = $true
                        $notes = 'MSRC API-backed wrapper generated.'
                    }
                    else {
                        $notes = 'MSRC API enrichment returned no data; wrapper includes fetched page preview only.'
                    }
                }
                catch {
                    $notes = "MSRC enrichment failed; preserved normal fetched HTML. Error: $($_.Exception.Message)"
                    Write-Log -Level WARN -Message $notes
                }
            }

            $manifest += New-ManifestEntry -Title $item.Title -Url $item.URL -HtmlFile $htmlPath -Method $methodUsed -Status 'Success' -Blocked $result.Blocked -BlockReason $result.BlockReason -ChallengeLikely $result.ChallengeLikely -ChallengeType $result.ChallengeType -ChallengeReason $result.ChallengeReason -IsMsrcCve $isMsrcCve -MsrcCve $msrcCve -MsrcApiUsed $result.MsrcApiUsed -Notes $notes
            Write-Log -Level INFO -Message ("Saved HTML file ({0}): {1}" -f $methodUsed, $item.URL)
        }
        catch {
            $msg = "Save failure for $($item.URL): $($_.Exception.Message)"
            Write-Log -Level ERROR -Message $msg
            $failedUrls += [PSCustomObject]@{ Title = $item.Title; URL = $item.URL; Error = $msg }
            $result.Method = $methodUsed
            $result.Success = $false
            $result.Error = $msg
        }
    }

    if (($failedUrls | Measure-Object).Count -gt 0) {
        $failedUrls | Export-Csv -Path $failedUrlsCsv -NoTypeInformation -Encoding UTF8
    }

    Write-Log -Level INFO -Message 'Processed all URLs.'

    foreach ($attachment in $mailItem.Attachments) {
        try {
            $originalName = [string]$attachment.FileName
            $safeAttachmentName = Remove-InvalidFileNameChars -Name $originalName
            $filePath = Get-UniquePath -Path (Join-Path $readyOut ("Source - $safeAttachmentName"))
            $attachment.SaveAsFile($filePath)

            $attachmentIndex += [PSCustomObject]@{
                FileName = [System.IO.Path]::GetFileName($filePath)
                Path     = $filePath
                Size     = $attachment.Size
            }

            Write-Log -Level INFO -Message ("Saved attachment: {0}" -f $originalName)
        }
        catch {
            $attachmentErr = $_.Exception.Message
            Write-Log -Level ERROR -Message ("Failed attachment: {0} - {1}" -f $attachment.FileName, $attachmentErr)
            $failedAttachments += [PSCustomObject]@{ FileName = $attachment.FileName; Error = $attachmentErr }
        }
    }

    if (($attachmentIndex | Measure-Object).Count -gt 0) {
        $attachmentIndex | Export-Csv -Path $attachmentIndexCsv -NoTypeInformation -Encoding UTF8
    }

    if (($failedAttachments | Measure-Object).Count -gt 0) {
        $failedAttachments | Export-Csv -Path $failedAttachmentsCsv -NoTypeInformation -Encoding UTF8
    }

    Write-Log -Level INFO -Message 'Processed attachments.'

    Safe-JsonOut -Object $manifest -Path $manifestJson
    Write-Log -Level INFO -Message 'Generated AI manifest.'

    $preparedFiles = @(Get-ChildItem -Path $readyOut -File | Select-Object -ExpandProperty Name | Sort-Object)
    $fileListText = if ($preparedFiles.Count -gt 0) {
        ($preparedFiles | ForEach-Object { "- $_" }) -join [Environment]::NewLine
    } else {
        '- No files were prepared successfully.'
    }

    $failureNote = @()
    if (($failedUrls | Measure-Object).Count -gt 0) { $failureNote += "URL failures: $($failedUrls.Count)" }
    if (($failedAttachments | Measure-Object).Count -gt 0) { $failureNote += "Attachment failures: $($failedAttachments.Count)" }
    $challengeCount = @($results | Where-Object { $_.ChallengeLikely }).Count
    if ($challengeCount -gt 0) { $failureNote += "Challenge-tagged pages: $challengeCount" }
    $msrcCount = @($results | Where-Object { $_.IsMsrcCve }).Count
    if ($msrcCount -gt 0) { $failureNote += "MSRC CVE pages: $msrcCount" }
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
If content appears truncated, corrupted, HTML artifact-heavy, challenge-gated, or dynamically rendered:
Possible incomplete or gated scrape detected - please verify source content.
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
MSRC wrapper files may include API-backed metadata when available. Challenge-tagged pages may contain partial or gated content.

Files:
$fileListText

7. EXTRACTION NOTES
$failureNoteText
If a page appears to be a block, challenge page, dynamically rendered shell, or incomplete scrape based on the HTML content, treat that source cautiously.
"@

    $prompt = Convert-ToPlainAscii -Text $prompt
    $null = Save-TextFile -Path $promptPath -Content $prompt
    Write-Log -Level INFO -Message 'Generated ASCII-sanitized AI prompt.'

    Write-Log -Level INFO -Message 'Script completed successfully.'

    $successCount = @($results | Where-Object { $_.Success }).Count
    $failCount = @($results | Where-Object { -not $_.Success }).Count

    Write-Host ''
    Write-Host 'Article fetch summary:' -ForegroundColor Cyan
    Write-Host ("  Successful: {0}" -f $successCount)
    Write-Host ("  Failed:     {0}" -f $failCount)
    Write-Host ("  Challenge tagged: {0}" -f $challengeCount)
    Write-Host ("  MSRC CVE tagged: {0}" -f $msrcCount)
    Write-Host ''
    Write-Host ("Ready folder: {0}" -f $readyOut) -ForegroundColor Green
    Write-Host ("Prompt file:  {0}" -f $promptPath) -ForegroundColor Green
}
catch {
    Write-Log -Level ERROR -Message ("Fatal error: {0}" -f $_.Exception.Message)
    throw
}
finally {
    if ($client -ne $null) {
        try { $client.Dispose() } catch {}
    }
    if ($mailItem -ne $null) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($mailItem) }
    if ($namespace -ne $null) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($namespace) }
    if ($outlook -ne $null) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($outlook) }
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()

    if ($tempMsgPath -and (Test-Path -LiteralPath $tempMsgPath)) {
        try { Remove-Item -LiteralPath $tempMsgPath -Force -ErrorAction SilentlyContinue } catch {}
    }
}
