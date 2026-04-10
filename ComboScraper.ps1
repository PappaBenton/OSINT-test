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
$articleOut = Join-Path $readyOut 'articles'
$attachOut = Join-Path $readyOut 'attachments'
$logFile = Join-Path $rootOut 'run.log'
$urlListTxt = Join-Path $readyOut 'osint-title-link.txt'
$urlListJson = Join-Path $readyOut 'osint-title-link.json'
$urlStatusCsv = Join-Path $readyOut 'scrape-url-status.csv'
$attachmentIndexCsv = Join-Path $rootOut 'attachments-index.csv'
$failedAttachmentsCsv = Join-Path $rootOut 'failed-attachments.csv'
$browserTimeoutMs = 80000
$minDelaySeconds = 2
$maxDelaySeconds = 5
$maxUrlLength = 2000

$browserHeaders = @{
    'User-Agent'                = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
    'Accept'                    = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
    'Accept-Language'           = 'en-US,en;q=0.9'
    'Accept-Encoding'           = 'gzip, deflate, br'
    'Connection'                = 'keep-alive'
    'Cache-Control'             = 'no-cache'
    'Pragma'                    = 'no-cache'
    'Upgrade-Insecure-Requests' = '1'
    'DNT'                       = '1'
}

function Initialize-OutputFolders {
    New-Item -ItemType Directory -Force -Path $rootOut, $readyOut, $articleOut, $attachOut | Out-Null
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
    $invalidPattern = "[{0}]" -f [Regex]::Escape($invalidChars)

    $clean = $Name -replace $invalidPattern, ' '
    $clean = $clean -replace '[^\p{L}\p{Nd}\s.-]', ' '
    $clean = $clean -replace '\s+', ' '
    $clean = $clean.Trim().TrimEnd('.', ' ')

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

function Get-ChromiumPath {
    $candidates = @(
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe"
    )

    foreach ($path in $candidates) {
        if (Test-Path $path) { return $path }
    }

    throw 'Neither Microsoft Edge nor Google Chrome was found.'
}

function Get-OrderedOsintItems {
    param(
        [Parameter(Mandatory)][string]$HtmlBody,
        [Parameter(Mandatory)][string]$PlainBody
    )

    $items = New-Object System.Collections.Generic.List[object]
    $workingPlain = $PlainBody
    $workingHtml = $HtmlBody

    $plainIdx = $workingPlain.IndexOf($marker)
    if ($plainIdx -ge 0) {
        $workingPlain = $workingPlain.Substring(0, $plainIdx + $marker.Length)
    }

    $htmlIdx = $workingHtml.IndexOf($marker)
    if ($htmlIdx -ge 0) {
        $workingHtml = $workingHtml.Substring(0, $htmlIdx + $marker.Length)
    }

    $anchorPattern = '<a\b[^>]*href\s*=\s*"(?<Url>https?://[^"]+)"[^>]*>(?<Title>.*?)</a>'
    $matches = [regex]::Matches(
        $workingHtml,
        $anchorPattern,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Singleline
    )

    $order = 1
    foreach ($m in $matches) {
        $url = [string]$m.Groups['Url'].Value.Trim()
        $title = [string]$m.Groups['Title'].Value
        $title = [regex]::Replace($title, '<[^>]+>', ' ')
        try { $title = [System.Net.WebUtility]::HtmlDecode($title) } catch {}
        $title = ($title -replace '\s+', ' ').Trim()

        if ([string]::IsNullOrWhiteSpace($title)) { continue }
        if ([string]::IsNullOrWhiteSpace($url)) { continue }
        if ($url.Length -gt $maxUrlLength) { $url = $url.Substring(0, $maxUrlLength) }

        $items.Add([PSCustomObject]@{
            Order = $order
            Source = 'OSINT'
            Title = $title
            URL = $url
            Label = "$title - $url"
        })
        $order++
    }

    if ($items.Count -gt 0) { return $items }

    $fallbackPattern = '^\s*\*\s+(?<Title>.+?)\s*<(?<Url>https?://[^>]+)>'
    $fallbackMatches = [regex]::Matches(
        $workingPlain,
        $fallbackPattern,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline
    )

    $fallbackOrder = 1
    foreach ($m in $fallbackMatches) {
        $title = [string]$m.Groups['Title'].Value.Trim()
        $url = [string]$m.Groups['Url'].Value.Trim()
        if ([string]::IsNullOrWhiteSpace($title)) { continue }
        if ([string]::IsNullOrWhiteSpace($url)) { continue }
        if ($url.Length -gt $maxUrlLength) { $url = $url.Substring(0, $maxUrlLength) }

        $items.Add([PSCustomObject]@{
            Order = $fallbackOrder
            Source = 'OSINT'
            Title = $title
            URL = $url
            Label = "$title - $url"
        })
        $fallbackOrder++
    }

    return $items
}

function Get-ArticleTextFromHtml {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Html
    )

    if (-not $Html) { return '' }

    try {
        $doc = New-Object -ComObject 'HTMLFile'
        $doc.IHTMLDocument2_write([ref]$Html)
        $doc.Close()

        $articles = @($doc.getElementsByTagName('article'))
        if ($articles.Count -gt 0) {
            $a = $articles[0]
            if ($a -and $a.innerText) {
                $txt = $a.innerText
                $txt = [regex]::Replace($txt, '\r?\n{3,}', "`r`n`r`n")
                return $txt.Trim()
            }
        }

        $pattern = 'article|story|content|post|entry|main|body'
        $candidates = @()

        foreach ($el in $doc.all) {
            $id = $el.id
            $cls = $el.className
            if ((($id -and $id -match $pattern) -or ($cls -and $cls -match $pattern)) -and $el.innerText -and $el.innerText.Length -gt 200) {
                $candidates += $el
            }
        }

        if ($candidates.Count -gt 0) {
            $best = $candidates | Sort-Object { $_.innerText.Length } -Descending | Select-Object -First 1
            $txt = $best.innerText
            $txt = [regex]::Replace($txt, '\r?\n{3,}', "`r`n`r`n")
            return $txt.Trim()
        }
    }
    catch {
    }

    try { Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue } catch {}

    $text = $Html
    $text = [regex]::Replace($text, '<script.*?</script>', '', 'Singleline, IgnoreCase')
    $text = [regex]::Replace($text, '<style.*?</style>', '', 'Singleline, IgnoreCase')
    $text = [regex]::Replace($text, '<\s*(br|/p|/div|/section|/article|/li|/h[1-6])\b[^>]*>', "`r`n", 'IgnoreCase')
    $text = [regex]::Replace($text, '<[^>]+>', ' ')
    try { $text = [System.Web.HttpUtility]::HtmlDecode($text) } catch {}
    $text = [regex]::Replace($text, '\r?\n\s*\r?\n\s*', "`r`n`r`n")
    $text = [regex]::Replace($text, '[ \t]{2,}', ' ')
    return $text.Trim()
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
        } catch {}
        $Sessions[$siteKey] = $session
    }

    $session = $Sessions[$siteKey]
    $headers = @{}
    foreach ($key in $BaseHeaders.Keys) { $headers[$key] = $BaseHeaders[$key] }
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

function Get-ArticleTextViaHttp {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][hashtable]$Sessions,
        [Parameter(Mandatory)][hashtable]$BaseHeaders,
        [Parameter(Mandatory)][System.Net.Http.HttpClient]$Client
    )

    try {
        $response = Invoke-SessionRequest -Url $Url -Sessions $Sessions -BaseHeaders $BaseHeaders
        $html = [string]$response.Content
    }
    catch {
        $html = Invoke-HttpClientFallback -Url $Url -Client $Client
    }

    if ([string]::IsNullOrWhiteSpace($html)) {
        throw 'HTTP fetch returned empty content.'
    }

    $text = Get-ArticleTextFromHtml -Html $html
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw 'Article text was empty after HTML cleaning.'
    }

    return $text
}

function Get-ArticleTextViaBrowser {
    param(
        [Parameter(Mandatory)][string]$Url
    )

    $browser = Get-ChromiumPath
    $escapedUrl = '"' + $Url.Replace('"','\"') + '"'

    $argList = @(
        '--headless=new'
        '--disable-gpu'
        '--run-all-compositor-stages-before-draw'
        '--virtual-time-budget=15000'
        '--dump-dom'
        $escapedUrl
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $browser
    $psi.Arguments = ($argList -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    [void]$proc.Start()

    if (-not $proc.WaitForExit($browserTimeoutMs)) {
        try {
            $proc.Kill()
            $proc.WaitForExit()
        } catch {}
        throw "Browser fetch timed out after $browserTimeoutMs ms for URL: $Url"
    }

    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $exitCode = $proc.ExitCode

    if ($exitCode -ne 0) {
        throw "Browser fetch failed. ExitCode=$exitCode Url=$Url StdErr=$stderr"
    }

    if ([string]::IsNullOrWhiteSpace($stdout)) {
        throw "Browser returned empty DOM output for URL: $Url. StdErr=$stderr"
    }

    $cleanText = Get-ArticleTextFromHtml -Html $stdout
    if ([string]::IsNullOrWhiteSpace($cleanText)) {
        throw 'Browser content was empty after HTML cleaning.'
    }

    return $cleanText
}

$outlook = $null
$namespace = $null
$mailItem = $null
$attachmentsCom = $null
$httpClientPackage = $null
$client = $null
$tempMsgPath = $null
$sessions = @{}
$osintItems = @()
$results = @()
$attachmentIndex = @()
$failedAttachments = @()
$attachmentOrder = 0

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
    $mailItem = $namespace.OpenSharedItem($tempMsgPath)

    $plainBody = [string]$mailItem.Body
    $htmlBody = [string]$mailItem.HTMLBody

    $osintItems = Get-OrderedOsintItems -HtmlBody $htmlBody -PlainBody $plainBody

    if (($osintItems | Measure-Object).Count -eq 0) {
        Write-Log -Level WARN -Message 'No OSINT URLs found.'
    }

    Save-TextFile -Path $urlListTxt -Content ($osintItems | Sort-Object Order | ForEach-Object { $_.Label }) | Out-Null
    ($osintItems | Sort-Object Order) | ConvertTo-Json -Depth 5 | Set-Content -Path $urlListJson -Encoding UTF8
    Write-Log -Level INFO -Message 'Saved ordered OSINT title/link outputs in original email order.'

    $httpClientPackage = Initialize-HttpClient
    $client = $httpClientPackage.Client

    foreach ($item in ($osintItems | Sort-Object Order)) {
        $cleanTitle = Remove-InvalidFileNameChars -Name $item.Title
        $filePath = Get-UniquePath -Path (Join-Path $articleOut ("{0}.txt" -f $cleanTitle))

        $result = [ordered]@{
            Order = $item.Order
            Status = 'Failed'
            Method = 'None'
            'Article Title' = $item.Title
            URL = $item.URL
            Notes = 'Manual review required'
            SavedAs = [System.IO.Path]::GetFileName($filePath)
        }

        $delay = Get-RandomDelaySeconds
        Write-Log -Level INFO -Message ("Sleeping {0} second(s) before request: {1}" -f $delay, $item.URL)
        Start-Sleep -Seconds $delay

        try {
            Write-Log -Level INFO -Message ("Fetching via HTTP-first path: {0}" -f $item.URL)
            $content = Get-ArticleTextViaHttp -Url $item.URL -Sessions $sessions -BaseHeaders $browserHeaders -Client $client

            if ($content -like '*You need to enable JavaScript to run this app*' -or
                $content -like '*Enable JavaScript*' -or
                $content -like '*Please enable JavaScript*') {
                throw 'JS-gated page detected in HTTP response.'
            }

            Save-TextFile -Path $filePath -Content @(
                "TITLE: $($item.Title)"
                "URL: $($item.URL)"
                ""
                $content
            ) | Out-Null

            $result.Status = 'Success'
            $result.Method = 'HTTP'
            $result.Notes = 'Successfully scraped'
            Write-Log -Level INFO -Message ("Saved article content via HTTP: {0}" -f $filePath)
        }
        catch {
            $httpErr = $_.Exception.Message
            Write-Log -Level WARN -Message ("HTTP path failed for {0}: {1}" -f $item.URL, $httpErr)

            try {
                Write-Log -Level INFO -Message ("Retrying via headless browser: {0}" -f $item.URL)
                $content = Get-ArticleTextViaBrowser -Url $item.URL

                Save-TextFile -Path $filePath -Content @(
                    "TITLE: $($item.Title)"
                    "URL: $($item.URL)"
                    ""
                    $content
                ) | Out-Null

                $result.Status = 'Success'
                $result.Method = 'Browser'
                $result.Notes = 'Successfully scraped via browser fallback'
                Write-Log -Level INFO -Message ("Saved article content via browser: {0}" -f $filePath)
            }
            catch {
                $browserErr = $_.Exception.Message
                Save-TextFile -Path $filePath -Content @(
                    "TITLE: $($item.Title)"
                    "URL: $($item.URL)"
                    ""
                    'FAILED TO PULL'
                ) | Out-Null

                $result.Status = 'Failed'
                $result.Method = 'Failed'
                $result.Notes = "HTTP: $httpErr | Browser: $browserErr"
                Write-Log -Level ERROR -Message ("All fetch methods failed for {0}: {1}" -f $item.URL, $browserErr)
            }
        }

        $results += [PSCustomObject]$result
    }

    if (($results | Measure-Object).Count -gt 0) {
        $results |
            Sort-Object Order |
            Select-Object Status, Method, 'Article Title', URL, SavedAs, Notes |
            Export-Csv -Path $urlStatusCsv -NoTypeInformation -Encoding UTF8
        Write-Log -Level INFO -Message 'Generated unified scrape URL status CSV.'
    }

    $attachmentsCom = $mailItem.Attachments
    Write-Log -Level INFO -Message ("Found {0} attachment(s)." -f $attachmentsCom.Count)

    foreach ($att in $attachmentsCom) {
        $attachmentOrder++
        $origName = [string]$att.FileName

        try {
            $savePath = Get-UniquePath -Path (Join-Path $attachOut $origName)
            $att.SaveAsFile($savePath)

            $attachmentIndex += [PSCustomObject]@{
                Order = $attachmentOrder
                OriginalName = $origName
                SavedAs = [System.IO.Path]::GetFileName($savePath)
                Path = $savePath
                Size = $att.Size
                Status = 'Saved'
            }

            Write-Log -Level INFO -Message ("Saved attachment with original email filename: {0}" -f $origName)
        }
        catch {
            $attachmentErr = $_.Exception.Message
            $failedAttachments += [PSCustomObject]@{
                Order = $attachmentOrder
                FileName = $origName
                Error = $attachmentErr
            }
            Write-Log -Level ERROR -Message ("Failed attachment: {0} - {1}" -f $origName, $attachmentErr)
        }
    }

    if (($attachmentIndex | Measure-Object).Count -gt 0) {
        $attachmentIndex | Sort-Object Order | Export-Csv -Path $attachmentIndexCsv -NoTypeInformation -Encoding UTF8
    }

    if (($failedAttachments | Measure-Object).Count -gt 0) {
        $failedAttachments | Sort-Object Order | Export-Csv -Path $failedAttachmentsCsv -NoTypeInformation -Encoding UTF8
    }

    $successCount = @($results | Where-Object { $_.Status -eq 'Success' }).Count
    $failCount = @($results | Where-Object { $_.Status -eq 'Failed' }).Count

    Write-Host ''
    Write-Host 'Article fetch summary:' -ForegroundColor Cyan
    Write-Host ("  Successful: {0}" -f $successCount)
    Write-Host ("  Failed:     {0}" -f $failCount)
    Write-Host ''
    Write-Host ("Ready folder: {0}" -f $readyOut) -ForegroundColor Green

    $manualReviewItems = @($results | Where-Object { $_.Status -eq 'Failed' } | Sort-Object Order)
    if ($manualReviewItems.Count -gt 0) {
        Write-Host ''
        $answer = Read-Host ("Open {0} manual-review URL(s) now? (Y/N)" -f $manualReviewItems.Count)
        if ($answer -match '^(?i)y(?:es)?$') {
            foreach ($item in $manualReviewItems) {
                if (-not [string]::IsNullOrWhiteSpace($item.URL)) {
                    Write-Host ("Opening: {0}" -f $item.URL) -ForegroundColor Yellow
                    Start-Process $item.URL
                    Start-Sleep -Milliseconds 500
                }
            }
        }
    }

    Write-Log -Level INFO -Message 'Script completed successfully.'
}
catch {
    Write-Log -Level ERROR -Message ("Fatal error: {0}" -f $_.Exception.Message)
    throw
}
finally {
    if ($client -ne $null) {
        try { $client.Dispose() } catch {}
    }
    if ($attachmentsCom -ne $null) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($attachmentsCom) }
    if ($mailItem -ne $null) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($mailItem) }
    if ($namespace -ne $null) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($namespace) }
    if ($outlook -ne $null) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($outlook) }
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()

    if ($tempMsgPath -and (Test-Path -LiteralPath $tempMsgPath)) {
        try { Remove-Item -LiteralPath $tempMsgPath -Force -ErrorAction SilentlyContinue } catch {}
    }
}
