#tested with POSH Version 7

<#
.SYNOPSIS
Parse an Outlook .msg file for OSINT URLs and attachments, save article content and attachments,
and generate logs/manifests for downstream AI-assisted MTTP/TTP extraction.

.DESCRIPTION
Workflow:
1. Load first .msg file in current directory
2. Read Body and HTMLBody
3. Trim body at FYSA marker if present
4. Extract OSINT title/URL pairs from plain-text bullet lines
5. Save URL list to txt/csv/json
6. Fetch each URL via Microsoft Edge or Google Chrome headless --dump-dom
7. Save all attachments from the .msg
8. Log all successes/failures without terminating the whole run
9. Output summary files for downstream AI processing

.NOTES
- Tested for Windows PowerShell 7 with Outlook installed
- Uses Outlook COM
- Uses Edge first, then Chrome, in headless mode for article retrieval
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


# -----------------------------
# Simple menu
# -----------------------------
Read-Host -Prompt "Press Enter to start"


# -----------------------------
# Configuration
# -----------------------------
$marker = '(U) FYSA:'
$basePath = Get-Location
$rootOut = Join-Path $basePath 'output'
$articleOut = Join-Path $rootOut 'articles'
$attachOut = Join-Path $rootOut 'attachments'
$logFile = Join-Path $rootOut 'run.log'
$urlListTxt = Join-Path $rootOut 'osint-title-link.txt'
$urlListCsv = Join-Path $rootOut 'osint-title-link.csv'
$urlListJson = Join-Path $rootOut 'osint-title-link.json'
$attachmentIndexCsv = Join-Path $rootOut 'attachments-index.csv'
$failedUrlsCsv = Join-Path $rootOut 'failed-urls.csv'
$failedAttachmentsCsv = Join-Path $rootOut 'failed-attachments.csv'
$manifestJson = Join-Path $rootOut 'ai-manifest.json'

# Max time (ms) to wait for headless browser to return DOM
$browserTimeoutMs = 80000   # 80 seconds; adjust as needed


# -----------------------------
# Helpers
# -----------------------------
function Initialize-OutputFolders {
    New-Item -ItemType Directory -Force -Path $rootOut, $articleOut, $attachOut | Out-Null
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

    if ([string]::IsNullOrWhiteSpace($clean)) {
        return 'untitled'
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

        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [object[]]$Content
    )

    $target = Get-UniquePath -Path $Path

    if ($null -eq $Content) {
        $Content = @()
    }

    $normalized = foreach ($line in $Content) {
        if ($null -eq $line) {
            ''
        }
        else {
            [string]$line
        }
    }

    Set-Content -Path $target -Value $normalized -Encoding UTF8 -ErrorAction Stop
    return $target
}

function Get-ChromiumPath {
    $candidates = @(
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe"
    )

    foreach ($path in $candidates) {
        if (Test-Path $path) {
            return $path
        }
    }

    throw "Neither Microsoft Edge nor Google Chrome was found."
}

# HTTP first-pass settings for article fetch
$baseHeaders = @{
    'User-Agent'      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
    'Accept'          = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
    'Accept-Language' = 'en-US,en;q=0.9'
    'Accept-Encoding' = 'gzip, deflate, br'
    'Connection'      = 'keep-alive'
}

# per-site WebRequestSession cache
$sessions = @{}

function Get-ArticleTextViaHttp {
    param(
        [Parameter(Mandatory)]
        [string]$Url
    )

    $uri     = [Uri]$Url
    $siteKey = '{0}://{1}' -f $uri.Scheme, $uri.Host   # e.g., https://www.example.com

    # Ensure session for this site
    if (-not $sessions.ContainsKey($siteKey)) {
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        try {
            Invoke-WebRequest -Uri $siteKey -Headers $baseHeaders -WebSession $session -ErrorAction SilentlyContinue | Out-Null
        } catch {
            # warm-up failure is non-fatal
        }
        $sessions[$siteKey] = $session
    }

    $session = $sessions[$siteKey]
    $headers = $baseHeaders.Clone()
    $headers['Referer'] = $siteKey

    # HTTP fetch
    $response = Invoke-WebRequest -Uri $Url `
                                  -Headers $headers `
                                  -WebSession $session `
                                  -MaximumRedirection 5 `
                                  -ErrorAction Stop

    if ([string]::IsNullOrWhiteSpace($response.Content)) {
        throw "HTTP fetch returned empty content."
    }

    $text = Get-ArticleTextFromHtml -Html $response.Content

    if ([string]::IsNullOrWhiteSpace($text)) {
        throw "Article text was empty after HTML cleaning."
    }

    return $text
}


function Get-ArticleTextFromHtml {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Html
    )

    if (-not $Html) { return '' }

    # --- 1. Try DOM-based extraction via MSHTML COM ---
    try {
        $doc = New-Object -ComObject 'HTMLFile'
        $doc.IHTMLDocument2_write([ref]$Html)
        $doc.Close()

        # 1a) Prefer <article> elements
        $articles = @($doc.getElementsByTagName('article'))
        if ($articles.Count -gt 0) {
            $a = $articles[0]
            if ($a -and $a.innerText) {
                $txt = $a.innerText
                $txt = [regex]::Replace($txt, '\r?\n{3,}', "`r`n`r`n")
                return $txt.Trim()
            }
        }

        # 1b) Look for common article/content containers by id/class
        $pattern    = 'article|story|content|post|entry|main|body'
        $candidates = @()

        foreach ($el in $doc.all) {
            $id  = $el.id
            $cls = $el.className

            if (($id  -and $id  -match $pattern) -or
                ($cls -and $cls -match $pattern)) {

                if ($el.innerText -and $el.innerText.Length -gt 200) {
                    $candidates += $el
                }
            }
        }

        if ($candidates.Count -gt 0) {
            $best = $candidates |
                    Sort-Object { $_.innerText.Length } -Descending |
                    Select-Object -First 1

            $txt = $best.innerText
            $txt = [regex]::Replace($txt, '\r?\n{3,}', "`r`n`r`n")
            return $txt.Trim()
        }
    }
    catch {
        # If COM/MSHTML not available, fall through to regex-based fallback
    }

    # --- 2. Fallback: generic HTML → text (may include some boilerplate) ---
    try { Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue } catch {}

    $text = $Html

    # Remove script and style blocks
    $text = [regex]::Replace($text, '<script.*?</script>', '', 'Singleline, IgnoreCase')
    $text = [regex]::Replace($text, '<style.*?</style>',  '', 'Singleline, IgnoreCase')

    # Convert some tags to line breaks
    $text = [regex]::Replace($text, '<\s*(br|/p|/div|/section|/article|/li|/h[1-6])\b[^>]*>', "`r`n", 'IgnoreCase')

    # Strip remaining tags
    $text = [regex]::Replace($text, '<[^>]+>', ' ')

    # Decode HTML entities if possible
    try {
        $text = [System.Web.HttpUtility]::HtmlDecode($text)
    } catch {}

    # Normalize whitespace
    $text = [regex]::Replace($text, '\r?\n\s*\r?\n\s*', "`r`n`r`n")
    $text = [regex]::Replace($text, '[ \t]{2,}', ' ')
    return $text.Trim()
}


function Get-ArticleText {
    param(
        [Parameter(Mandatory)]
        [string]$Url
    )

    $browser    = Get-ChromiumPath
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
    $psi.FileName               = $browser
    $psi.Arguments              = ($argList -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi

    [void]$proc.Start()

    # Wait with timeout; if it doesn't exit, kill it and fail
    if (-not $proc.WaitForExit($browserTimeoutMs)) {
        try {
            $proc.Kill()
            $proc.WaitForExit()
        } catch { }

        throw "Browser fetch timed out after $browserTimeoutMs ms for URL: $Url"
    }

    # Process has exited at this point; now read output
    $stdout   = $proc.StandardOutput.ReadToEnd()
    $stderr   = $proc.StandardError.ReadToEnd()
    $exitCode = $proc.ExitCode

    if ($exitCode -ne 0) {
        throw "Browser fetch failed. ExitCode=$exitCode Url=$Url StdErr=$stderr"
    }

    if ([string]::IsNullOrWhiteSpace($stdout)) {
        throw "Browser returned empty DOM output for URL: $Url. StdErr=$stderr"
    }

    # Clean/strip the HTML into article text (same cleaning you already use)
    $cleanText = Get-ArticleTextFromHtml -Html $stdout
    return $cleanText
}





# -----------------------------
# Main
# -----------------------------

$outlook = $null
$namespace = $null
$mailItem = $null
$attachmentsCom = $null

if ($attachmentsCom -ne $null) {
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($attachmentsCom)
    }

    if ($mailItem -ne $null) {
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($mailItem)
    }

    if ($outlook -ne $null) {
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($outlook)
    }


$outlook = $null
$namespace = $null
$mailItem = $null
$attachmentsCom = $null

$httpClientPackage = $null

$osintItems = @()
$failedUrls = @()
$attachmentIndex = @()
$failedAttachments = @()

try {
    Initialize-OutputFolders
    "" | Set-Content -Path $logFile -Encoding UTF8

    Write-Log -Level INFO -Message "Starting Outlook MSG parser run."

    $msg = Get-ChildItem -Path $basePath -Filter *.msg | Select-Object -First 1
    if (-not $msg) {
        throw "No .msg file found in current directory."
    }

    Write-Log -Level INFO -Message "Using MSG file: $($msg.FullName)"

    $browserPath = Get-ChromiumPath
    Write-Log -Level INFO -Message "Using browser engine: $browserPath"

    $outlook = New-Object -ComObject Outlook.Application
    $mailItem = $outlook.CreateItemFromTemplate($msg.FullName)

    $plainBody = $mailItem.Body
    $htmlBody = $mailItem.HTMLBody
    $subject = $mailItem.Subject
    $receivedTime = $mailItem.ReceivedTime

    Write-Log -Level INFO -Message "Loaded mail item. Subject='$subject' Received='$receivedTime'"

    # Trim body at FYSA marker if present
    $idx = $plainBody.IndexOf($marker)
    if ($idx -ge 0) {
        $plainBody = $plainBody.Substring(0, $idx + $marker.Length)
        Write-Log -Level INFO -Message "FYSA marker found. Body trimmed at marker '$marker'."
    }
    else {
        Write-Log -Level WARN -Message "FYSA marker '$marker' not found. Using full body."
    }

    # Regex for lines like:
    # * Some Title <https://example.com>
    $pattern = '^\s*\*\s+(?<Title>.+?)\s*<(?<Url>https?://[^>]+)>'
    $regexOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor `
                    [System.Text.RegularExpressions.RegexOptions]::Multiline

    $matches = [regex]::Matches($plainBody, $pattern, $regexOptions)
    Write-Log -Level INFO -Message "Found $($matches.Count) candidate OSINT URL entries."

    foreach ($m in $matches) {
        $title = $m.Groups['Title'].Value.Trim()
        $url = $m.Groups['Url'].Value.Trim()

        if ([string]::IsNullOrWhiteSpace($title) -or [string]::IsNullOrWhiteSpace($url)) {
            Write-Log -Level WARN -Message "Skipped malformed OSINT line due to missing title or URL."
            continue
        }

        $osintItems += [PSCustomObject]@{
            Source = 'OSINT'
            Title  = $title
            Url    = $url
            Label  = "OSINT - $title - $url"
        }
    }

    # Save URL lists
    $osintItems.Label | Set-Content -Path $urlListTxt -Encoding UTF8 -ErrorAction Stop
    $osintItems | Export-Csv -Path $urlListCsv -NoTypeInformation -Encoding UTF8
    $osintItems | ConvertTo-Json -Depth 4 | Set-Content -Path $urlListJson -Encoding UTF8

    Write-Log -Level INFO -Message "Saved OSINT URL lists to txt/csv/json."

# First pass: try HTTP (Invoke-WebRequest) for all URLs
$browserRetryItems = @()

foreach ($item in $osintItems) {
    $safeTitle = Remove-InvalidFileNameChars -Name $item.Title
    $fileName  = "OSINT - $safeTitle.txt"
    $filePath  = Join-Path $articleOut $fileName

    try {
        Write-Log -Level INFO -Message "Fetching URL via HTTP: $($item.Url)"
        $content = Get-ArticleTextViaHttp -Url $item.Url

        # NEW: detect JS-gated pages and defer to browser
        if ($content -like '*You need to enable JavaScript to run this app*') {
            Write-Log -Level WARN -Message "HTTP content indicates JS-gated page; queuing for browser: Title='$($item.Title)' Url='$($item.Url)'"

            $browserRetryItems += [PSCustomObject]@{
                Title    = $item.Title
                Url      = $item.Url
                FilePath = $filePath
            }

            continue
        }

        # Normal HTTP success path
        $savedPath = Save-TextFile -Path $filePath -Content @(
            "TITLE: $($item.Title)"
            "URL: $($item.Url)"
            ""
            $content
        )

        Write-Log -Level INFO -Message "Saved article content via HTTP: $savedPath"
    }
    catch {
        $errMsg = $_.Exception.Message
        Write-Log -Level WARN -Message "HTTP fetch failed; will retry via browser: Title='$($item.Title)' Url='$($item.Url)' Error='$errMsg'"

        # Queue for browser fallback; reuse same file path
        $browserRetryItems += [PSCustomObject]@{
            Title    = $item.Title
            Url      = $item.Url
            FilePath = $filePath
        }

        continue
    }
}


# Second pass: retry only failed URLs via Chromium browser
foreach ($item in $browserRetryItems) {
    $title    = $item.Title
    $url      = $item.Url
    $filePath = $item.FilePath

    try {
        Write-Log -Level INFO -Message "Fetching URL via Chromium browser (fallback): $url"
        $content = Get-ArticleText -Url $url

        $savedPath = Save-TextFile -Path $filePath -Content @(
            "TITLE: $title"
            "URL: $url"
            ""
            $content
        )

        Write-Log -Level INFO -Message "Saved article content via browser: $savedPath"
    }
    catch {
        $errMsg = $_.Exception.Message

        $failedUrls += [PSCustomObject]@{
            Title = $title
            Url   = $url
            Error = $errMsg
        }

        Write-Log -Level ERROR -Message "BROWSER URL FAILED: Title='$title' Url='$url' Error='$errMsg'"

        try {
            # NEW: always write a simple stub file for Chrome failures
            $savedPath = Save-TextFile -Path $filePath -Content @(
                "TITLE: $title"
                "URL: $url"
                ""
                "FAILED TO PULL"
            )

            Write-Log -Level WARN -Message "Saved failure stub for URL: $savedPath"
        }
        catch {
            $stubErr = $_.Exception.Message
            Write-Log -Level ERROR -Message "FAILED TO SAVE URL FAILURE STUB: Title='$title' Error='$stubErr'"
        }

        continue
    }
}



    # Extract attachments
	$attachmentsCom = $mailItem.Attachments
	Write-Log -Level INFO -Message "Found $($attachmentsCom.Count) attachment(s)."

	foreach ($att in $attachmentsCom) {
		$origName = $att.FileName
		$baseName = [System.IO.Path]::GetFileNameWithoutExtension($origName)
		$ext      = [System.IO.Path]::GetExtension($origName)

		# --- Only process PDFs ---
		if ($ext -ine '.pdf') {
			Write-Log -Level INFO -Message "Skipping non-PDF attachment: $origName"
			continue
		}

		# Skip any PDF whose name contains "Tipper" (case-insensitive)
		if ($origName -imatch 'Tipper') {
			Write-Log -Level INFO -Message "Skipping PDF (Tipper match): $origName"
			continue
		}

		if (-not $baseName) {
			Write-Log -Level WARN -Message "Skipping PDF with empty/invalid base name: $origName"
			continue
		}

		# Default: Source - <original-name>.pdf
		$safeBase = Remove-InvalidFileNameChars -Name $baseName
		$safeBase = "Source - $safeBase"

		# Apply vendor prefixes, *keeping* the full original base name
		# 26-xxxx.pdf   -> Mandiant - 26-xxxx.pdf
		# csa-xxxx.pdf  -> Crowdstrike - csa-xxxx.pdf
		# OSIR-xxxx.pdf -> HSIN - OSIR-xxxx.pdf
		if ($baseName -like '26-*') {
			$safeBase = Remove-InvalidFileNameChars -Name ("Mandiant - $baseName")
		}
		elseif ($baseName -like 'csa-*') {
			$safeBase = Remove-InvalidFileNameChars -Name ("Crowdstrike - $baseName")
		}
		else {
			$safeBase = Remove-InvalidFileNameChars -Name ("HSIN - $baseName")
		}

		$saveName = "$safeBase$ext"
		$savePath = Get-UniquePath -Path (Join-Path $attachOut $saveName)

		try {
			Write-Log -Level INFO -Message "Saving attachment: $origName"
			$att.SaveAsFile($savePath)

			$attachmentIndex += [PSCustomObject]@{
				Source       = 'Source'
				Title        = $baseName
				SavedAs      = [System.IO.Path]::GetFileName($savePath)
				OriginalName = $origName
				FullPath     = $savePath
				Status       = 'Saved'
			}

			Write-Log -Level INFO -Message "Saved attachment: $savePath"
		}
		catch {
			$errMsg = $_.Exception.Message

			$failedAttachments += [PSCustomObject]@{
				OriginalName = $origName
				IntendedPath = $savePath
				Error        = $errMsg
			}

			$attachmentIndex += [PSCustomObject]@{
				Source       = 'Source'
				Title        = $baseName
				SavedAs      = [System.IO.Path]::GetFileName($savePath)
				OriginalName = $origName
				FullPath     = $savePath
				Status       = 'Failed'
			}

			Write-Log -Level ERROR -Message "ATTACHMENT FAILED: Original='$origName' Path='$savePath' Error='$errMsg'"
			continue
		}
	}


    # Save attachment index
    $attachmentIndex | Export-Csv -Path $attachmentIndexCsv -NoTypeInformation -Encoding UTF8

    if ($failedUrls.Count -gt 0) {
        $failedUrls | Export-Csv -Path $failedUrlsCsv -NoTypeInformation -Encoding UTF8
        Write-Log -Level WARN -Message "Failed URL CSV written: $failedUrlsCsv"
    }

    if ($failedAttachments.Count -gt 0) {
        $failedAttachments | Export-Csv -Path $failedAttachmentsCsv -NoTypeInformation -Encoding UTF8
        Write-Log -Level WARN -Message "Failed attachment CSV written: $failedAttachmentsCsv"
    }

    # Manifest for AI workflow
    $manifest = [PSCustomObject]@{
        MessageSubject         = $subject
        MessageDate            = $receivedTime
        MsgFile                = $msg.FullName
        BrowserUsed            = $browserPath
        UrlCount               = $osintItems.Count
        UrlFailureCount        = $failedUrls.Count
        AttachmentCount        = $attachmentIndex.Count
        AttachmentFailureCount = $failedAttachments.Count
        ArticleFolder          = $articleOut
        AttachmentFolder       = $attachOut
        UrlListTxt             = $urlListTxt
        UrlListCsv             = $urlListCsv
        UrlListJson            = $urlListJson
        AttachmentIndexCsv     = $attachmentIndexCsv
        FailedUrlsCsv          = $(if ($failedUrls.Count -gt 0) { $failedUrlsCsv } else { $null })
        FailedAttachmentsCsv   = $(if ($failedAttachments.Count -gt 0) { $failedAttachmentsCsv } else { $null })
        LogFile                = $logFile
        SuggestedAiSchema      = @(
            'Source',
            'Title',
            'URL',
            'ATT&CK Tactic',
            'ATT&CK Technique ID',
            'Technique Name',
            'Procedure',
            'Evidence',
            'Confidence'
        )
    }

    $manifest | ConvertTo-Json -Depth 6 | Set-Content -Path $manifestJson -Encoding UTF8
    Write-Log -Level INFO -Message "AI manifest written: $manifestJson"

    # Console summary
    Write-Host ""
    Write-Host "================ RUN SUMMARY ================" -ForegroundColor Cyan
    Write-Host ("Subject:               {0}" -f $subject)
    Write-Host ("Browser used:          {0}" -f $browserPath)
    Write-Host ("URLs found:            {0}" -f $osintItems.Count)
    Write-Host ("URL failures:          {0}" -f $failedUrls.Count)
    Write-Host ("Attachments found:     {0}" -f $attachmentIndex.Count)
    Write-Host ("Attachment failures:   {0}" -f $failedAttachments.Count)
    Write-Host ("Output folder:         {0}" -f $rootOut)
    Write-Host "============================================="
    Write-Host ""

    if ($failedUrls.Count -gt 0) {
        Write-Host "Failed URLs:" -ForegroundColor Yellow
        $failedUrls | Format-Table -AutoSize
        Write-Host ""
    }

    if ($failedAttachments.Count -gt 0) {
        Write-Host "Failed Attachments:" -ForegroundColor Yellow
        $failedAttachments | Format-Table -AutoSize
        Write-Host ""
    }



    # NEW: scan article files for manual review
    $manualReview = @()

    if (Test-Path -LiteralPath $articleOut) {
        $articleFiles = Get-ChildItem -Path $articleOut -Filter '*.txt' -File -ErrorAction SilentlyContinue

        foreach ($file in $articleFiles) {
            $needsManual = $false
            $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue

            if ($null -eq $content) { continue }

            # Condition 1: explicit failure marker
            if ($content -like '*FAILED TO PULL*') {
                $needsManual = $true
            }
            else {
                # Condition 2: very small file + JS warning
                if ($file.Length -lt 1024 -and $content -like '*Enable JavaScript*') {
                    $needsManual = $true
                }
            }

            if ($needsManual) {
                $lines = $content -split "`r?`n"

                $titleLine = ($lines | Where-Object { $_ -like 'TITLE:*' } | Select-Object -First 1)
                $urlLine   = ($lines | Where-Object { $_ -like 'URL:*' }   | Select-Object -First 1)

                $titleVal = if ($titleLine) { $titleLine -replace '^TITLE:\s*', '' } else { '' }
                $urlVal   = if ($urlLine)   { $urlLine   -replace '^URL:\s*',   '' } else { '' }

                $manualReview += [PSCustomObject]@{
                    FileName = $file.Name
                    Url      = $urlVal
                }
            }
        }
    }

    if ($manualReview.Count -gt 0) {
        Write-Host ""
        Write-Host "You need to manually pull these:" -ForegroundColor Yellow
        $manualReview | Format-Table -AutoSize
        Write-Host ""
    
	 # NEW: prompt to open all manual-review URLs in Google Chrome GUI
        $openChoice = Read-Host "Open all these URLs in Google Chrome? (Y/N)"

        if ($openChoice -match '^[Yy]') {
            # Try to locate Google Chrome specifically
            $chromeCandidates = @(
                "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
                "$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe"
            )

            $chromePath = $chromeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

            if (-not $chromePath) {
                Write-Host "Google Chrome not found in standard locations. Cannot open URLs automatically." -ForegroundColor Red
            }
            else {
                Write-Host "Opening manual-review URLs in Google Chrome..." -ForegroundColor Cyan
                foreach ($item in $manualReview) {
                    if ([string]::IsNullOrWhiteSpace($item.Url)) { continue }
                    Start-Process -FilePath $chromePath -ArgumentList $item.Url
                }
            }
        }
    }





    Write-Log -Level INFO -Message "Run complete. URL failures: $($failedUrls.Count). Attachment failures: $($failedAttachments.Count)."
}
catch {
    $fatalMsg = $_.Exception.Message
    Write-Host "FATAL ERROR: $fatalMsg" -ForegroundColor Red

    if (Test-Path -LiteralPath $rootOut) {
        Add-Content -Path $logFile -Value ("{0} [ERROR] FATAL: {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $fatalMsg)
    }

    throw
}
finally {
    if ($attachmentsCom -ne $null) {
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($attachmentsCom)
    }

    if ($mailItem -ne $null) {
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($mailItem)
    }

    if ($outlook -ne $null) {
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($outlook)
    }

    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}


# output folder rename
	$msg_full_name = Get-ChildItem -Path $basePath -Filter *.msg | Select-Object -First 1
	if (-not $msg_full_name) {
		throw "No .msg file found in current directory."
	}
	
	if ($msg_full_name.name -match '-(.*?)-') {$msg_cut_name=$Matches[1]}
	
	$folder_update_name="output -" + $msg_cut_name
	
	rename-item .\output\ -newname $folder_update_name

Read-Host -Prompt "Press Enter to close"
