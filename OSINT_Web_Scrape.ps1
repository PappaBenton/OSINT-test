#requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Remove-InvalidFileNameChars {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
    $re = "[{0}]" -f [Regex]::Escape($invalidChars)
    ($Name -replace $re, '_').Trim()
}

function Get-ArticleText {
    param(
        [Parameter(Mandatory)]
        [string]$Url
    )

    try {
        $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 30
        if ($resp.Content) {
            return $resp.Content
        }
        return ""
    }
    catch {
        return "FAILED TO RETRIEVE URL: $Url`r`nERROR: $($_.Exception.Message)"
    }
}

# Input .msg
$msgFile = Get-ChildItem -Path . -Filter *.msg | Select-Object -First 1 -ExpandProperty FullName
if (-not $msgFile) {
    throw "No .msg file found in current directory."
}

# Output folders
$rootOut       = Join-Path $PWD "output"
$articleOut    = Join-Path $rootOut "articles"
$attachOut     = Join-Path $rootOut "attachments"
New-Item -ItemType Directory -Force -Path $rootOut, $articleOut, $attachOut | Out-Null

# Outlook COM
$outlook  = New-Object -ComObject Outlook.Application
$mailItem = $outlook.CreateItemFromTemplate($msgFile)

$plainBody = $mailItem.Body
$htmlBody  = $mailItem.HTMLBody

# Trim at FYSA marker if present
$marker = '(U) FYSA:'
$idx = $plainBody.IndexOf($marker)
if ($idx -ge 0) {
    $plainBody = $plainBody.Substring(0, $idx + $marker.Length)
}

# Extract title/url pairs from plain text feed lines like:
# * Some Article Title <https://example.com/article>
$pattern = '^\s*\*\s+(?<Title>.+?)\s*<(?<Url>https?://[^>]+)>'
$matches = [regex]::Matches($plainBody, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline)

$osintItems = foreach ($m in $matches) {
    $title = $m.Groups['Title'].Value.Trim()
    $url   = $m.Groups['Url'].Value.Trim()

    [PSCustomObject]@{
        Source = 'OSINT'
        Title  = $title
        Url    = $url
        Label  = "OSINT - $title - $url"
    }
}

# Save URL list to array and file
$OSINT_title_link = $osintItems.Label
$OSINT_title_link | Set-Content -Path (Join-Path $rootOut 'osint-title-link.txt') -Encoding UTF8

# Pull article content into one file per URL
foreach ($item in $osintItems) {
    $safeTitle = Remove-InvalidFileNameChars $item.Title
    $fileName  = "OSINT - $safeTitle.txt"
    $filePath  = Join-Path $articleOut $fileName

    $content = Get-ArticleText -Url $item.Url
    @(
        "TITLE: $($item.Title)"
        "URL: $($item.Url)"
        ""
        $content
    ) | Set-Content -Path $filePath -Encoding UTF8
}

# Extract attachments
$attachmentIndex = @()
foreach ($att in $mailItem.Attachments) {
    $origName = $att.FileName
    $baseName = [IO.Path]::GetFileNameWithoutExtension($origName)
    $ext      = [IO.Path]::GetExtension($origName)

    $safeBase = Remove-InvalidFileNameChars $baseName
    $saveName = "Source - $safeBase$ext"
    $savePath = Join-Path $attachOut $saveName

    $att.SaveAsFile($savePath)

    $attachmentIndex += [PSCustomObject]@{
        Source         = 'Source'
        Title          = $baseName
        SavedAs        = $saveName
        OriginalName   = $origName
        FullPath       = $savePath
    }
}

$attachmentIndex | Export-Csv -Path (Join-Path $rootOut 'attachments-index.csv') -NoTypeInformation -Encoding UTF8

# Optional: create AI upload manifest
$aiManifest = [PSCustomObject]@{
    MessageSubject   = $mailItem.Subject
    MessageDate      = $mailItem.ReceivedTime
    UrlCount         = $osintItems.Count
    AttachmentCount  = $attachmentIndex.Count
    ArticleFolder    = $articleOut
    AttachmentFolder = $attachOut
}

$aiManifest | ConvertTo-Json -Depth 3 | Set-Content -Path (Join-Path $rootOut 'ai-manifest.json') -Encoding UTF8
