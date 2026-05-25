param(
    [string]$AuditDir = "audits/audits_uniq_id",
    [string]$AuxiliaryDoc = "auxiliary_descriptions_without_unique_naming.md",
    [string]$SummaryPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$descriptionPattern = '^\[(?<id>\d+(?:\.\d+)*)\]\[(?<os>MS|OL|N/A)\]\[(?<osv>2016|2019|2022|W11|8|N/A)\]\[(?<role>DM|DC|N/A)\]\[(?<bench>v\d+\.\d+\.\d+)\]\[(?<level>L\d+)\] (?<title>.+)$'

function Get-DescriptionValue {
    param([string]$Line)

    $value = ($Line -replace '^\s*#?\s*description\s*:\s*', '').Trim()
    if ($value.Length -ge 2) {
        $first = $value.Substring(0, 1)
        $last = $value.Substring($value.Length - 1, 1)
        if (($first -eq '"' -and $last -eq '"') -or ($first -eq "'" -and $last -eq "'")) {
            $value = $value.Substring(1, $value.Length - 2)
        }
    }

    return $value
}

function Get-AuxiliaryMap {
    param([string]$Path)

    $map = @{}
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Warning "No se encontro $Path; los auxiliares no documentados se reportaran como incidencias."
        return $map
    }

    $currentFile = $null
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^###\s+(?<file>.+\.audit)\s*$') {
            $currentFile = $Matches.file
            continue
        }

        if ($currentFile -and $line -match '^\|\s*(?<line>\d+)\s*\|\s*(?<category>[^|]+)\|') {
            $key = "$currentFile|$($Matches.line)"
            $map[$key] = $Matches.category.Trim()
        }
    }

    return $map
}

function Get-ExpectedMetadata {
    param([string]$FileName)

    $bench = $null
    $level = $null
    if ($FileName -match '_(?<bench>v\d+\.\d+\.\d+)_L(?<level>\d+)_') {
        $bench = $Matches.bench
        $level = "L$($Matches.level)"
    }

    if ($FileName -match 'Windows_Server_(?<version>2016|2019|2022)') {
        return @{
            Known = $true
            Os = "MS"
            OsVersion = $Matches.version
            Roles = @("DM", "DC", "N/A")
            Benchmark = $bench
            Level = $level
            WindowsServer = $true
        }
    }

    if ($FileName -match 'Windows_11') {
        return @{
            Known = $true
            Os = "MS"
            OsVersion = "W11"
            Roles = @("N/A")
            Benchmark = $bench
            Level = $level
            WindowsServer = $false
        }
    }

    if ($FileName -match 'Oracle_Linux_8') {
        return @{
            Known = $true
            Os = "OL"
            OsVersion = "8"
            Roles = @("N/A")
            Benchmark = $bench
            Level = $level
            WindowsServer = $false
        }
    }

    return @{
        Known = $false
        Os = $null
        OsVersion = $null
        Roles = @()
        Benchmark = $bench
        Level = $level
        WindowsServer = $false
    }
}

function Add-Issue {
    param(
        [System.Collections.Generic.List[object]]$Issues,
        [string]$File,
        [int]$Line,
        [string]$Type,
        [string]$Detail,
        [string]$Description
    )

    $Issues.Add([pscustomobject]@{
        File = $File
        Line = $Line
        Type = $Type
        Detail = $Detail
        Description = $Description
    })
}

if (-not (Test-Path -LiteralPath $AuditDir -PathType Container)) {
    throw "No existe la carpeta de audits: $AuditDir"
}

$files = Get-ChildItem -LiteralPath $AuditDir -Filter "*.audit" | Sort-Object Name
if ($files.Count -eq 0) {
    throw "No se encontraron ficheros .audit en: $AuditDir"
}

$auxMap = Get-AuxiliaryMap -Path $AuxiliaryDoc
$issues = New-Object System.Collections.Generic.List[object]
$summary = New-Object System.Collections.Generic.List[object]

foreach ($file in $files) {
    $expected = Get-ExpectedMetadata -FileName $file.Name
    $lines = Get-Content -LiteralPath $file.FullName

    $total = 0
    $named = 0
    $aux = 0
    $headers = 0

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -notmatch 'description\s*:') {
            continue
        }

        $total++
        $lineNumber = $i + 1
        $value = Get-DescriptionValue -Line $line
        $commented = ($line -match '^\s*#')
        $isHeader = ($commented -and $value -match '^This \.audit is designed against ')
        $auxKey = "$($file.Name)|$lineNumber"
        $isDocumentedAux = $auxMap.ContainsKey($auxKey)

        if ($isHeader) {
            $headers++
            continue
        }

        if ($isDocumentedAux) {
            $aux++
        }

        if ($value -notmatch $descriptionPattern) {
            if (-not $isDocumentedAux) {
                Add-Issue -Issues $issues -File $file.Name -Line $lineNumber -Type "DESCRIPTION_NAMING" -Detail "Description sin naming convention y no documentado como auxiliar" -Description $value
            }
            continue
        }

        $named++
        $controlId = $Matches.id
        $os = $Matches.os
        $osVersion = $Matches.osv
        $role = $Matches.role
        $benchmark = $Matches.bench
        $level = $Matches.level
        $title = $Matches.title

        if ($value -match '\[IG\d+\]') {
            Add-Issue -Issues $issues -File $file.Name -Line $lineNumber -Type "DESCRIPTION_IG" -Detail "IG no debe formar parte del description" -Description $value
        }

        if ($value -match '\]\[L\d+\]\s+\([Ll]\d+\)') {
            Add-Issue -Issues $issues -File $file.Name -Line $lineNumber -Type "DESCRIPTION_DUPLICATE_LEVEL" -Detail "El nivel no debe duplicarse como [Lx] (Lx)" -Description $value
        }

        if ($value -match ' {2,}') {
            Add-Issue -Issues $issues -File $file.Name -Line $lineNumber -Type "DESCRIPTION_CONSECUTIVE_SPACES" -Detail "El description contiene espacios consecutivos; cambiar un espacio cambia la identidad visible del control" -Description $value
        }

        if ($value -match 'CONTROL_|CUSTOMER|MS_ONLY|DC_ONLY|INTERNAL_VERSION') {
            Add-Issue -Issues $issues -File $file.Name -Line $lineNumber -Type "DESCRIPTION_REFERENCE_FIELD" -Detail "Campos de reference no deben aparecer en description" -Description $value
        }

        if ($title.Trim().Length -eq 0) {
            Add-Issue -Issues $issues -File $file.Name -Line $lineNumber -Type "DESCRIPTION_EMPTY_TITLE" -Detail "Titulo vacio despues de los bloques de identidad" -Description $value
        }

        if ($expected.Known) {
            if ($os -ne $expected.Os) {
                Add-Issue -Issues $issues -File $file.Name -Line $lineNumber -Type "SEMANTIC_OS" -Detail "OS esperado: $($expected.Os); encontrado: $os" -Description $value
            }
            if ($osVersion -ne $expected.OsVersion) {
                Add-Issue -Issues $issues -File $file.Name -Line $lineNumber -Type "SEMANTIC_OS_VERSION" -Detail "OS_VERSION esperado: $($expected.OsVersion); encontrado: $osVersion" -Description $value
            }
            if ($expected.Roles -notcontains $role) {
                Add-Issue -Issues $issues -File $file.Name -Line $lineNumber -Type "SEMANTIC_ROLE" -Detail "ROLE no esperado para este audit: $role" -Description $value
            }
        }

        if ($expected.Benchmark -and $benchmark -ne $expected.Benchmark) {
            Add-Issue -Issues $issues -File $file.Name -Line $lineNumber -Type "SEMANTIC_BENCHMARK" -Detail "Benchmark esperado: $($expected.Benchmark); encontrado: $benchmark" -Description $value
        }

        if ($expected.Level -and $level -ne $expected.Level) {
            Add-Issue -Issues $issues -File $file.Name -Line $lineNumber -Type "SEMANTIC_LEVEL" -Detail "Level esperado: $($expected.Level); encontrado: $level" -Description $value
        }

        $start = $i
        while ($start -gt 0 -and $lines[$start] -notmatch '^\s*#?\s*<(custom_item|report)\b') {
            $start--
        }

        $end = $i
        while ($end -lt ($lines.Count - 1) -and $lines[$end] -notmatch '^\s*#?\s*</(custom_item|report)>') {
            $end++
        }

        $block = $lines[$start..$end] -join "`n"
        $requiredReferenceFields = @("CONTROL_IG|", "CONTROL_INTERNAL_VERSION|", "CONTROL_CUSTOMER|", "CONTROL_CIS|")
        if ($expected.WindowsServer) {
            $requiredReferenceFields += @("CONTROL_MS_ONLY|", "CONTROL_DC_ONLY|")
        }

        $missing = @()
        foreach ($field in $requiredReferenceFields) {
            if ($block -notmatch [regex]::Escape($field)) {
                $missing += $field
            }
        }

        if ($missing.Count -gt 0) {
            Add-Issue -Issues $issues -File $file.Name -Line $lineNumber -Type "REFERENCE_MISSING_FIELD" -Detail ("Faltan: " + ($missing -join ", ")) -Description $value
        }

        if ((-not $expected.WindowsServer) -and ($block -match 'CONTROL_MS_ONLY\||CONTROL_DC_ONLY\|')) {
            Add-Issue -Issues $issues -File $file.Name -Line $lineNumber -Type "REFERENCE_WINDOWS_ONLY_FIELD" -Detail "Windows 11 y Linux no deben tener CONTROL_MS_ONLY ni CONTROL_DC_ONLY" -Description $value
        }

        [void]$controlId
    }

    $summary.Add([pscustomobject]@{
        File = $file.Name
        TotalDescriptions = $total
        NamingOk = $named
        AuxiliaryDocumented = $aux
        HeaderComments = $headers
    })
}

if (-not [string]::IsNullOrWhiteSpace($SummaryPath)) {
    if (-not (Test-Path -LiteralPath $SummaryPath -PathType Leaf)) {
        throw "No existe el summary indicado: $SummaryPath"
    }

    $summaryRows = Import-Csv -LiteralPath $SummaryPath
    $summaryName = Split-Path -Leaf $SummaryPath
    $summaryTotal = 0
    $summaryNamed = 0

    if ($summaryRows.Count -gt 0 -and ($summaryRows[0].PSObject.Properties.Name -notcontains "Plugin Name")) {
        Add-Issue -Issues $issues -File $summaryName -Line 1 -Type "SUMMARY_MISSING_PLUGIN_NAME" -Detail "El summary no contiene la columna Plugin Name" -Description ""
    }
    else {
        for ($i = 0; $i -lt $summaryRows.Count; $i++) {
            $row = $summaryRows[$i]
            $lineNumber = $i + 2
            $value = $row.'Plugin Name'
            $summaryTotal++

            if ([string]::IsNullOrWhiteSpace($value)) {
                Add-Issue -Issues $issues -File $summaryName -Line $lineNumber -Type "SUMMARY_EMPTY_PLUGIN_NAME" -Detail "Plugin Name vacio en summary" -Description $value
                continue
            }

            if ($value -notmatch $descriptionPattern) {
                Add-Issue -Issues $issues -File $summaryName -Line $lineNumber -Type "SUMMARY_DESCRIPTION_NAMING" -Detail "Plugin Name no sigue la naming convention esperada" -Description $value
                continue
            }

            $summaryNamed++

            if ($value -match '\[IG\d+\]') {
                Add-Issue -Issues $issues -File $summaryName -Line $lineNumber -Type "SUMMARY_DESCRIPTION_IG" -Detail "IG no debe formar parte del description" -Description $value
            }

            if ($value -match '\]\[L\d+\]\s+\([Ll]\d+\)') {
                Add-Issue -Issues $issues -File $summaryName -Line $lineNumber -Type "SUMMARY_DESCRIPTION_DUPLICATE_LEVEL" -Detail "El nivel no debe duplicarse como [Lx] (Lx)" -Description $value
            }

            if ($value -match ' {2,}') {
                Add-Issue -Issues $issues -File $summaryName -Line $lineNumber -Type "SUMMARY_DESCRIPTION_CONSECUTIVE_SPACES" -Detail "El Plugin Name contiene espacios consecutivos; cambiar un espacio cambia la identidad visible del control" -Description $value
            }

            if ($value -match 'CONTROL_|CUSTOMER|MS_ONLY|DC_ONLY|INTERNAL_VERSION') {
                Add-Issue -Issues $issues -File $summaryName -Line $lineNumber -Type "SUMMARY_DESCRIPTION_REFERENCE_FIELD" -Detail "Campos de reference no deben aparecer en Plugin Name" -Description $value
            }
        }
    }

    $summary.Add([pscustomobject]@{
        File = $summaryName
        TotalDescriptions = $summaryTotal
        NamingOk = $summaryNamed
        AuxiliaryDocumented = 0
        HeaderComments = 0
    })
}

Write-Host "Resumen:"
$summary | Format-Table -AutoSize

if ($issues.Count -gt 0) {
    Write-Host ""
    Write-Host "Incidencias encontradas: $($issues.Count)"
    $issues | Sort-Object File, Line | Format-List
    exit 1
}

Write-Host ""
Write-Host "OK: validacion completada sin incidencias."
exit 0
