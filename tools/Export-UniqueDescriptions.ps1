param(
    [string]$AuditDir = "audits/audits_uniq_id",
    [string]$OutputPath = "uniqueID_descriptions_by_audit.md"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

if (-not (Test-Path -LiteralPath $AuditDir -PathType Container)) {
    throw "No existe la carpeta de audits: $AuditDir"
}

$files = Get-ChildItem -LiteralPath $AuditDir -Filter "*.audit" | Sort-Object Name
if ($files.Count -eq 0) {
    throw "No se encontraron ficheros .audit en: $AuditDir"
}

$out = New-Object System.Collections.Generic.List[string]
$out.Add("# Descriptions por audit uniqueID")
$out.Add("")
$out.Add("Inventario generado desde ``$AuditDir/*.audit``. Incluye todos los campos ``description``, tambien cabeceras comentadas y checks auxiliares.")
$out.Add("")

$total = 0
foreach ($file in $files) {
    $out.Add("## $($file.Name)")
    $out.Add("")
    $out.Add("| Linea | Comentado | Description |")
    $out.Add("| ---: | --- | --- |")

    $lines = Get-Content -LiteralPath $file.FullName
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -notmatch 'description\s*:') {
            continue
        }

        $commented = if ($line -match '^\s*#') { "si" } else { "no" }
        $value = Get-DescriptionValue -Line $line
        $value = $value -replace '\|', '\|'
        $out.Add("| $($i + 1) | $commented | $value |")
        $total++
    }

    $out.Add("")
}

$resolvedOutput = Join-Path (Get-Location) $OutputPath
[System.IO.File]::WriteAllLines($resolvedOutput, $out, [System.Text.UTF8Encoding]::new($false))

Write-Host "OK: exportados $total description a $resolvedOutput"
