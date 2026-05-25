# Guia de herramientas

Esta guia explica las herramientas auxiliares del repositorio.

## 1. Requisitos

- PowerShell.

Las reglas de naming, `description`, `reference`, auxiliares y controles reportables viven en:

```text
audit_rules.md
```

Esta guia no sustituye esas reglas.

## 2. Herramientas disponibles

### Validar identidad de controles `.audit`

Script:

```text
tools/validate_audit_identity.py
```

Uso normal desde la raiz del repo:

```powershell
python .\tools\validate_audit_identity.py
```

Con el Python empaquetado de Codex:

```powershell
C:\Users\Alberto\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe .\tools\validate_audit_identity.py
```

Que valida:

- Solo exige naming/reference a controles reportables o terminales.
- Ignora checks auxiliares internos dentro de `<condition>`.
- Asigna `description` y `reference` al bloque Tenable reportable mas interno abierto, para no mezclar contenedores con ramas anidadas.
- Valida `description` como identidad exacta del control.
- Exige `description` reportable delimitado con comillas dobles exteriores.
- Exige exactamente un espacio entre `[LEVEL]` y el titulo.
- Detecta espacios consecutivos en `description`.
- Detecta comillas escapadas con backslash, como `\'`, porque Tenable puede exponerlas en el nombre.
- Detecta `description` delimitados con comilla simple que contienen apostrofes.
- Valida campos enriquecidos de `reference`.

Validar tambien summaries CSV de Tenable:

```powershell
python .\tools\validate_audit_identity.py --summary "C:\ruta\summary.csv"
```

Generar reporte JSON:

```powershell
python .\tools\validate_audit_identity.py --json-report "reports\audit_identity_report.json"
```

### Validar audits uniqueID

Script:

```text
tools/Validate-UniqueAudits.ps1
```

Uso normal desde la raiz del repo:

```powershell
.\tools\Validate-UniqueAudits.ps1
```

Si Windows bloquea la ejecucion de scripts:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\tools\Validate-UniqueAudits.ps1"
```

Que valida:

- Naming convention de `description` en controles reportables.
- Ausencia de `[IGx]` en `description`.
- Ausencia de duplicados de nivel como `[L1] (L1)` o `[L2] (L2)`.
- Ausencia de espacios consecutivos en `description`.
- Coherencia de OS, version, rol, benchmark y level segun el fichero.
- Campos minimos de `reference` en controles con naming:
  - `CONTROL_IG`
  - `CONTROL_INTERNAL_VERSION`
  - `CONTROL_CUSTOMER`
  - `CONTROL_CIS`
- Campos adicionales Windows Server:
  - `CONTROL_MS_ONLY`
  - `CONTROL_DC_ONLY`
- Ausencia de `CONTROL_MS_ONLY` y `CONTROL_DC_ONLY` en Windows 11 y Linux.
- Auxiliares documentados en `auxiliary_descriptions_without_unique_naming.md`.

El script termina con codigo `0` si no encuentra incidencias y `1` si encuentra problemas.

Uso con rutas explicitas:

```powershell
.\tools\Validate-UniqueAudits.ps1 `
  -AuditDir "audits\audits_uniq_id" `
  -AuxiliaryDoc "auxiliary_descriptions_without_unique_naming.md"
```

Validar tambien un summary CSV de scan:

```powershell
.\tools\Validate-UniqueAudits.ps1 `
  -SummaryPath "C:\ruta\summary.csv"
```

### Exportar descriptions por audit

Script:

```text
tools/Export-UniqueDescriptions.ps1
```

Uso normal:

```powershell
.\tools\Export-UniqueDescriptions.ps1
```

Si Windows bloquea la ejecucion de scripts:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\tools\Export-UniqueDescriptions.ps1"
```

Genera:

```text
uniqueID_descriptions_by_audit.md
```

Ese fichero contiene todos los `description` agrupados por `.audit`, con numero de linea y si la linea esta comentada.

Uso con salida explicita:

```powershell
.\tools\Export-UniqueDescriptions.ps1 `
  -AuditDir "audits\audits_uniq_id" `
  -OutputPath "uniqueID_descriptions_by_audit.md"
```

## 3. Flujo recomendado de revision

Desde la raiz del repo:

```powershell
.\tools\Validate-UniqueAudits.ps1
.\tools\Export-UniqueDescriptions.ps1
```

Alternativa si la execution policy de Windows bloquea `.ps1`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\tools\Validate-UniqueAudits.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\tools\Export-UniqueDescriptions.ps1"
```

Si la validacion falla, revisar las incidencias antes de usar o entregar los audits.
