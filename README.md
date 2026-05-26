# Holcim - Compliance Audits

Repositorio de trabajo para compliance CIS/Tenable/Nessus basado en ficheros `.audit`.

La linea de trabajo actual queda centrada exclusivamente en audits, reglas de naming, versionado y documentacion operativa Tenable/Nessus.

## Estructura principal

- `audits/`: ficheros `.audit` de Tenable/Nessus.
- `audits/v0/`: referencias historicas/base.
- `audits/v1/`: versiones productivas cuando una familia no tiene version superior.
- `audits/v2/`: versiones disponibles de audits; actualmente contiene las versiones productivas de Windows Server.
- `audits/audits_uniq_id/`: audits derivados con identificadores visibles enriquecidos.
- `quick_test/`: audits ligeros para probar aplicabilidad o controles concretos rapidamente con menos checks.
- `tools/validator.py`: validador canonico Python para decidir si un `.audit` esta listo para uso.
- `tools/validator_config.json`: valores esperados por el validador para naming, familias y campos `reference`.
- `tools/GUIA_VALIDATOR.md`: uso del validator y mantenimiento de `validator_config.json`.
- `audit_rules.md`: reglas vigentes para crear, nombrar, enriquecer, correlacionar y modificar `.audit`.
- `DOCUMENTACION_PROYECTO_COMPLIANCE.md`: estructura operativa Tenable.sc y audits.

## Referencias obligatorias

Antes de modificar sintaxis, estructura o checks en un `.audit`, revisar:

```text
audits/NessusComplianceChecksReference.pdf
```

Antes de crear o modificar reglas de identificacion, naming, `reference` o correlacion de controles, revisar:

```text
audit_rules.md
```

## Versiones productivas actuales

| Familia | Version productiva | Fichero productivo |
| --- | --- | --- |
| Windows Server 2016 | `v2` | `audits/v2/CIS_Microsoft_Windows_Server_2016_v4.0.0_L1_v2.audit` |
| Windows Server 2019 | `v2` | `audits/v2/CIS_Microsoft_Windows_Server_2019_v4.0.0_L1_v2.audit` |
| Windows Server 2022 | `v2` | `audits/v2/CIS_Microsoft_Windows_Server_2022_v5.0.0_L1_v2.audit` |
| Windows 11 Stand-alone | `v1` | `audits/v1/CIS_Microsoft_Windows_11_Stand-alone_v4.0.0_L1_v1.audit` |
| Oracle Linux 8 | `v1` | `audits/v1/CIS_Oracle_Linux_8_v4.0.0_L1_v1.audit` |

La version productiva se determina por cada `.audit` o familia concreta. Que exista `audits/v2` o que Windows Server use `v2` no implica que Windows 11 u Oracle Linux tengan que migrar a `v2`.

## Audits con IDs unicos

Los audits derivados con naming enriquecido viven en:

```text
audits/audits_uniq_id/
```

La convencion vigente de `description` y `reference` esta definida exclusivamente en `audit_rules.md`.

El filtro definitivo antes de usar o publicar audits enriquecidos es:

```text
python tools/validator.py
```

El parser del validator identifica bloques Tenable y conserva campos multilínea como `info`, `solution`, `cmd` o `expect` como un unico valor logico.

Si se incorpora una familia, OS, version o rol nuevo al proyecto, primero debe actualizarse:

```text
tools/validator_config.json
```

## Reglas de trabajo

- No modificar `audits/vX` productivos salvo instruccion explicita.
- Para pruebas o derivados, trabajar en `audits/audits_uniq_id/` u otra carpeta indicada por el usuario.
- Usar `quick_test/` solo para pruebas rapidas con audits reducidos; no son sustitutos de produccion.
- Preservar la logica Windows Server unificada para `DM` y `DC`.
- No aplicar logica Windows Server a Linux.
- Mantener `audit_rules.md` como fuente de verdad para reglas de naming y referencia.
- No reintroducir artefactos de lineas descartadas.

## Fuentes activas

Las reglas vigentes estan identificadas asi:

- `audit_rules.md`: fuente de verdad para `.audit`.
- `AGENTS.md`: instrucciones de trabajo para Codex.
- `DOCUMENTACION_PROYECTO_COMPLIANCE.md`: estructura Tenable.sc y relacion de scans/targets/audits.
- `audits/v1/README.txt` y `audits/v2/README.txt`: notas historicas de version dentro de cada carpeta de audits.

## Publicacion

Para preparar y publicar este proyecto en GitHub, usar:

```text
GITHUB_SETUP.md
```
