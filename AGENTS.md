# Instrucciones para Codex

## Contexto del proyecto

Este repositorio contiene trabajo de compliance para Tenable/Nessus usando ficheros `.audit`.

La linea anterior ajena al mantenimiento de audits queda descartada. No se debe restaurar, recrear ni documentar esa linea salvo peticion explicita futura del usuario.

El documento de referencia principal para sintaxis Tenable/Nessus es:

```text
audits/NessusComplianceChecksReference.pdf
```

Antes de modificar checks, sintaxis o estructura de ficheros `.audit`, revisar ese PDF y aplicar sus reglas.

Las reglas operativas propias del proyecto para crear, nombrar, enriquecer, correlacionar y modificar ficheros `.audit` estan centralizadas en:

```text
audit_rules.md
```

Cualquier regla nueva o cambio de criterio sobre naming convention, campos `reference`, identificadores, correlacion, controles cliente/CIS o modificacion de definiciones de audits debe documentarse y mantenerse en `audit_rules.md`.

## Objetivo funcional

El objetivo actual del repositorio es mantener ficheros `.audit` CIS/Tenable claros, versionados y trazables.

En Windows Server, los ficheros productivos estan unificados para que un mismo `.audit` pueda gestionar servidores miembro y domain controllers cuando la logica puede convivir en el mismo audit.

En Linux no se aplica la logica de unificacion Windows salvo instruccion explicita.

## Versiones de produccion

Los ficheros de produccion estan dentro de `audits/vX`, donde `X` es la numeracion de version.

La version de produccion no se asume por la carpeta global mas alta. Se determina para cada `.audit` o familia concreta como la version mas alta disponible de ese mismo audit/familia dentro de `audits/vX`.

Reglas:

- Si Windows Server existe en `audits/v2`, la version productiva de Windows Server es `v2`.
- Si Linux solo existe en `audits/v1`, la version productiva de Linux sigue siendo `v1`.
- Que exista una `v2` para Windows no implica que Linux tenga que migrar a `v2`.
- Que exista una carpeta `audits/v2` no significa que todos los `.audit` tengan una version productiva `v2`.
- Si un audit/familia no esta presente en la carpeta de version mas alta, su version de produccion es la inmediatamente anterior disponible para ese mismo audit/familia.

Inventario actual conocido:

| Familia | Version productiva | Fichero productivo |
| --- | --- | --- |
| Windows Server 2016 | `v2` | `audits/v2/CIS_Microsoft_Windows_Server_2016_v4.0.0_L1_v2.audit` |
| Windows Server 2019 | `v2` | `audits/v2/CIS_Microsoft_Windows_Server_2019_v4.0.0_L1_v2.audit` |
| Windows Server 2022 | `v2` | `audits/v2/CIS_Microsoft_Windows_Server_2022_v5.0.0_L1_v2.audit` |
| Windows 11 Stand-alone | `v1` | `audits/v1/CIS_Microsoft_Windows_11_Stand-alone_v4.0.0_L1_v1.audit` |
| Oracle Linux 8 | `v1` | `audits/v1/CIS_Oracle_Linux_8_v4.0.0_L1_v1.audit` |

## Forma de actuar

- Responder en espanol, con tono preciso y conciso.
- No asumir que todos los sistemas comparten la misma version de produccion.
- Antes de modificar artefactos de compliance, identificar el tipo de trabajo: `.audit`, documentacion, script auxiliar u otro.
- Si las instrucciones no son claras para el tipo de artefacto afectado, pedir aclaracion antes de actuar.
- Evitar refactors amplios si el cambio solicitado afecta a checks concretos.
- Preservar nombres, estructura y convenciones existentes de los ficheros.
- Documentar cualquier cambio funcional relevante en la respuesta final.
- No introducir de nuevo artefactos de la linea descartada.

## Directivas para `.audit`

Antes de modificar un `.audit`:

- Revisar `audit_rules.md`; es la referencia interna para como se crean, nombran, enriquecen y correlacionan los audits del proyecto.
- Identificar la familia afectada, la version de produccion vigente y si aplica a Windows Server, Windows 11 o Linux.
- Comparar contra la version de produccion correspondiente.
- Revisar la sintaxis esperada en `audits/NessusComplianceChecksReference.pdf`.
- Mantener compatibilidad con Tenable/Nessus.
- Mantener el criterio de unificacion Windows para servidores miembro y domain controllers cuando aplique.
- No aplicar la logica de unificacion Windows a Linux salvo instruccion explicita.
- Validar que la logica no rompe escenarios de servidores miembro ni domain controllers cuando el fichero sea Windows Server unificado.
- Para Linux, limitar los cambios a la necesidad concreta del benchmark o check.
- Si durante el trabajo se define una regla nueva sobre creacion, naming, `reference`, correlacion o modificacion de controles, actualizar `audit_rules.md` en el mismo cambio.

## Naming y referencias

La convencion vigente de `description`, los campos enriquecidos de `reference`, las reglas de controles cliente/CIS y la semantica de roles viven en `audit_rules.md`. No duplicar esas reglas en otros documentos; actualizar `audit_rules.md` cuando cambien.

## Quick tests

La carpeta `quick_test/` se usa para ficheros `.audit` ligeros destinados a probar aplicabilidad, conectividad o controles concretos rapidamente con menos checks que un benchmark completo. No sustituyen a los audits productivos ni a los audits unique.

## Criterios de modificacion

Al modificar cualquier artefacto:

- Limitar el cambio al objetivo solicitado.
- Preservar compatibilidad con el consumidor del artefacto: Tenable/Nessus para `.audit`.
- Evitar cambios de formato masivos salvo que sean necesarios para cumplir la regla acordada.
- No tocar versiones productivas si el usuario pide trabajar sobre copias, pruebas o `audits/audits_uniq_id`.
- No borrar ni revertir cambios existentes del usuario salvo peticion explicita.

## Ambitos que conviene aclarar si faltan

Pedir aclaracion si falta informacion sobre:

- familia afectada;
- version de benchmark;
- si el cambio aplica a produccion o a `audits/audits_uniq_id`;
- si el cambio aplica a Windows Server `DM`, `DC`, ambos o `N/A`;
- si un control nuevo es CIS, cliente o adaptacion de CIS;
- si una modificacion requiere incrementar `CONTROL_INTERNAL_VERSION`.
