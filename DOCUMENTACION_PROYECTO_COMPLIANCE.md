# Documentacion de estructura del proyecto CIS Compliance

Fecha de preparacion: 2026-05-25
Estado: linea actual centrada en Tenable.sc y ficheros `.audit`

## 1. Proposito

Este documento describe la estructura funcional del proyecto para ejecutar controles CIS de compliance mediante Tenable.sc y ficheros `.audit`.

Las reglas detalladas de creacion, naming, campos `reference`, controles cliente/CIS, version interna y validacion de `.audit` viven en:

```text
audit_rules.md
```

Este documento no duplica esas reglas; solo identifica como encajan los audits dentro de la estructura operativa.

## 2. Alcance

La linea actual cubre:

- Tenable.sc como plataforma de scans de compliance.
- Repositorios de compliance por zona y tipo de equipo.
- Scans por zona, tecnologia, sistema operativo, dominio o segmento.
- Credenciales asociadas a dominios o segmentos.
- Targets basados en assets estaticos o muestras controladas.
- Audits CIS/Tenable usados por los scans.
- Procedimientos basicos de mantenimiento y validacion de Tenable.sc y audits.

## 3. Principios de diseno

- No mantener un unico scan global para todo el parque.
- Separar scans por zona, dominio, sistema operativo y credencial cuando sea necesario.
- Separar repositorios de compliance de repositorios de vulnerabilidades.
- Usar targets precisos para scans de compliance de servidores.
- Usar muestras workstation controladas cuando la poblacion sea dinamica.
- Mantener los audits versionados por familia tecnologica.
- Preservar la logica Windows Server unificada para servidores miembro y domain controllers.
- No aplicar logica Windows Server a Linux salvo decision explicita.

## 4. Zonas

| Zona | Literal recomendado | Uso |
| --- | --- | --- |
| EMEA | `emea` | Repositorios, scans y targets de EMEA. |
| APAC | `apac` | Repositorios, scans y targets de APAC. |
| AMERICAS | `americas` | Repositorios, scans y targets de Americas. |

La nomenclatura abreviada debe mantenerse consistente en repositorios, scans, targets y documentacion.

## 5. Repositorios de compliance

La nomenclatura definida es:

```text
<zona>_compliance_server
<zona>_compliance_ws
```

Reglas:

- Los servidores Windows y Linux van a repositorios `<zona>_compliance_server`.
- Las workstations van a repositorios `<zona>_compliance_ws`.
- No mezclar servidores y workstations dentro de un mismo repositorio funcional.
- No usar repositorios de otra zona aunque el audit sea el mismo.

Ejemplos:

```text
emea_compliance_server
apac_compliance_server
americas_compliance_server
emea_compliance_ws
apac_compliance_ws
americas_compliance_ws
```

## 6. Separacion de scans

Los criterios de separacion son:

- zona;
- tecnologia;
- tipo de equipo;
- sistema operativo;
- version de sistema operativo;
- dominio;
- segmento de credencial;
- audit aplicable;
- repositorio de destino.

## 7. Scans Windows Server

Para Windows Server, cada zona y dominio debe tener scans separados por version de sistema operativo:

- Windows Server 2016;
- Windows Server 2019;
- Windows Server 2022.

Cada scan debe usar:

- target correspondiente;
- audit CIS de la version de Windows Server;
- credencial del dominio evaluado;
- repositorio de compliance server de la zona.

Ejemplo para EMEA y dominio `ea`:

| Zona | Dominio | Sistema operativo | Target | Repositorio |
| --- | --- | --- | --- | --- |
| EMEA | `ea` | Windows Server 2016 | `cis_compliance_emea_server_2016_ea` | `emea_compliance_server` |
| EMEA | `ea` | Windows Server 2019 | `cis_compliance_emea_server_2019_ea` | `emea_compliance_server` |
| EMEA | `ea` | Windows Server 2022 | `cis_compliance_emea_server_2022_ea` | `emea_compliance_server` |

## 8. Scans Linux Server

Para Linux, la separacion depende de la zona y de las credenciales disponibles.

Ejemplo APAC:

```text
cis_compliance_apac_oracle_8
```

Ejemplo EMEA con credenciales segmentadas:

```text
cis_compliance_emea_oracle_8_<segmento_credencial_linux>
```

Reglas:

- No aplicar la logica `DM/DC` de Windows a Linux.
- Separar targets cuando cambie la credencial necesaria.
- Mantener el repositorio `<zona>_compliance_server`.
- Usar el audit Linux correspondiente a la distribucion y version evaluada.

## 9. Scans Workstation

Para workstations se pueden usar muestras DNS controladas por zona cuando la poblacion sea dinamica.

Reglas:

- Usar el repositorio `<zona>_compliance_ws`.
- No mezclar muestras workstation con targets de servidores.
- Mantener la separacion por zona.
- Usar el audit workstation correspondiente.

Muestras previstas:

| Zona | Muestras WS |
| --- | --- |
| EMEA | `EMEA_WS_EITS`, `EMEA_WS_GBR`, `EMEA_WS_MEA`, `EMEA_WS_GITSC` |
| AMERICAS | `americas_ws_laser` |
| APAC | `apac_ws_hanz`, `apac_ws_heabs`, `apac_ws_hssa` |

## 10. Targets

La nomenclatura general para targets de compliance es:

```text
cis_compliance_<zona>_<tecnologia>_<dominio_o_segmento>
```

Para Windows Server:

```text
cis_compliance_<zona>_server_<version>_<dominio>
```

Para Oracle Linux 8:

```text
cis_compliance_<zona>_oracle_8
cis_compliance_<zona>_oracle_8_<segmento_credencial>
```

Ejemplos:

| Target | Combinacion |
| --- | --- |
| `cis_compliance_emea_server_2016_ea` | Windows Server 2016 + dominio `ea` |
| `cis_compliance_emea_server_2019_ea` | Windows Server 2019 + dominio `ea` |
| `cis_compliance_emea_server_2022_ea` | Windows Server 2022 + dominio `ea` |
| `cis_compliance_apac_oracle_8` | Oracle Linux 8 APAC |

## 11. Credenciales

Reglas:

- No reutilizar credenciales de un dominio para otro sin validacion explicita.
- No documentar secretos.
- Documentar solo identificador funcional, propietario y alcance.
- Separar credenciales Windows y Linux.
- Separar credenciales Linux cuando exista segmentacion por grupos de equipos.

Matriz pendiente:

| Zona | Tecnologia | Dominio o segmento | Identificador funcional | Scans asociados | Responsable | Estado |
| --- | --- | --- | --- | --- | --- | --- |
| EMEA | Windows Server | `ea` | Pendiente | Pendiente | Pendiente | Pendiente |
| APAC | Windows Server | Pendiente | Pendiente | Pendiente | Pendiente | Pendiente |
| AMERICAS | Windows Server | Pendiente | Pendiente | Pendiente | Pendiente | Pendiente |
| EMEA | Oracle Linux 8 | Pendiente | Pendiente | Pendiente | Pendiente | Pendiente |

## 12. Inventario productivo de audits

La version productiva se determina por familia, no por carpeta global.

| Familia | Version productiva | Fichero productivo | Observacion |
| --- | --- | --- | --- |
| Windows Server 2016 | `v2` | `audits/v2/CIS_Microsoft_Windows_Server_2016_v4.0.0_L1_v2.audit` | Unificado `DM/DC`. |
| Windows Server 2019 | `v2` | `audits/v2/CIS_Microsoft_Windows_Server_2019_v4.0.0_L1_v2.audit` | Unificado `DM/DC`. |
| Windows Server 2022 | `v2` | `audits/v2/CIS_Microsoft_Windows_Server_2022_v5.0.0_L1_v2.audit` | Unificado `DM/DC`. |
| Windows 11 Stand-alone | `v1` | `audits/v1/CIS_Microsoft_Windows_11_Stand-alone_v4.0.0_L1_v1.audit` | Sin rol servidor. |
| Oracle Linux 8 | `v1` | `audits/v1/CIS_Oracle_Linux_8_v4.0.0_L1_v1.audit` | Sin unificacion Windows. |

Las reglas completas de mantenimiento de audits estan en `audit_rules.md`.

## 13. Procedimientos minimos

Antes de crear o modificar un scan:

1. Identificar zona.
2. Identificar tecnologia y sistema operativo.
3. Identificar dominio o segmento.
4. Identificar target.
5. Identificar audit productivo.
6. Identificar credencial.
7. Seleccionar repositorio correcto.
8. Ejecutar validacion controlada.
9. Revisar errores de autenticacion y cobertura de hosts.

Antes de modificar un audit:

1. Revisar `audit_rules.md`.
2. Revisar `audits/NessusComplianceChecksReference.pdf`.
3. Comparar contra la version productiva de la familia.
4. Aplicar el cambio minimo necesario.
5. Validar compatibilidad Tenable/Nessus.
6. Documentar el cambio funcional.

## 14. Matriz de audits por scan

| Tecnologia | Sistema operativo | Audit productivo | Scans que lo usan | Observaciones |
| --- | --- | --- | --- | --- |
| Windows Server | 2016 | `audits/v2/CIS_Microsoft_Windows_Server_2016_v4.0.0_L1_v2.audit` | Pendiente | Unificado `DM/DC`. |
| Windows Server | 2019 | `audits/v2/CIS_Microsoft_Windows_Server_2019_v4.0.0_L1_v2.audit` | Pendiente | Unificado `DM/DC`. |
| Windows Server | 2022 | `audits/v2/CIS_Microsoft_Windows_Server_2022_v5.0.0_L1_v2.audit` | Pendiente | Unificado `DM/DC`. |
| Windows 11 | Stand-alone | `audits/v1/CIS_Microsoft_Windows_11_Stand-alone_v4.0.0_L1_v1.audit` | Pendiente | Sin rol servidor. |
| Oracle Linux | 8 | `audits/v1/CIS_Oracle_Linux_8_v4.0.0_L1_v1.audit` | Pendiente | Sin unificacion Windows. |

## 15. Glosario

| Termino | Definicion |
| --- | --- |
| Audit | Fichero `.audit` de Tenable/Nessus que define controles de compliance. |
| Compliance repository | Repositorio Tenable.sc dedicado a resultados de compliance. |
| Credential | Credencial usada por Tenable.sc para autenticarse contra los equipos evaluados. |
| Domain controller | Servidor Windows que actua como controlador de dominio. |
| Scan | Configuracion Tenable.sc que ejecuta un audit contra un target. |
| Target | Conjunto de equipos contra el que se ejecuta un scan. |
