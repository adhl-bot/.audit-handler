# Guia Validator

Esta guia explica como usar y mantener el validador canonico del proyecto.

El objetivo de `validator.py` es actuar como filtro final antes de considerar un `.audit` listo para uso. El script valida estructura Tenable, naming de `description`, campos enriquecidos de `reference` y reglas especificas del proyecto.

La fuente de verdad funcional para naming, `reference`, controles CIS/cliente y roles sigue siendo:

```text
audit_rules.md
```

La configuracion tecnica de valores aceptados por el script vive en:

```text
tools/validator_config.json
```

## 1. Requisitos

- Python 3.
- Ejecutar los comandos desde la raiz del repositorio.

Uso normal:

```powershell
python .\tools\validator.py
```

Si `python` no esta en el `PATH`, usar el Python disponible en el entorno o el Python empaquetado de Codex:

```powershell
C:\Users\Alberto\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe .\tools\validator.py
```

## 2. Que Valida

El validator comprueba:

- controles reportables en `<custom_item>`, `<item>` y `<report>`;
- checks auxiliares dentro de `<condition>` sin exigirles naming de control final;
- campos multilinea como `info`, `solution`, `cmd` o `expect`;
- cabeceras Tenable con atributos, incluidas variantes como `<condition auto:"FAILED" type:"AND">` o `<report type:"PASSED">`;
- `description` con estructura exacta `[control_id][OS][OS_VERSION][ROLE][BENCHMARK_VERSION][LEVEL] titulo`;
- valores de `description` contra `validator_config.json`;
- `reference` con campos `CONTROL_*`, valores esperados y duplicados;
- combinacion valida de `CONTROL_CUSTOMER` y `CONTROL_CIS`;
- semantica de `CONTROL_MS_ONLY` y `CONTROL_DC_ONLY` en Windows Server;
- balance de tags Tenable activos y comentados;
- bloques comentados parcialmente;
- presencia de condiciones `DomainRole` para audits Windows Server unificados.

El script termina con:

- `0` si no encuentra incidencias;
- `1` si encuentra incidencias;
- `2` si falta una ruta de entrada.

## 3. Opciones De Uso

Validar el scope por defecto definido en `validator_config.json`:

```powershell
python .\tools\validator.py
```

Validar una carpeta concreta:

```powershell
python .\tools\validator.py --audit-dir .\quick_test
```

Validar un fichero concreto:

```powershell
python .\tools\validator.py --audit .\audits\v2\CIS_Microsoft_Windows_Server_2022_v5.0.0_L1_v2.audit
```

Validar varios ficheros concretos:

```powershell
python .\tools\validator.py `
  --audit .\audits\v2\CIS_Microsoft_Windows_Server_2019_v4.0.0_L1_v2.audit `
  --audit .\audits\v2\CIS_Microsoft_Windows_Server_2022_v5.0.0_L1_v2.audit
```

Mostrar contadores tecnicos por fichero:

```powershell
python .\tools\validator.py --details
```

Generar salida JSON ademas de la salida humana:

```powershell
python .\tools\validator.py --json-report .\reports\validator_report.json
```

Usar una configuracion alternativa:

```powershell
python .\tools\validator.py --config .\tools\validator_config.json --audit-dir .\quick_test
```

Usar un documento alternativo de auxiliares permitidos:

```powershell
python .\tools\validator.py --auxiliary-doc .\auxiliary_descriptions_without_unique_naming.md
```

Validar un CSV summary de Tenable:

```powershell
python .\tools\validator.py --summary .\tenable_summary.csv
```

Ejemplo completo:

```powershell
python .\tools\validator.py `
  --audit-dir .\audits\audits_uniq_id `
  --summary .\tenable_summary.csv `
  --json-report .\reports\validator_report.json `
  --details
```

## 4. Salida Esperada

La salida normal esta pensada para una revision humana. Prioriza:

- `Description / naming`;
- `Reference CONTROL_*`;
- `Estructura Tenable`;
- `Windows Server role detection`;
- `Summary CSV`, si se valida un summary.

Los errores se agrupan por fichero y muestran:

- linea;
- categoria;
- campo con error;
- valor erroneo;
- codigo interno;
- control afectado, si aplica.

Los contadores como `blocks`, `fields_checked`, `active_tags` o `commented_blocks` solo se muestran con `--details`.

## 5. Como Mantener validator_config.json

`validator_config.json` es el punto que permite cambiar el alcance sin tocar el codigo Python.

Reglas generales:

- El fichero debe ser JSON valido.
- JSON no permite comentarios ni comas finales.
- Los valores distinguen mayusculas y minusculas.
- Antes de eliminar un valor, confirmar que ningun `.audit` vigente lo usa.
- Si cambia una regla funcional de naming o `reference`, actualizar tambien `audit_rules.md`.
- Despues de cualquier cambio, ejecutar el validator contra un scope pequeno y luego contra el scope completo.

### defaults

Define las entradas por defecto cuando se ejecuta `validator.py` sin argumentos:

```json
{
  "defaults": {
    "audit_dir": "audits/audits_uniq_id",
    "auxiliary_doc": "auxiliary_descriptions_without_unique_naming.md"
  }
}
```

Cambiar `audit_dir` si el scope principal de trabajo deja de ser `audits/audits_uniq_id`.

### naming.allowed_values

Controla los valores permitidos dentro de `description`:

```json
{
  "naming": {
    "allowed_values": {
      "os": ["MS", "OL", "N/A"],
      "os_version": ["2016", "2019", "2022", "W11", "8", "N/A"],
      "role": ["DM", "DC", "N/A"],
      "benchmark_version": ["v0.0.0", "v4.0.0", "v5.0.0"],
      "level": ["L1", "L2"]
    }
  }
}
```

Usar este bloque para anadir, sustituir o reducir codigos globales aceptados.

Ejemplos:

- Si entra un nuevo OS, anadir su codigo en `os`.
- Si entra una nueva version de OS, anadirla en `os_version`.
- Si cambia la version CIS, anadir la nueva en `benchmark_version`.
- Si se retira un OS del scope, eliminar sus valores solo cuando ya no existan controles que los usen.

Importante: `allowed_values` permite valores globales, pero no define que fichero debe usarlos. Esa relacion se controla en `families`.

### reference.groups

Define los campos `CONTROL_*` reconocidos y sus tipos.

Tipos soportados:

- `boolean`: solo acepta `true` o `false` en minusculas.
- `integer`: acepta enteros no negativos y puede usar `min`.
- `enum`: acepta solo valores definidos en `allowed_values`.

Ejemplo de campo booleano:

```json
{
  "name": "CONTROL_CIS",
  "type": "boolean"
}
```

Ejemplo de campo enum:

```json
{
  "name": "CONTROL_IG",
  "type": "enum",
  "allowed_values": ["IG1", "IG2", "IG3"]
}
```

Ejemplo de campo entero:

```json
{
  "name": "CONTROL_INTERNAL_VERSION",
  "type": "integer",
  "min": 0
}
```

Los grupos actuales son:

- `common`: campos requeridos para todas las familias conocidas;
- `windows_server`: campos adicionales para Windows Server unificado.

Para anadir un nuevo campo obligatorio a todos los audits conocidos, incluirlo en `common`.

Para anadir un campo obligatorio solo a una familia concreta, crear un grupo nuevo y enlazarlo desde `families[].reference_groups`.

### allowed_customer_cis_pairs

Controla combinaciones permitidas de:

```text
CONTROL_CUSTOMER / CONTROL_CIS
```

Estado actual:

```json
[
  ["false", "true"],
  ["true", "false"]
]
```

Esto significa:

- control CIS puro: `CONTROL_CUSTOMER|false`, `CONTROL_CIS|true`;
- control cliente puro: `CONTROL_CUSTOMER|true`, `CONTROL_CIS|false`.

No ampliar estas combinaciones sin actualizar primero la regla en `audit_rules.md`.

### roles

Define la semantica global de roles:

```json
{
  "roles": {
    "windows_server_member_roles": ["DM"],
    "windows_server_dc_roles": ["DC"],
    "neutral_roles": ["N/A"]
  }
}
```

Este bloque se usa para interpretar `CONTROL_MS_ONLY` y `CONTROL_DC_ONLY`.

No anadir roles aqui si todavia no estan definidos en `naming.allowed_values.role`.

### families

Define las familias conocidas por fichero.

Cada familia indica:

- `name`: identificador interno estable;
- `file_pattern`: patron regex para reconocer el `.audit`;
- `expected`: valores esperados en `description`;
- `reference_groups`: grupos `CONTROL_*` obligatorios;
- `forbidden_reference_fields`: campos prohibidos para esa familia;
- `requires_unified_role_detection`: si debe exigir logica Windows Server unificada;
- `role_detection`: condiciones `DomainRole` esperadas.

Ejemplo no Windows Server:

```json
{
  "name": "oracle_linux_8",
  "file_pattern": ".*Oracle_Linux_8.*\\.audit$",
  "expected": {
    "os": "OL",
    "os_version": "8",
    "roles": ["N/A"],
    "benchmark_version": "v4.0.0",
    "level": "L1"
  },
  "reference_groups": ["common"],
  "forbidden_reference_fields": ["CONTROL_MS_ONLY", "CONTROL_DC_ONLY"]
}
```

Ejemplo Windows Server unificado:

```json
{
  "name": "windows_server_2022",
  "file_pattern": ".*Windows_Server_2022.*\\.audit$",
  "expected": {
    "os": "MS",
    "os_version": "2022",
    "roles": ["DM", "DC", "N/A"],
    "benchmark_version": "v5.0.0",
    "level": "L1"
  },
  "reference_groups": ["common", "windows_server"],
  "requires_unified_role_detection": true,
  "role_detection": [
    {
      "name": "any_windows_server_role",
      "domain_role_values": [2, 3, 4, 5]
    },
    {
      "name": "member_server_branch",
      "domain_role_values": [2, 3]
    },
    {
      "name": "domain_controller_branch",
      "domain_role_values": [4, 5]
    }
  ]
}
```

## 6. Cambios De Scope

### Anadir un OS o familia

Pasos:

1. Anadir los codigos necesarios en `naming.allowed_values`.
2. Crear una entrada nueva en `families`.
3. Definir `file_pattern` para que solo capture los ficheros de esa familia.
4. Definir `expected` con los valores que debe tener el `description`.
5. Definir `reference_groups`.
6. Definir `forbidden_reference_fields` si esa familia no debe usar campos de otro scope.
7. Ejecutar el validator sobre un `.audit` de esa familia.
8. Ejecutar el validator sobre el scope completo.

### Sustituir un OS, version o benchmark

Pasos:

1. Anadir el nuevo valor en `naming.allowed_values`.
2. Cambiar `families[].expected` en la familia afectada.
3. Actualizar los `.audit` que correspondan.
4. Ejecutar el validator.
5. Cuando ya no quede ningun control con el valor antiguo, retirarlo de `naming.allowed_values` si deja de estar soportado.

No eliminar primero el valor antiguo si todavia conviven versiones durante una migracion.

### Reducir el scope auditado

Pasos:

1. Quitar o ajustar las entradas de `families` que ya no deban validarse como familias conocidas.
2. Ajustar `defaults.audit_dir` si cambia la carpeta principal de validacion.
3. Retirar valores de `naming.allowed_values` solo si ningun `.audit` vigente los conserva.
4. Ejecutar el validator sobre la carpeta final.

Si se deja un `.audit` fuera de `families`, el validator seguira validando la estructura general, `description` y `reference`, pero no aplicara reglas semanticas de familia.

### Anadir un campo CONTROL_*

Pasos:

1. Definir el campo en `reference.groups`.
2. Decidir si es comun o solo de una familia.
3. Si es especifico, crear o reutilizar un grupo y enlazarlo en `families[].reference_groups`.
4. Actualizar los `reference` de los controles afectados.
5. Documentar la regla en `audit_rules.md`.
6. Ejecutar el validator.

Ejemplo de grupo especifico:

```json
{
  "reference": {
    "groups": {
      "mi_scope": [
        {
          "name": "CONTROL_MI_CAMPO",
          "type": "enum",
          "allowed_values": ["A", "B"]
        }
      ]
    }
  }
}
```

Luego enlazarlo en una familia:

```json
{
  "reference_groups": ["common", "mi_scope"]
}
```

## 7. Checklist Tras Cambiar La Configuracion

Ejecutar primero contra un scope pequeno:

```powershell
python .\tools\validator.py --audit-dir .\quick_test --details
```

Ejecutar despues contra el scope real:

```powershell
python .\tools\validator.py --details
```

Si se ha tocado `validator_config.json`, revisar:

- que el JSON carga correctamente;
- que no hay comas finales;
- que los valores nuevos existen tambien en los `description`;
- que las familias no se pisan por `file_pattern` demasiado amplios;
- que los campos `CONTROL_*` nuevos estan documentados en `audit_rules.md`;
- que Windows Server conserva la logica unificada `DM` y `DC`;
- que Linux no hereda reglas Windows Server salvo instruccion explicita.

## 8. Scripts Mantenidos

El unico script mantenido para validar `.audit` es:

```powershell
python .\tools\validator.py
```

Los validadores historicos y scripts PowerShell previos se han retirado para evitar dobles criterios de validacion. Cualquier cambio nuevo debe hacerse en:

```text
tools/validator.py
tools/validator_config.json
```
