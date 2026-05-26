# Audit Rules

Este documento define las reglas operativas para crear, modificar y correlacionar ficheros `.audit` del proyecto. Aplica a los audits existentes y a cualquier audit nuevo que se genere a partir de ahora.

## 1. Alcance

Estas reglas aplican a controles reales de compliance dentro de ficheros `.audit`, incluidos:

- Controles activos.
- Controles comentados.
- Controles informativos o de cabecera como `0.0.0`.

No se deben aplicar a `description` internos auxiliares usados por la logica tecnica del check cuando no representen un control CIS/cliente real.

## 1.1. Controles condicionales y salida reportable

En ficheros `.audit` de Tenable/Nessus es valido que un mismo `control_id` aparezca mas de una vez dentro del mismo fichero cuando esas apariciones pertenecen a ramas condicionales alternativas.

Segun `NessusComplianceChecksReference.pdf`, las estructuras `<if>`, `<condition>`, `<then>` y `<else>` permiten ejecutar una rama u otra segun el resultado de checks previos. Los elementos dentro de `<condition>` actuan como precondiciones silenciosas: enrutan la logica, pero no son por si mismos el resultado final que debe verse como control CIS/cliente.

Definiciones operativas:

- `Control reportable`: control real que produce el resultado de compliance de una rama. Puede ser un `<report>` dentro de `<then>`/`<else>`, o un `<custom_item>`/`<item>` ejecutado como check final de esa rama.
- `Check auxiliar interno`: `<custom_item>`/`<item>` usado dentro de `<condition>` o como comprobacion tecnica de aplicabilidad/ruta. No representa por si solo un control CIS/cliente final.
- `Duplicado condicional valido`: mismo `control_id`, rol, benchmark, nivel y titulo repetido en varias ramas de una estructura condicional para cubrir valores esperados distintos segun el estado detectado del sistema.

Reglas:

- La naming convention y los campos enriquecidos de `reference` se aplican a los controles reportables.
- No es necesario aplicar naming convention ni campos `CONTROL_*` a checks auxiliares internos que solo deciden la rama condicional.
- Un duplicado condicional valido no debe tratarse como control duplicado a eliminar si cada aparicion pertenece a una rama alternativa o a una salida reportable distinta.
- Si se comenta o desactiva un control que vive dentro de una estructura condicional, deben comentarse todas las salidas reportables finales de ese control en la estructura, junto con la estructura envolvente necesaria para que no quede ninguna rama activa parcial.
- Si la salida final de la rama es un `<custom_item>` o `<item>` y no un `<report>`, ese elemento sigue siendo el control reportable y debe recibir naming/reference como cualquier control real.
- En estructuras anidadas, `description` y `reference` pertenecen al bloque reportable mas interno abierto. No se debe heredar un `description`/`reference` de una rama interna como si fuera del contenedor exterior.

## 2. Version de produccion

La version de produccion no se asume por la carpeta global mas alta. Se determina para cada `.audit` o familia concreta como la version mas alta disponible de ese mismo audit/familia dentro de `audits/vX`.

Ejemplos:

- Si Windows Server existe en `audits/v2`, esa es su base de produccion.
- Si Oracle Linux solo existe en `audits/v1`, esa sigue siendo su base de produccion aunque Windows tenga `v2`.
- Que exista una carpeta `audits/v2` no significa que todos los `.audit` tengan una version productiva `v2`.

Antes de crear un audit derivado:

1. Identificar familia, OS, version de benchmark y version de produccion real.
2. Copiar desde la version de produccion correspondiente.
3. Mantener intacta la logica funcional salvo que el cambio solicitado indique lo contrario.
4. Revisar `NessusComplianceChecksReference.pdf` antes de cambiar sintaxis, estructura o comportamiento de checks. No es necesario leer el documento completo: se deben revisar las secciones generales aplicables, incluidas `Compliance Checks Reference` y `Additional Information`, y la seccion especifica del OS o familia de OS representada por los audits tratados.

## 3. Naming convention de `description`

Todo control debe tener un `description` con esta estructura:

```text
[<control_id>][<OS>][<OS_VERSION>][<ROLE>][<BENCHMARK_VERSION>][<LEVEL>] <titulo original>
```

Reglas de formato:

- Todos los campos de identidad van entre corchetes.
- No hay espacios entre bloques.
- Hay un unico espacio entre `[<LEVEL>]` y el titulo.
- El valor de `description` de controles reportables debe delimitarse siempre con comillas dobles (`"`).
- El `description` no debe contener espacios consecutivos. Un cambio de espacios modifica la identidad visible del control y debe tratarse como cambio de ID.
- El titulo original se mantiene como lo entrega CIS/Tenable.
- Si el titulo original empieza por `(L1)` o `(L2)`, ese nivel se migra al bloque `[<LEVEL>]` y se elimina del titulo para evitar duplicar nivel como `[L1] (L1)`.
- No deben aparecer comillas escapadas con backslash dentro de `description`, como `\'` o `\"`, porque Tenable puede exponer esos caracteres como parte del nombre del control.
- Si un `description` necesita apostrofes o comillas simples en el titulo, se mantienen como texto interno dentro de las comillas dobles exteriores.
- `IG` no forma parte del `description`.
- Campos como `CUSTOMER`, `CIS`, `MS_ONLY`, `DC_ONLY` o `INTERNAL_VERSION` no forman parte del `description`.

Ejemplo:

```text
[1.1.1][MS][2022][DM][v5.0.0][L1] Ensure 'Enforce password history' is set to '24 or more password(s)'
```

## 4. Campos del identificador visible

### `control_id`

Numero original del control dentro del benchmark.

Ejemplos:

```text
[0.0.0]
[1.1.1]
[18.6.14.1]
```

### `OS`

Familia reducida del sistema.

Valores actuales:

```text
[MS]  Microsoft
[OL]  Oracle Linux
[N/A] OS no definido todavia
```

### `OS_VERSION`

Version reducida del sistema.

Valores actuales:

```text
[2016] Windows Server 2016
[2019] Windows Server 2019
[2022] Windows Server 2022
[W11]  Windows 11
[8]    Oracle Linux 8
```

### `ROLE`

Rol funcional del control.

Valores actuales:

```text
[DM]  Windows Server Domain/Member
[DC]  Windows Server Domain Controller
[N/A] No aplica rol funcional
```

Reglas:

- Windows Server debe conservar `[DM]` y `[DC]` cuando el audit unificado diferencie ambas ramas.
- Controles sin rol funcional, incluidos `0.0.0`, usan `[N/A]`.
- Windows 11 y Linux usan `[N/A]` salvo instruccion explicita futura.

### `BENCHMARK_VERSION`

Version CIS simplificada del benchmark.

Ejemplos:

```text
[v4.0.0]
[v5.0.0]
```

### `LEVEL`

Nivel/layer CIS del control.

Ejemplos:

```text
[L1]
[L2]
```

## 5. Campos enriquecidos en `reference`

Los metadatos propios del proyecto se anaden al final del campo `reference`, separados por coma, con formato `CLAVE|VALOR`.

Campos minimos para todos los controles:

```text
CONTROL_IG|IGx
CONTROL_INTERNAL_VERSION|0
CONTROL_CUSTOMER|true/false
CONTROL_CIS|true/false
```

Campos adicionales solo para Windows Server:

```text
CONTROL_MS_ONLY|true/false
CONTROL_DC_ONLY|true/false
```

Ejemplo Windows Server:

```text
reference : "... ,CONTROL_IG|IG1,CONTROL_INTERNAL_VERSION|0,CONTROL_CUSTOMER|false,CONTROL_CIS|true,CONTROL_MS_ONLY|false,CONTROL_DC_ONLY|false"
```

Ejemplo Windows 11 / Linux:

```text
reference : "... ,CONTROL_IG|IG1,CONTROL_INTERNAL_VERSION|0,CONTROL_CUSTOMER|false,CONTROL_CIS|true"
```

## 6. Semantica de `reference`

### `CONTROL_IG`

IG heredado del benchmark CIS.

Reglas:

- No forma parte del ID visible.
- Se mantiene como enriquecimiento.
- Si CIS cambia el IG en una nueva version, se actualiza este campo sin cambiar por ello la identidad visible salvo que tambien cambien campos del ID.

### `CONTROL_INTERNAL_VERSION`

Version interna de implementacion del control.

Valor inicial:

```text
CONTROL_INTERNAL_VERSION|0
```

Debe incrementarse si cambia:

- La forma tecnica de evaluar el control.
- El valor esperado.
- La logica del check.
- La forma de interpretar el resultado.

No debe incrementarse por cambios puramente documentales que no cambien el comportamiento del control.

### `CONTROL_CUSTOMER`

Indica si el control es unico del cliente y no existe en CIS.

Reglas:

- Control CIS original: `CONTROL_CUSTOMER|false`.
- Control creado exclusivamente para el cliente: `CONTROL_CUSTOMER|true`.
- Si un control CIS se adapta tecnicamente para el cliente, no pasa automaticamente a `CUSTOMER|true`; se mantiene `CONTROL_CIS|true` y se incrementa `CONTROL_INTERNAL_VERSION` si cambia el comportamiento.

### `CONTROL_CIS`

Indica si el control proviene de CIS.

Reglas:

- Control CIS original: `CONTROL_CIS|true`.
- Control exclusivamente del cliente sin origen CIS: `CONTROL_CIS|false`.

### `CONTROL_MS_ONLY`

Solo Windows Server.

Indica que el control existe solo en la rama Member Server / Domain Member.

Reglas:

- `true` si el control esta solo en `[DM]`.
- `false` si existe tambien en `[DC]`.
- El match se hace por `control_id` + titulo/description normalizado, comparando dentro del mismo OS, version, benchmark y level, ignorando solo el campo `[ROLE]`.

### `CONTROL_DC_ONLY`

Solo Windows Server.

Indica que el control existe solo en la rama Domain Controller.

Reglas:

- `true` si el control esta solo en `[DC]`.
- `false` si existe tambien en `[DM]`.
- El match se hace por `control_id` + titulo/description normalizado, comparando dentro del mismo OS, version, benchmark y level, ignorando solo el campo `[ROLE]`.

## 7. Correlacion funcional

Para correlacionar controles entre audits, resultados de scan o artefactos derivados deben extraerse estos campos desde `description` y `reference`:

```text
control_id
os
os_version
role
benchmark_version
level
title
control_ig
control_internal_version
control_customer
control_cis
control_ms_only
control_dc_only
```

Reglas:

- En Windows Server, `role` es funcional y debe conservarse porque puede cambiar aplicabilidad o interpretacion.
- En Windows 11 y Linux, `role` existe como campo parseable pero normalmente vale `N/A`.
- `CONTROL_IG` sirve para priorizacion y metricas agregadas por IG, no para identidad principal.
- `CONTROL_MS_ONLY` y `CONTROL_DC_ONLY` enriquecen aplicabilidad; no sustituyen a `role`.
- El titulo completo se conserva para mantener trazabilidad con Tenable/CIS y evitar colisiones.

## 8. Controles cliente y coexistencia de versiones

Si se anade un control nuevo del cliente:

- Debe seguir la misma naming convention.
- Debe usar `CONTROL_CUSTOMER|true`.
- Debe usar `CONTROL_CIS|false` si no existe origen CIS.
- Debe tener `CONTROL_INTERNAL_VERSION|0` al crearse.

Si se modifica un control CIS para el cliente:

- No se debe cambiar el titulo original salvo necesidad funcional explicita.
- Debe conservar `CONTROL_CIS|true`.
- Debe conservar `CONTROL_CUSTOMER|false` salvo que se transforme en un control cliente independiente.
- Debe incrementarse `CONTROL_INTERNAL_VERSION` si cambia la logica o los valores.

Si en algun momento deben convivir dos implementaciones del mismo control dentro del mismo audit, no basta con `CONTROL_INTERNAL_VERSION`, porque ese campo no forma parte del ID visible. En ese caso hay que definir explicitamente una extension de identidad antes de implementarlo.

## 9. Reglas para Windows Server unificado

Windows Server puede contener en un mismo `.audit` controles para member servers y domain controllers.

Reglas:

- Conservar la logica de deteccion de rol existente.
- Mantener controles `[DM]` y `[DC]` cuando aplique.
- No fusionar controles con distinta aplicabilidad funcional.
- Mantener `CONTROL_MS_ONLY` y `CONTROL_DC_ONLY` en todos los controles Windows Server, con valor `true` o `false`.
- Los controles `0.0.0` o equivalentes sin rol funcional usan `[N/A]` y ambos flags `false`.

## 10. Reglas para Windows 11 y Linux

Reglas:

- No inventar roles.
- Usar `[N/A]` en `ROLE`.
- No anadir `CONTROL_MS_ONLY` ni `CONTROL_DC_ONLY`.
- Mantener los campos minimos de `reference`.

## 11. Validaciones minimas despues de modificar audits

El validador canonico del proyecto es Python y debe ejecutarse como filtro final:

```text
python tools/validator.py
```

Los valores aceptados por el validador para `OS`, `OS_VERSION`, `ROLE`, `BENCHMARK_VERSION`, `LEVEL`, familias conocidas y campos `CONTROL_*` se mantienen en:

```text
tools/validator_config.json
```

Despues de modificar o crear audits unique:

1. Verificar que todos los controles reales tienen naming completo.
2. Verificar que `description` reportable usa comillas dobles exteriores.
3. Verificar que no hay espacios consecutivos en `description`.
4. Verificar que no hay comillas escapadas con backslash en `description`.
5. Verificar que `IG` no aparece en `description`.
6. Verificar que todo control tiene `CONTROL_IG`.
7. Verificar que todo control tiene `CONTROL_INTERNAL_VERSION`.
8. Verificar que todo control tiene `CONTROL_CUSTOMER`.
9. Verificar que todo control tiene `CONTROL_CIS`.
10. En Windows Server, verificar que todo control tiene `CONTROL_MS_ONLY` y `CONTROL_DC_ONLY`.
11. En Windows 11 y Linux, verificar que no aparecen `CONTROL_MS_ONLY` ni `CONTROL_DC_ONLY`.
12. Verificar que controles comentados y `0.0.0` siguen la misma convencion.

## 12. Ubicacion de audits derivados y quick tests

Los audits con identificadores enriquecidos deben residir en:

```text
audits/audits_uniq_id/
```

Los ficheros de produccion bajo `audits/vX` no deben modificarse salvo instruccion explicita.

La carpeta `quick_test/` se reserva para ficheros `.audit` ligeros de prueba rapida. Su proposito es validar aplicabilidad, conectividad o controles concretos con menos checks que un benchmark completo. Estos ficheros no sustituyen a los audits productivos ni a los audits unique; son artefactos auxiliares para pruebas acotadas.

## 13. Controles comentados entre versiones

Cuando se cree o actualice una nueva version de un audit, se deben revisar los controles comentados en la version anterior equivalente.

Regla principal:

- Si un control estaba comentado en la version anterior, debe permanecer comentado en la nueva version salvo aprobacion explicita para reactivarlo.

Definicion operativa:

- Un control comentado es un bloque logico completo que no debe ejecutarse porque todas sus lineas no vacias estan precedidas por `#`.
- No basta con comentar solo la linea `description`.
- El bloque logico incluye el `<custom_item>` principal, sus campos internos y cualquier estructura directa necesaria para que el control exista: `<if>`, `<condition>`, `<then>`, `<else>`, `<report>` o `custom_item` auxiliares anidados.
- En controles condicionales, el objetivo no es comentar los checks auxiliares internos por separado, sino asegurar que todas las salidas reportables finales del control quedan desactivadas y que la estructura condicional no queda parcialmente activa.

Reglas de migracion:

1. Extraer de la version anterior todos los controles comentados reales.
2. Comparar por `control_id`.
3. En Windows Server unificado, buscar el control en las ramas `[DM]` y `[DC]`.
4. Si el control existe en ambas ramas, comentar ambas.
5. Si existe solo en una rama, comentar esa rama.
6. Si el control esta dentro de una estructura condicional, comentar el bloque logico completo o todas las salidas reportables finales de ese control junto con su estructura envolvente necesaria; no basta con comentar una sola rama.
7. No borrar controles comentados; mantenerlos conserva trazabilidad.

Validaciones minimas:

- No debe quedar ninguna `description` activa para un control heredado como comentado.
- No debe haber bloques parcialmente comentados.
- En Windows Server unificado, las apariciones esperadas deben coincidir con los roles aplicables.
- Las aperturas y cierres activos de tags deben quedar balanceados.

Regla especifica para estructuras condicionales:

```text
si el control_id esta en salidas reportables dependientes de un <if>,
comentar todas las salidas finales de ese control y la estructura envolvente necesaria
para que no quede ninguna rama ejecutable de forma parcial
```

Ejemplo de caso validado:

- En Windows Server 2016, los controles comentados heredados de `v1` quedaron comentados en `v2` tanto para servidor miembro como para domain controller.
- No se debe reactivar ningun control comentado salvo aprobacion explicita.
