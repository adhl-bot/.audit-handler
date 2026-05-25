# Publicacion en GitHub

Esta guia explica como publicar este repositorio en GitHub para poder clonarlo o descargarlo como ZIP.

## Que debe subirse

El repositorio debe incluir:

- `audits/`
- `quick_test/`
- `tools/`
- `README.md`
- `AGENTS.md`
- `audit_rules.md`
- `DOCUMENTACION_PROYECTO_COMPLIANCE.md`
- `uniqueID_descriptions_by_audit.md`

No deben subirse temporales locales como:

- `results.csv`
- `tools/audit_identity_report.json`
- `tools/__pycache__/`
- `reports/`

Estos temporales quedan excluidos por `.gitignore`.

## Validar antes de publicar

Desde la raiz del repositorio:

```powershell
python .\tools\validate_audit_identity.py
```

O con el Python empaquetado de Codex:

```powershell
C:\Users\Alberto\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe .\tools\validate_audit_identity.py
```

La validacion esperada es:

```text
OK: validacion de identidad completada sin incidencias.
```

## Crear el repositorio remoto

En GitHub, crear un repositorio nuevo vacio, por ejemplo:

```text
holcim-compliance-audits
```

Recomendacion: usar repositorio privado salvo que se haya confirmado que todos los contenidos pueden publicarse.

## Conectar este repo local con GitHub

Sustituir `<URL_DEL_REPO>` por la URL SSH o HTTPS que da GitHub.

Ejemplo HTTPS:

```powershell
git remote add origin <URL_DEL_REPO>
git push -u origin main
```

Ejemplo SSH:

```powershell
git remote add origin git@github.com:<usuario>/<repo>.git
git push -u origin main
```

Si el remoto ya existe:

```powershell
git remote set-url origin <URL_DEL_REPO>
git push -u origin main
```

## Descargar desde GitHub

Opcion 1: clonar el repositorio.

```powershell
git clone <URL_DEL_REPO>
```

Opcion 2: descargar ZIP desde GitHub:

```text
Code -> Download ZIP
```
