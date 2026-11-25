# Rol C — DAST, quality gates y gestión de hallazgos

## Quality gates

| Gate | Job | Umbral | Modo | Implementación |
| --- | --- | --- | --- | --- |
| G1 | sca | ≥ 1 dependencia con CVSS v3 ≥ 7.0 | Aviso | `quality_gate.py --tool dependency-check --threshold 7.0 --mode warn` |
| G2 | sast | ≥ 1 hallazgo `ERROR` | Aviso | `--tool semgrep --threshold ERROR --mode warn` |
| G3 | iac | ≥ 1 check fallido | Aviso | `--tool checkov --threshold 1 --mode warn` |
| G4 | container | ≥ 1 `CRITICAL` con versión corregida | Aviso | `--tool trivy --threshold CRITICAL --mode warn` |
| G5 | dast | ≥ 1 alerta `High` no ignorada | Bloqueante | `--tool zap --threshold High --ignore security/zap/rules.tsv` |
| G6 | security-gate | CVSS ≥ 9.0 en SCA o ≥ 1 `CRITICAL` con parche en la imagen | Bloqueante | Dos llamadas a `quality_gate.py` y un paso de decisión |

Los gates en aviso usan `continue-on-error: true`: el job queda en verde con una anotación amarilla. Los bloqueantes paran el pipeline y `deploy` se salta.

`security-gate` añade además un resumen del estado en DefectDojo (`scripts/dd-gate-summary.sh`): cuenta las críticas activas que no son duplicadas, falsos positivos ni riesgo aceptado. Es informativo y no decide la release.

Cada gate escribe su tabla en el *Summary* del run.

## Comportamiento en `main`

| build | sca/sast/iac/container | dast | security-gate | deploy | notify |
| --- | --- | --- | --- | --- | --- |
| verde | verde con avisos (G1–G4) | rojo si ZAP encuentra alertas `High` (G5) | **rojo (G6)** | saltado | aviso enviado |

Es el comportamiento documentado en el run #48 (commit `633864c`): G5 bloqueó por 3 alertas High (SQL Injection, External Redirect, Off-site Redirect) y G6 por 4 dependencias con CVSS ≥ 9.0 y 41 vulnerabilidades CRITICAL con parche en la imagen. Las capturas están en `evidencias/runs/`.

Si ZAP no encuentra alertas `High`, G5 pasa y se documenta así; no se baja el umbral para forzarlo.

## Desbloquear una release

Un gate bloqueante solo se desbloquea de dos formas:

1. **Corrigiendo** el código, la dependencia o la imagen. El siguiente `reimport-scan` cierra el hallazgo.
2. **Aceptando el riesgo formalmente**: *Risk Acceptance* en DefectDojo con motivo, responsable y caducidad, y la misma supresión en el repositorio, entrando por pull request revisada por otro rol:
   - Trivy: `security/.trivyignore` → `CVE-AAAA-NNNNN  motivo · responsable · revisar antes de AAAA-MM-DD`
   - Dependency-Check: `security/dependency-check-suppressions.xml` → `<suppress until="AAAA-MM-DDZ">` con `<notes>` y `<cve>`
   - ZAP: `security/zap/rules.tsv` → `pluginid<TAB>IGNORE<TAB>(nombre) motivo`

## Triage en DefectDojo

- [ ] SLA asignada al producto y notificaciones *Scan added* activas
- [ ] Critical y High de las cinco herramientas revisados: los reales en *Verified* y con responsable
- [ ] Al menos un *False Positive* justificado y reflejado en la supresión de su herramienta
- [ ] Al menos una *Risk Acceptance* con motivo y expiración
- [ ] Dos runs seguidos sin cambios: el número de tests y de hallazgos no crece
- [ ] Un mismo CVE detectado por Dependency-Check y Trivy, con uno de ellos marcado *Duplicate*

## Ajustes en GitHub

- *Settings → Branches*: regla para `main` con *Require a pull request before merging* y *Require status checks to pass* con `security-gate`.
- *Settings → Secrets*: `DISCORD_WEBHOOK` (opcional) para el job `notify`.
- *Settings → Actions → General*: *Workflow permissions* en solo lectura.
