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

## Comportamiento esperado

| Rama | build | sca/sast/iac/container | dast | security-gate | deploy | notify |
| --- | --- | --- | --- | --- | --- | --- |
| `main` | verde | verde con avisos | verde o rojo según G5 | **rojo (G6)** | saltado | ejecutado |
| `demo/gate` | verde | verde con avisos | verde o rojo según G5 | verde | **despliega en kind** | saltado |

Si ZAP no encuentra alertas `High`, G5 pasa y se documenta así en el informe; no se baja el umbral para forzarlo.

## Rama demo/gate

1. Lanzar el pipeline en `main` y abrir el *Summary* de `security-gate`.
2. Copiar los CVE de las tablas de G6.
3. Crear la rama:
   ```bash
   git checkout main && git pull
   git checkout -b demo/gate
   ```
4. Añadir cada CVE de Trivy a `security/.trivyignore`:
   ```
   CVE-AAAA-NNNNN  riesgo aceptado demo/gate · Rol C · revisar antes de 2026-12-31
   ```
5. Añadir cada CVE de Dependency-Check a `security/dependency-check-suppressions.xml`:
   ```xml
   <suppress until="2026-12-31Z">
     <notes>Riesgo aceptado para la demostración de la rama demo/gate. Responsable: Rol C.</notes>
     <cve>CVE-AAAA-NNNNN</cve>
   </suppress>
   ```
6. Push de la rama. Si G6 sigue fallando, repetir con los CVE que queden.
7. Registrar los mismos CVE como *Risk Acceptance* en DefectDojo con motivo, responsable y expiración 2026-12-31.

La rama `demo/gate` no se mergea en `main`.

Si G5 falla en `demo/gate` porque ZAP encuentra alertas `High` reales, el despliegue tampoco ocurre. En ese caso se añaden a `security/zap/rules.tsv` solo en `demo/gate`, con el motivo, y se explica en el informe.

## Triage en DefectDojo

- [ ] SLA asignada al producto y notificaciones *Scan added* activas
- [ ] Critical y High de las cinco herramientas revisados: los reales en *Verified* y con responsable
- [ ] Al menos un *False Positive* justificado y reflejado en la supresión de su herramienta
- [ ] Al menos una *Risk Acceptance* con motivo y expiración (los CVE de `demo/gate`)
- [ ] Dos runs seguidos sin cambios: el número de tests y de hallazgos no crece
- [ ] Un mismo CVE detectado por Dependency-Check y Trivy, con uno de ellos marcado *Duplicate*

## Ajustes en GitHub

- *Settings → Branches*: regla para `main` con *Require a pull request before merging* y *Require status checks to pass* con `security-gate`.
- *Settings → Secrets*: `DISCORD_WEBHOOK` (opcional) para el job `notify`.
- *Settings → Actions → General*: *Workflow permissions* en solo lectura.
