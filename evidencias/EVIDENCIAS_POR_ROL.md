# Evidencias — PAI-4 ST20

Estado final a 25/11/2026. La evidencia principal es el **run #48 en `main`** (commit `633864c`, run 45350011275), en el que los dos gates bloqueantes se disparan y detienen el pipeline.

## Run #48 en `main`: gates bloqueantes disparados

| Fichero | Qué demuestra |
| --- | --- |
| `runs/grafo-main.png` | Grafo completo: análisis en verde, `dast` y `security-gate` en rojo, `deploy` saltado, `notify` ejecutado (46 min 26 s) |
| `runs/summary-g5-dast.png` | G5 bloqueante: 3 alertas High de ZAP (SQL Injection, External Redirect, Off-site Redirect) |
| `runs/log-g5-bloqueo.png` | Paso *Quality gate G5* en rojo: «3 hallazgos superan el umbral High» |
| `runs/summary-g6-sca.png` | G6 sobre Dependency-Check: 4 dependencias con CVSS ≥ 9.0 (crypto-js, decompress, lodash, vm2) |
| `runs/summary-g6-container-1.png`, `runs/summary-g6-container-2-defectdojo.png` | G6 sobre Trivy: 41 vulnerabilidades CRITICAL con parche, y estado de DefectDojo (89 críticas sin gestionar) |
| `runs/log-g6-bloqueo.png` | Paso *Decision G6* en rojo: «Release bloqueada: SCA=failure, Container=failure» |
| `runs/discord-aviso.png` | Aviso del job `notify` en Discord con el enlace al run |

## Informes de las herramientas (artefactos del run #48)

| Fichero | Herramienta | Resumen |
| --- | --- | --- |
| `informes/dependency-check-report.xml`, `.html` | Dependency-Check | 37 de 43 dependencias vulnerables; 141 vulnerabilidades (44 critical, 45 high) |
| `informes/semgrep.json` | Semgrep | 102 hallazgos (31 ERROR) |
| `informes/checkov-docker.json`, `checkov-k8s.json` | Checkov | Dockerfile: 5 checks fallidos · Kubernetes: 19 checks fallidos |
| `informes/trivy.json` | Trivy | 287 vulnerabilidades (47 CRITICAL, 77 HIGH) |
| `informes/zap-report.html`, `.json`, `.xml` | OWASP ZAP | 46 alertas (3 High, 10 Medium) |

## DefectDojo

| Fichero | Qué demuestra |
| --- | --- |
| `defectdojo/hallazgos-abiertos-602.pdf` | 602 hallazgos abiertos en el producto, ordenados por severidad |
| `defectdojo/hallazgo-trivy-vm2.pdf` | Hallazgo concreto (CVE-2026-22709, vm2 3.9.17, Critical 9.8) en el test *Container - Trivy*, subido por `ci-bot`, con SLA y marcado como no modificado en el último reimport |
| `defectdojo/reimport-sin-duplicar.png` | Dos reimports seguidos sin duplicar el test ni los hallazgos |

## Plataforma (Rol A)

| Fichero | Qué demuestra |
| --- | --- |
| `plataforma/secretos-github.png` | Secretos del repositorio (solo nombres) |
| `plataforma/proteccion-main-regla.png` | Regla de protección de `main` |
| `plataforma/proteccion-main-pr15-bloqueada.png` | Una PR no se puede fusionar sin aprobación y sin checks en verde |
| `plataforma/kind-local-pods.png`, `kind-local-curl-200.png` | Manifiestos de `k8s/` desplegados en kind y aplicación respondiendo |
| `runs/run23-grafo-9-jobs.png`, `run23-deploy-kind.png`, `run23-smoke-test.png` | Estructura de 9 jobs y despliegue en kind con smoke test (run #23) |

## Histórico (pipeline anterior, con import-scan)

| Fichero | Qué demuestra |
| --- | --- |
| `runs/historico/run3-trivy-defectdojo-verde.png` | Primera integración del pipeline con DefectDojo |
| `runs/historico/run4-gate-defectdojo-141-criticas.png` | Primer gate bloqueante (141 críticas) |
| `runs/historico/run-rolb-gate-defectdojo-696-criticas.png` | Pipeline de A+B con las 4 herramientas (696 críticas) |
| `runs/historico/lista-runs-1-a-6.png` | Primeros runs del workflow |
| `defectdojo/historico-import-scan/*` | Cifras infladas por import-scan (31 tests, 4.450 hallazgos), que motivaron el cambio a reimport-scan |
