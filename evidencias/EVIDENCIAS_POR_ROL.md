# Evidencias por rol — PAI-4 ST20

Estado a 23/11/2026. Todas las rutas son relativas a la carpeta `evidencias/` que va en `PAI4-ST20.zip` (no se sube al repositorio).

Leyenda: ✅ hecha · ⚠️ existe pero hay que rehacerla · ❌ pendiente

Requisito previo para casi todo lo pendiente: **DefectDojo levantado, túnel activo y `DD_URL` actualizado** (Rol A).

---

## Rol A — Plataforma

| Evidencia | Estado | Ubicación | Cómo obtenerla |
| --- | --- | --- | --- |
| Secretos configurados (solo nombres) | ✅ | `plataforma/secretos-github.png` | — |
| Regla de protección de `main` | ✅ | `plataforma/proteccion-main-regla.png` | — |
| PR bloqueada por la protección de `main` | ✅ | `plataforma/proteccion-main-pr15-bloqueada.png` | — |
| Dos reimports seguidos sin duplicar hallazgos | ✅ | `defectdojo/reimport-sin-duplicar.png` | — |
| Manifiestos `k8s/` en kind local (pods y servicio) | ✅ | `plataforma/kind-local-pods.png` | — |
| Juice Shop responde en kind local (HTTP 200) | ✅ | `plataforma/kind-local-curl-200.png` | — |
| Estructura de 9 jobs (run #23, esqueleto) | ✅ | `runs/run23-grafo-9-jobs.png` | — |
| Job deploy y smoke test (run #23) | ✅ | `runs/run23-deploy-kind.png`, `runs/run23-smoke-test.png` | — |
| Ajustes de DefectDojo (deduplicación y False positive history) | ❌ | `defectdojo/system-settings.png` | *Configuración → System Settings*, captura con ambas casillas marcadas |
| Despliegue en kind del run de `demo/gate` | ❌ | `runs/demo-gate-deploy.png` | Cuando C lance `demo/gate`: job **deploy** desplegado, con *rollout* y *smoke test* en verde |
| Run #3: primera integración con DefectDojo (histórico) | ✅ | `runs/historico/run3-trivy-defectdojo-verde.png` | — |
| Run #4: primer gate bloqueante, 141 críticas (histórico) | ✅ | `runs/historico/run4-gate-defectdojo-141-criticas.png` | — |
| Panel del producto con 496 hallazgos (histórico) | ✅ | `defectdojo/historico-import-scan/panel-producto-496-hallazgos.png` | — |

---

## Rol B — Análisis en build

Todo lo pendiente sale del **run de `main` con el pipeline completo** (el mismo que usa C) y de DefectDojo.

| Evidencia | Estado | Ubicación | Cómo obtenerla |
| --- | --- | --- | --- |
| Summary del job `sca` con la tabla de G1 | ❌ | `runs/summary-g1-sca.png` | Run de `main` → **Summary** → tabla *Quality gate dependency-check (aviso, umbral 7.0)* |
| Summary del job `sast` con la tabla de G2 | ❌ | `runs/summary-g2-sast.png` | Tabla *Quality gate semgrep (aviso, umbral ERROR)* |
| Summary del job `iac` con la tabla de G3 | ❌ | `runs/summary-g3-iac.png` | Tablas *Quality gate checkov* (Dockerfile y K8s) |
| Summary del job `container` con la tabla de G4 | ❌ | `runs/summary-g4-container.png` | Tabla *Quality gate trivy (aviso, umbral CRITICAL)* |
| Informe de Dependency-Check | ❌ | `informes/dependency-check-report.xml` | Artefacto `report-sca` del run de `main` |
| Informe de Semgrep | ❌ | `informes/semgrep.json` | Artefacto `report-sast` |
| Informes de Checkov | ❌ | `informes/checkov-docker.json`, `informes/checkov-k8s.json` | Artefacto `report-iac` |
| Informe de Trivy | ❌ | `informes/trivy.json` | Artefacto `report-container` |
| Hallazgo concreto de Dependency-Check (CVE + paquete) | ❌ | `defectdojo/hallazgo-dependency-check.png` | DefectDojo → test *SCA - Dependency-Check* → abrir un hallazgo Critical |
| Hallazgo concreto de Semgrep (regla + fichero:línea) | ❌ | `defectdojo/hallazgo-semgrep.png` | Test *SAST - Semgrep* → hallazgo en `routes/` o `lib/` |
| Hallazgo concreto de Checkov (ID del check + recurso) | ❌ | `defectdojo/hallazgo-checkov.png` | Test *IaC - Checkov K8s* → un `CKV_K8S_*` sobre el deployment |
| Hallazgo concreto de Trivy (CVE + paquete del SO) | ❌ | `defectdojo/hallazgo-trivy.png` | Test *Container - Trivy* → hallazgo Critical con versión corregida |
| Duplicado entre Dependency-Check y Trivy | ❌ | `defectdojo/duplicado-dc-trivy.png` | *Hallazgos* → filtrar *Duplicate = Yes* → uno cuyo original sea de la otra herramienta |
| Tests del engagement antiguo (histórico) | ✅ | `defectdojo/historico-import-scan/tests-31-engagement-antiguo.png` | — |
| Métricas con 4.450 hallazgos (histórico) | ✅ | `defectdojo/historico-import-scan/metricas-4450-hallazgos.png` | — |
| Gate de DefectDojo con 696 críticas (histórico) | ✅ | `runs/historico/run-rolb-gate-defectdojo-696-criticas.png` | — |
| Historial de los runs 1 a 6 (histórico) | ✅ | `runs/historico/lista-runs-1-a-6.png` | — |

---

## Rol C — DAST, gates y gestión

C además reúne la carpeta completa y monta el zip.

| Evidencia | Estado | Ubicación | Cómo obtenerla |
| --- | --- | --- | --- |
| Log completo del run de `main` que falla en G6 | ❌ | `runs/main-gate-fallido.zip` | Run de `main` → **⋯ → Download log archive** |
| Grafo de jobs del run de `main` | ❌ | `runs/grafo-main.png` | **Summary** del run: `security-gate` en rojo, `deploy` saltado, `notify` ejecutado |
| Summary del job `dast` con la tabla de G5 | ❌ | `runs/summary-g5-dast.png` | Tabla *Quality gate zap (bloqueante, umbral High)* |
| Summary de `security-gate` con G6 y el estado de DefectDojo | ❌ | `runs/summary-g6-security-gate.png` | Tablas de G6 (SCA y Container) y *Estado en DefectDojo* |
| Informe de ZAP | ❌ | `informes/zap-report.html` | Artefacto `report-dast` → `report_html.html` |
| Hallazgo concreto de ZAP (alerta + URL) | ❌ | `defectdojo/hallazgo-zap.png` | Test *DAST - ZAP* → abrir una alerta High o Medium |
| Aviso recibido en Discord | ❌ | `runs/discord-aviso.png` | Canal `#pipeline-avisos` tras el run fallido de `main` |
| Engagement con los 6 tests | ⚠️ | `defectdojo/engagement-tests.png` | Rehacer en *CI/CD GitHub Actions* tras el run de `main`. La captura antigua es del engagement con import-scan |
| Hallazgos por severidad | ⚠️ | `defectdojo/hallazgos-severidad.png` | Rehacer tras el run de `main`. Las cifras antiguas están infladas |
| Falso positivo marcado y justificado | ❌ | `defectdojo/falso-positivo.png` | Triage: marcar *False Positive* con justificación y añadir su supresión en el repo |
| Aceptación de riesgo | ❌ | `defectdojo/riesgo-aceptado.png` | Engagement → *Risk Acceptance* con los CVE de `demo/gate`, motivo, responsable y expiración |
| SLA y notificaciones configuradas | ❌ | `defectdojo/sla-notificaciones.png` | *SLA Configuration* asignada al producto y *Notifications → Scan added* |
| Métricas del producto tras el triage | ❌ | `defectdojo/metricas.png` | Producto → **Métricas** |
| Log completo del run de `demo/gate` | ❌ | `runs/demo-gate-despliegue.zip` | Run de `demo/gate` → **⋯ → Download log archive** |
| Grafo de jobs del run de `demo/gate` | ❌ | `runs/grafo-demo-gate.png` | `security-gate` y `deploy` en verde, `notify` saltado |

---

## Orden recomendado

1. **A**: levantar DefectDojo y el túnel, actualizar `DD_URL` y capturar *System Settings*.
2. **C**: lanzar el run de `main` y descargar el log, los artefactos y las capturas del Summary y de Discord.
3. **B**: con ese mismo run, sacar las tablas G1–G4, guardar los informes y capturar los 4 hallazgos concretos y el duplicado.
4. **C**: hacer el triage (falso positivo, riesgo aceptado, SLA) y capturar el engagement, las severidades y las métricas.
5. **B + C**: crear `demo/gate` con los CVE de G6 y lanzar su run.
6. **A**: capturar el despliegue en kind de `demo/gate`.
7. **C**: comprobar que no hay secretos y montar el zip:
   ```bash
   grep -rniE "token|api_key|apikey|password|trycloudflare|webhook" evidencias/
   ```

## Resumen

| Rol | Hechas | Pendientes |
| --- | --- | --- |
| A | 11 | 2 |
| B | 4 (históricas) | 13 |
| C | 0 | 15 (2 de ellas para rehacer) |
