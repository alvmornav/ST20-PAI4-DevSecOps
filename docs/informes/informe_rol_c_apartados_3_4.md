# Informe PAI-4 ST20 — Aportación del Rol C a los apartados 3 y 4

> Borrador para integrar en el informe conjunto. Los valores marcados como **[completar]** se rellenan con los datos del run final de `main` y del run de `demo/gate`.

---

## 3.2. Flujo ante una vulnerabilidad (diagrama 1.b)

El diagrama 1.b (Figura X) describe qué ocurre con una vulnerabilidad desde que se detecta en el pipeline hasta que se cierra. El flujo parte de un principio: **todo hallazgo queda registrado en DefectDojo**, pero solo los gates bloqueantes detienen el pipeline, y ningún hallazgo se da por cerrado hasta que un nuevo análisis lo confirma.

**[Insertar Figura X: `docs/diagramas/1b-flujo-vulnerabilidad.png`]**
*Figura X. Flujo ante una vulnerabilidad: detección, decisión del gate, triage en DefectDojo y cierre con un nuevo análisis.*

### Detección y registro

Cada push o pull request lanza los cinco análisis (SCA, SAST, IaC, contenedor y DAST). Cada informe se sube a DefectDojo con `reimport-scan` sobre un test fijo por herramienta, lo que permite tres cosas:

- Los hallazgos que ya existían se actualizan en lugar de duplicarse.
- Los que aparecen por primera vez se marcan como nuevos.
- Los que han desaparecido se cierran como *Mitigated* (`close_old_findings`).

La deduplicación del engagement agrupa además el mismo CVE cuando lo detectan dos herramientas distintas, como ocurre con Dependency-Check y Trivy.

### Decisión 1: ¿supera el umbral de su gate?

Cada herramienta tiene un gate con un umbral propio (apartado 4).

- **No lo supera:** el hallazgo queda registrado en DefectDojo sin generar ningún aviso en el pipeline. Entra en el triage ordinario y se prioriza según el SLA de su severidad.
- **Lo supera:** se pasa a la segunda decisión.

### Decisión 2: ¿el gate es bloqueante?

- **No (G1–G4):** el job termina en verde con una anotación de aviso y una tabla con los hallazgos en el *Summary* del run. El pipeline continúa. El objetivo es que el equipo vea el problema sin bloquear la entrega por hallazgos de severidad media o sin corrección disponible.
- **Sí (G5 y G6):** el job falla, `deploy` se salta y el job `notify` envía un aviso a Discord con el enlace al run. Al estar `security-gate` configurado como *required status check* de `main`, el mismo fallo impide fusionar una pull request.

En los tres casos el hallazgo llega al mismo punto: el triage en DefectDojo.

### Decisión 3: ¿es una vulnerabilidad real?

El responsable de seguridad revisa el hallazgo en DefectDojo.

- **No (falso positivo):** se marca como *False Positive* con la justificación y se añade la supresión equivalente en el repositorio (`.semgrepignore`, `security/zap/rules.tsv`, `security/.trivyignore` o `security/dependency-check-suppressions.xml`). Con *False positive history* activado, DefectDojo no vuelve a abrirlo en los siguientes reimports, y la supresión evita que siga contando en el gate.
- **Sí:** se marca como *Verified*, se asigna un responsable y se pasa a la cuarta decisión.

### Decisión 4: ¿se puede corregir ahora?

- **Sí:** se corrige el código, se actualiza la dependencia o se cambia la imagen base.
- **No:** se registra una *Risk Acceptance* en el engagement, con motivo, responsable y fecha de expiración, y se añade la supresión del CVE en el repositorio con la misma fecha de revisión. Es el caso de un CVE sin parche disponible o de un cambio que no cabe en la entrega actual.

Toda supresión entra en `main` por pull request revisada por otro miembro del equipo, de modo que ningún rol puede silenciar un hallazgo por su cuenta.

### Cierre

Las tres salidas (corrección, falso positivo y riesgo aceptado) terminan en un nuevo push. El siguiente `reimport-scan` cierra los hallazgos corregidos, no reabre los falsos positivos y vuelve a evaluar los gates. Si ya no se supera ningún umbral bloqueante, `deploy` se ejecuta. El ciclo se cierra con una prueba, no con la palabra de quien hizo el cambio.

---

## 4. Quality gates

### 4.1. Resumen de los gates

| Gate | Job | Herramienta | Umbral | Modo |
| --- | --- | --- | --- | --- |
| G1 | `sca` | Dependency-Check | ≥ 1 dependencia con CVSS v3 ≥ 7.0 | Aviso |
| G2 | `sast` | Semgrep | ≥ 1 hallazgo de severidad ERROR | Aviso |
| G3 | `iac` | Checkov | ≥ 1 check fallido | Aviso |
| G4 | `container` | Trivy | ≥ 1 vulnerabilidad CRITICAL con versión corregida | Aviso |
| G5 | `dast` | OWASP ZAP | ≥ 1 alerta High no ignorada | **Bloqueante** |
| G6 | `security-gate` | Dependency-Check + Trivy | CVSS ≥ 9.0 en SCA, o ≥ 1 CRITICAL con versión corregida en la imagen | **Bloqueante** |

Los seis gates usan el mismo script, `scripts/quality_gate.py`, que recibe la herramienta, el informe, el umbral y el modo (`warn` o `block`). El script lee el informe que el propio job deja como artefacto, no la API de DefectDojo, para que los gates sigan funcionando aunque DefectDojo no esté accesible. Cada ejecución escribe en el *Summary* del run una tabla con los hallazgos que superan el umbral.

### 4.2. Por qué G1–G4 avisan y G5–G6 bloquean

Juice Shop es una aplicación vulnerable a propósito: cualquier umbral razonable en los análisis estáticos se supera en todas las ejecuciones. Si G1–G4 bloquearan, el pipeline estaría siempre en rojo y el gate perdería su valor como señal. Además, los análisis estáticos tienen una tasa de falsos positivos mayor que el DAST: Semgrep marca patrones, no explotaciones, y Dependency-Check incluye dependencias que no siempre se usan en tiempo de ejecución. Por eso G1–G4 se ejecutan con `continue-on-error: true`: el job queda en verde con una anotación y los hallazgos se gestionan en el triage.

**G5 bloquea** porque una alerta High de ZAP se ha obtenido atacando la aplicación en ejecución, con peticiones reales contra el contenedor recién construido. Es la evidencia más cercana a una explotación real que produce el pipeline, y una alerta de ese nivel no debería llegar a producción.

**G6 bloquea** porque es el gate de release: no evalúa un análisis aislado, sino si la imagen puede desplegarse. Se ejecuta en `security-gate` después de los cinco análisis (`if: always()`, para que se evalúe incluso si alguno ha fallado), descarga sus informes y decide si `deploy` puede ejecutarse. Si falta un informe, el gate también falla: una release sin análisis no se da por buena.

### 4.3. G5: análisis dinámico con OWASP ZAP

El job `dast` descarga la imagen construida en `build`, la arranca en el runner y espera a que responda en el puerto 3000. A continuación lanza un *full scan* de ZAP con:

- *ajax spider* (`-j`), necesario porque Juice Shop es una SPA en Angular y el spider clásico apenas descubre rutas.
- Un tiempo máximo de spider de 5 minutos (`-m 5`), para que el job no supere el límite de 60 minutos.
- El fichero de reglas `security/zap/rules.tsv`.

El fichero de reglas ignora cuatro alertas informativas, cada una con su motivo: aplicación SPA, marcas de tiempo, comentarios en librerías minificadas y recursos en Base64. Ninguna afecta al umbral de G5, que solo cuenta alertas High. Se ignoran para reducir ruido en DefectDojo.

El informe XML se sube a DefectDojo como test *DAST - ZAP*. El JSON se evalúa con G5, que excluye las reglas marcadas como `IGNORE`.

**Resultado en el run de `main`:** ZAP generó **[completar]** alertas: **[completar]** High, **[completar]** Medium, **[completar]** Low y **[completar]** informativas. G5 **[completar: bloqueó / no bloqueó]**.

> Si ZAP no encuentra alertas High, se mantiene el umbral y se documenta así. Bajarlo a Medium solo para que el gate salte invalidaría el criterio.

### 4.4. G6: gate de release

G6 combina dos comprobaciones sobre los informes de SCA y del contenedor:

| Comprobación | Umbral G6 | Umbral del gate de aviso |
| --- | --- | --- |
| Dependencias (Dependency-Check) | CVSS v3 ≥ 9.0 | G1: CVSS ≥ 7.0 |
| Imagen (Trivy) | ≥ 1 CRITICAL con versión corregida | G4: igual, pero en modo aviso |

Los umbrales de G6 son más altos que los de G1 porque G6 decide si se despliega, y no se puede bloquear una release por cada vulnerabilidad High de una aplicación que tiene cientos. Un CVSS de 9.0 o superior corresponde a vulnerabilidades críticas, normalmente explotables en remoto y sin autenticación.

En Trivy, G6 solo cuenta las vulnerabilidades CRITICAL con versión corregida. Una vulnerabilidad del sistema base sin parche no se puede resolver actualizando la imagen, así que bloquear por ella dejaría el pipeline parado sin que el equipo pudiera hacer nada. Esas vulnerabilidades se gestionan con una aceptación de riesgo en DefectDojo.

El paso final de `security-gate` toma el resultado de las dos comprobaciones y falla si cualquiera de ellas lo ha hecho. Antes, un paso informativo consulta DefectDojo y escribe en el *Summary* el número de críticas activas que no son duplicados, falsos positivos ni riesgos aceptados. Este paso refleja el triage, pero no decide la release, porque depende de que el túnel esté activo.

### 4.5. Comportamiento en `main` y en `demo/gate`

| Rama | Análisis (G1–G4) | `dast` (G5) | `security-gate` (G6) | `deploy` | `notify` |
| --- | --- | --- | --- | --- | --- |
| `main` | Verde con avisos | **[completar]** | Rojo | Saltado | Aviso enviado |
| `demo/gate` | Verde con avisos | **[completar]** | Verde | Despliega en kind | No se ejecuta |

**`main`.** G6 detectó **[completar]** dependencias con CVSS ≥ 9.0 y **[completar]** vulnerabilidades CRITICAL con versión corregida en la imagen (Figura X). El pipeline se detuvo, `deploy` no se ejecutó y llegó el aviso a Discord (Figura X). Es el comportamiento esperado en Juice Shop y constituye la evidencia de una ejecución que falla por un quality gate.

**`demo/gate`.** Para demostrar que el gate también deja pasar, se creó la rama `demo/gate`. En ella, los CVE que hacían fallar G6 se añadieron a `security/.trivyignore` y a `security/dependency-check-suppressions.xml`, cada uno con motivo y fecha de revisión (31/12/2026). En DefectDojo se registraron como aceptación de riesgo con la misma fecha. Con esas supresiones el run superó G6 y `deploy` publicó la imagen en GHCR y la desplegó en kind (Figura X). La rama no se fusiona en `main`.

Los dos runs, con el mismo código y distinta gestión del riesgo, demuestran que el gate decide en los dos sentidos y que la única forma de desbloquear una release es corregir la vulnerabilidad o aceptarla formalmente.
