# Informe PAI-4 ST20 — Rol C: apartados 6 y 7

> Extracto de la parte del Rol C del informe final (`docs/informe/PAI4-ST20-Informe.md`), con las cifras del run #48 en `main`.

## 6. Gestión en DefectDojo

### 6.1. Organización e ingestión

| Nivel | Valor |
| --- | --- |
| Product Type / Product | SSII / Juice Shop ST20 |
| Engagement | CI/CD GitHub Actions (único y continuo) |
| Tests | SCA - Dependency-Check · SAST - Semgrep · IaC - Checkov · IaC - Checkov K8s · Container - Trivy · DAST - ZAP |

El pipeline sube los informes con `POST /api/v2/reimport-scan/` usando el usuario de servicio **ci-bot**, que solo tiene rol *Writer* sobre el producto. Si su clave se filtrara, no daría acceso al resto de la instancia. Cada importación guarda el run, el commit y la rama. El hallazgo CVE-2026-22709 (`vm2`, Critical 9,8) muestra en su ficha la ruta del componente, *Fix Available: True*, el SLA en curso y que lo subió `ci-bot` (Anexo A).

### 6.2. Deduplicación

Hay deduplicación en dos niveles:

- **Entre ejecuciones.** `reimport-scan` actualiza el test existente en lugar de crear uno nuevo. Los hallazgos que se repiten quedan como *untouched*, los nuevos se añaden y los que desaparecen se cierran como *Mitigated*. Se comprobó con dos subidas seguidas del mismo informe, que no cambiaron el número de tests ni de hallazgos. Tras varias ejecuciones, el producto tiene **602 hallazgos abiertos**, frente a los 4.450 que llegó a acumular con `import-scan`.
- **Entre herramientas.** Con *Deduplicate findings* y `deduplication_on_engagement=true`, un mismo CVE detectado por dos herramientas se marca como duplicado. Es el caso esperable de las librerías de Node que detectan a la vez Dependency-Check, desde `package-lock.json`, y Trivy, desde la imagen: `vm2`, `lodash` o `crypto-js`. El resumen de `security-gate` cuenta por ello solo las críticas activas **no duplicadas**: 89 en el run #48.

### 6.3. Clasificación y priorización

DefectDojo aplica un SLA por severidad y muestra en cada hallazgo los días restantes: el CVE-2026-22709, Critical, descubierto hace 2 días, tiene 5 días de SLA, es decir, un plazo de 7 días para los Critical.

Aplicando el flujo del diagrama 1.b a los resultados del run #48, la clasificación queda así:

| Clase | Hallazgos | Tratamiento |
| --- | --- | --- |
| Prioridad inmediata (Critical/High reales) | Inyección SQL confirmada por ZAP y Semgrep; `vm2` 3.9.17 (CVSS 10); claves privadas en `lib/insecurity.ts` | *Verified*, responsable asignado y corrección dentro del SLA de 7 días |
| Falso positivo | 4 inyecciones que Semgrep marca en `data/static/codefixes/*.ts`. Son fragmentos de código de los retos que la aplicación muestra como texto y nunca ejecuta | *False Positive* con la justificación y la ruta añadida a `.semgrepignore` |
| Riesgo aceptado | Vulnerabilidades heredadas de Juice Shop sin corrección en el alcance de la práctica, como la cadena de dependencias de `vm2` | *Risk Acceptance* con motivo, responsable y caducidad, y supresión del CVE con la misma fecha de revisión |
| Hallazgo en el propio pipeline | Semgrep marca `scripts/rol_b_parsers.py:9` (`use-defused-xml-parse`): el parser lee XML con `xml.etree`, vulnerable a XXE | Riesgo bajo, porque el XML lo genera Dependency-Check dentro del runner. Se corrige usando `defusedxml` |

Que el pipeline detecte un fallo en su propio código muestra que se analiza todo el repositorio, no solo la aplicación.

## 7. Conclusiones y respuesta al cliente

**Sí: los incidentes del cliente se explican por su forma de trabajar.** Su pipeline compilaba y desplegaba sin que ninguna etapa comprobara la seguridad. Cualquier vulnerabilidad escrita por un desarrollador, heredada de una librería o causada por un Dockerfile o un manifiesto mal configurado llegaba a producción sin que nadie la viera.

Una sola ejecución de nuestro pipeline sobre Juice Shop lo demuestra:

- 141 vulnerabilidades en dependencias, 44 de ellas críticas.
- 31 errores graves en el código.
- 24 fallos de configuración en el contenedor y Kubernetes.
- 287 vulnerabilidades en la imagen, 47 críticas.
- 3 vulnerabilidades altas explotables con la aplicación en marcha, una de ellas la inyección SQL que también localiza el análisis del código.

Cada herramienta encuentra problemas que las demás no ven, así que ninguna basta por sí sola.

La migración a Kubernetes agrava el problema. Cada microservicio añade su código, sus dependencias, su imagen y sus manifiestos. Los manifiestos que reproducen su punto de partida generan 19 fallos de Checkov que en un clúster real permitirían, por ejemplo, ejecutar contenedores como root o agotar los recursos del nodo.

**Qué aporta la solución:**

- **Detección en cada cambio.** Las cinco herramientas se ejecutan en cada *push* y *pull request*, sin intervención manual.
- **Bloqueo de lo grave y aviso de lo demás.** G5 y G6 impidieron desplegar la versión vulnerable y avisaron al equipo (run #48). Como son *checks* obligatorios, tampoco se puede fusionar código que no los supere.
- **Un único punto de gestión.** DefectDojo reúne los resultados de las cinco herramientas, elimina duplicados, cierra automáticamente lo corregido y conserva cada decisión (falso positivo, riesgo aceptado), con autor y fecha.
- **Decisiones trazables.** Un gate solo se desbloquea corrigiendo o aceptando formalmente el riesgo, con una supresión revisada en el repositorio.

**Limitaciones y recomendaciones:**

- **El DAST completo tarda unos 45 minutos.** Conviene un escaneo *baseline* en las *pull requests* y reservar el completo para `main`.
- **DefectDojo en local, con un túnel rápido.** La URL cambia en cada reinicio y obliga a actualizar el secreto. En producción debe ir en un servidor con dominio fijo.
- **Juice Shop es vulnerable por diseño.** En un proyecto real, el volumen inicial sería menor y los gates de aviso podrían pasar a bloqueantes de forma progresiva.
- **Queda pendiente corregir lo detectado en los artefactos del cliente:** `securityContext`, límites y sondas en los manifiestos, y fijar las versiones de las imágenes y de las herramientas del pipeline (aún queda `Dependency-Check_Action@main`).

Recomendamos al cliente adoptar este pipeline como plantilla para cada microservicio: el coste de integrarlo es pequeño frente al de un incidente, y convierte la seguridad en una comprobación automática de cada cambio.
