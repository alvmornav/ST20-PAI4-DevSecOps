# Evidencias — PAI-4 ST20

Estructura que se incluye en `PAI4-ST20.zip`. Antes de añadir cualquier fichero, comprobar que no contiene tokens, URLs del túnel ni contraseñas.

```
evidencias/
├── runs/
│   ├── main-gate-fallido.zip          log completo del run de main parado por G6
│   ├── demo-gate-despliegue.zip       log completo del run de demo/gate que despliega
│   ├── grafo-main.png                 grafo de jobs del run fallido
│   ├── grafo-demo-gate.png            grafo de jobs del run de demo/gate
│   ├── summary-gates.png              tablas G1–G6 del Summary
│   └── discord-aviso.png              aviso recibido por notify
├── informes/
│   ├── dependency-check-report.xml
│   ├── semgrep.json
│   ├── checkov-docker.json
│   ├── checkov-k8s.json
│   ├── trivy.json
│   └── zap-report.html
├── defectdojo/
│   ├── engagement-tests.png           los seis tests del engagement
│   ├── hallazgos-severidad.png
│   ├── reimport-sin-duplicar.png      dos runs seguidos con las mismas cifras
│   ├── duplicado-dc-trivy.png
│   ├── falso-positivo.png
│   ├── riesgo-aceptado.png
│   └── metricas.png
└── plataforma/
    ├── secretos.png                   solo nombres, sin valores
    ├── proteccion-main.png
    └── kind-despliegue.png
```

Descarga del log de un run: *Actions → run → ⋯ → Download log archive*.
Descarga de los informes: artefactos `report-sca`, `report-sast`, `report-iac`, `report-container` y `report-dast` del run de `main`.

Comprobación final:

```bash
grep -rniE "token|api_key|apikey|password|trycloudflare|webhook" evidencias/ codigo/
```
