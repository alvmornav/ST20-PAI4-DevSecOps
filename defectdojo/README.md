# DefectDojo — Security Team 20

Instancia de OWASP DefectDojo donde el pipeline `devsecops.yml` centraliza los hallazgos de las cinco herramientas. Este documento no contiene credenciales.

## 1. Levantar la instancia

Requisitos: Docker con Compose y al menos 4 GB de RAM libres en la máquina que se queda encendida durante la práctica.

```bash
git clone https://github.com/DefectDojo/django-DefectDojo.git
cd django-DefectDojo
docker compose up -d
docker compose logs initializer | grep "Admin password:"
```

Si el README de la versión clonada lo pide, ejecutar antes `docker compose build`. La interfaz queda en `http://localhost:8080`.

Para pararla sin perder datos: `docker compose stop`. Para arrancarla de nuevo: `docker compose start`.

## 2. Configuración inicial (una sola vez)

1. Entrar como `admin` y cambiar la contraseña inicial.
2. **System Settings**: activar *Deduplicate findings* y *False positive history*.
3. **Product Types**: crear `SSII`.
4. **Users**: crear `ci-bot` sin permisos de superusuario. En el producto `Juice Shop ST20` → *Members*, añadirlo con rol **Writer**.
5. Entrar como `ci-bot` → menú de usuario → *API v2 Key* y copiar la clave. Esa es la única clave que usa el pipeline.
6. **SLA Configuration**: Critical 7 días, High 30, Medium 90, Low 120. Asignarla al producto.
7. **Notifications** del producto: activar *Scan added*.

El pipeline crea el resto del contexto la primera vez (`auto_create_context=true`):

| Nivel | Valor |
| --- | --- |
| Product Type | SSII |
| Product | Juice Shop ST20 |
| Engagement | CI/CD GitHub Actions |
| Tests | SCA - Dependency-Check · SAST - Semgrep · IaC - Checkov · IaC - Checkov K8s · Container - Trivy · DAST - ZAP |

## 3. Exponer la API a GitHub Actions

Los runners de GitHub no alcanzan `localhost`, así que se publica con un túnel saliente de Cloudflare, sin abrir puertos en el router:

```bash
cloudflared tunnel --url http://localhost:8080
```

`cloudflared` muestra una URL `https://<subdominio>.trycloudflare.com` con certificado válido.

Si la API responde `400 Bad Request`, añadir el host del túnel a `DD_ALLOWED_HOSTS` (o `*` durante la práctica) en la configuración de Compose y reiniciar con `docker compose up -d`.

## 4. Secretos en GitHub

*Settings → Secrets and variables → Actions*:

| Secreto | Contenido |
| --- | --- |
| `DD_URL` | URL del túnel, sin barra final |
| `DD_API_KEY` | API v2 key de `ci-bot` |
| `NVD_API_KEY` | Clave de la NVD para Dependency-Check |
| `DISCORD_WEBHOOK` | Opcional, webhook del canal de avisos |

## 5. Operación habitual

**Cuando cambia la URL del túnel** (cada vez que se reinicia `cloudflared`):

1. Copiar la nueva URL.
2. Actualizar el secreto `DD_URL`.
3. Relanzar el workflow desde *Actions → DevSecOps Pipeline ST20 → Run workflow*.

**Rotar la API key de `ci-bot`**:

1. Entrar como `ci-bot` → *API v2 Key* → *Generate New Key*.
2. Actualizar el secreto `DD_API_KEY`.
3. La clave anterior queda invalidada en el momento de regenerarla.

**Comprobar que la API responde** (desde cualquier equipo con la clave en una variable de entorno):

```bash
curl -s -H "Authorization: Token $DD_API_KEY" "$DD_URL/api/v2/products/?name=Juice%20Shop%20ST20" | jq '.count'
```

## 6. Cómo llegan los informes

Cada job llama a `scripts/dd-upload.sh <scan_type> <informe> <test_title>`, que hace `POST /api/v2/reimport-scan/`:

- Si el test no existe, lo crea; si existe, lo actualiza en lugar de crear uno nuevo.
- `close_old_findings=true` cierra como mitigados los hallazgos que desaparecen tras una corrección.
- `deduplication_on_engagement=true` marca como duplicado el mismo hallazgo detectado por dos herramientas.
- Se guardan `build_id`, `commit_hash` y `branch_tag` para trazar cada hallazgo hasta su run.

Prueba local del script:

```bash
export DD_URL=https://<subdominio>.trycloudflare.com DD_API_KEY=<clave-ci-bot>
export DD_PRODUCT="Juice Shop ST20" DD_ENGAGEMENT="CI/CD GitHub Actions"
bash scripts/dd-upload.sh "Trivy Scan" trivy.json "Container - Trivy"
```

Repetir el comando no debe crear un test nuevo ni duplicar hallazgos.

## 7. Triage

| Situación | Acción en DefectDojo | Acción en el repositorio |
| --- | --- | --- |
| Vulnerabilidad real | Marcar *Verified* y asignar responsable | Corregir; el siguiente reimport la cierra |
| Falso positivo | Marcar *False Positive* con justificación | Añadir la supresión de la herramienta (`.semgrepignore`, `security/zap/rules.tsv`…) |
| Riesgo asumido | *Risk Acceptance* en el engagement con motivo, responsable y fecha de expiración | Añadir el CVE a `security/.trivyignore` o a `security/dependency-check-suppressions.xml` con motivo y fecha |

Toda supresión entra en `main` por pull request revisado por otro miembro del equipo.
