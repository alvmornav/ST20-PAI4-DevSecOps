#!/usr/bin/env bash
set -euo pipefail

product=$(jq -rn --arg v "$DD_PRODUCT" '$v|@uri')
url="$DD_URL/api/v2/findings/?product_name=$product&severity=Critical&active=true&duplicate=false&false_p=false&risk_accepted=false&limit=1"
count=$(curl -sS --fail-with-body -H "Authorization: Token $DD_API_KEY" "$url" | jq '.count')

echo "Criticas activas en DefectDojo: $count"
{
  echo "### Estado en DefectDojo ($DD_PRODUCT)"
  echo
  echo "Vulnerabilidades Critical activas, no duplicadas, sin falso positivo ni riesgo aceptado: **$count**"
  echo
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

if [ "$count" -gt 0 ]; then
  echo "::warning title=DefectDojo::$count criticas activas sin gestionar en DefectDojo"
  exit 1
fi
