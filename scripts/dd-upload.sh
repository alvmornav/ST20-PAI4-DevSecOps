#!/usr/bin/env bash
set -euo pipefail

scan_type="$1"
report="$2"
test_title="$3"

if [ ! -s "$report" ]; then
  echo "::warning title=DefectDojo::No existe el informe $report, no se sube"
  exit 0
fi

curl -sS --fail-with-body -X POST "$DD_URL/api/v2/reimport-scan/" \
  -H "Authorization: Token $DD_API_KEY" \
  -F "scan_type=$scan_type" \
  -F "file=@$report" \
  -F "test_title=$test_title" \
  -F "product_type_name=SSII" \
  -F "product_name=$DD_PRODUCT" \
  -F "engagement_name=$DD_ENGAGEMENT" \
  -F "auto_create_context=true" \
  -F "deduplication_on_engagement=true" \
  -F "close_old_findings=true" \
  -F "minimum_severity=Info" \
  -F "active=true" \
  -F "verified=false" \
  -F "build_id=${GITHUB_RUN_ID:-local}" \
  -F "commit_hash=${GITHUB_SHA:-local}" \
  -F "branch_tag=${GITHUB_REF_NAME:-local}"
echo