#!/usr/bin/env bash
# Check exactly the staged publication tree, without printing secret values.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
command -v gitleaks >/dev/null || { echo "Install gitleaks before publication." >&2; exit 1; }
publication_tmp=$(mktemp -d)
trap 'rm -rf "$publication_tmp"' EXIT
# Ignore rules cannot protect files already staged or committed.
if git ls-files | grep -Eq '(^|/)(\.work|\.idea|node_modules|__pycache__)/|^deploy/(values\.yaml|secrets\.yaml|regcred\.yaml)$|(^|/)\.env($|\.)|\.(key|p12|pfx|kubeconfig|log)$'; then
  echo "Local configuration or sensitive artifact is tracked; remove it from the index before publication." >&2
  exit 1
fi
git checkout-index --all --prefix="$publication_tmp/"
gitleaks dir "$publication_tmp" --redact --no-banner --max-decode-depth 3
if git rev-parse --verify HEAD >/dev/null 2>&1; then
  gitleaks git . --redact --no-banner
fi
echo "Secret scan passed. Review organization-specific content and licensing separately."
