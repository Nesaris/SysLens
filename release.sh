#!/bin/sh
# Publie une version : ./release.sh 0.2.0 "Ce qui change"
# Les installations SysLens la récupèrent toutes seules (vérification toutes les heures).
set -eu
V="${1:?usage: ./release.sh 0.2.0 \"notes\"}"; NOTES="${2:-Version $V}"
cd "$(dirname "$0")"
node -e 'const f="package.json",p=JSON.parse(require("fs").readFileSync(f));p.version=process.argv[1];require("fs").writeFileSync(f,JSON.stringify(p,null,2)+"\n")' "$V"
node syslens.js --selftest
shasum -a 256 syslens.js console.html package.json > SHA256SUMS
git add -A && git commit -m "v$V" && git tag "v$V" && git push && git push origin "v$V"
gh release create "v$V" --title "v$V" --notes "$NOTES"
echo "v$V publiée."
