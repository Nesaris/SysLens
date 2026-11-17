#!/bin/sh
# Publie une version : ./release.sh 0.3.0 "Ce qui change"
# Avant : ajouter l'entrée de la version en tête de nouveautes.json.
# Les installations la récupèrent seules dans l'heure (fichiers listés dans SHA256SUMS).
set -eu
export TZ=UTC
V="${1:?usage: ./release.sh 0.3.0 \"notes\"}"; NOTES="${2:-Version $V}"
cd "$(dirname "$0")"
node -e 'const n=require("./nouveautes.json");if(!n[0]||n[0].version!==process.argv[1]){console.error("Ajouter v"+process.argv[1]+" en tête de nouveautes.json");process.exit(1)}' "$V"
node -e 'const f="package.json",fs=require("fs"),p=JSON.parse(fs.readFileSync(f));p.version=process.argv[1];fs.writeFileSync(f,JSON.stringify(p,null,2)+"\n")' "$V"
npm test
node syslens.js --selftest
shasum -a 256 syslens.js console.html referentiel.json package.json nouveautes.json > SHA256SUMS
git add -A && { git diff --cached --quiet || git commit -m "v$V"; } && git tag "v$V" && git push && git push origin "v$V"
gh release create "v$V" --title "v$V" --notes "$NOTES"
echo "v$V publiée."
