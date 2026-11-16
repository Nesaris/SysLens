# SysLens

Collecte les logs des équipements réseau, les trie par gravité et les affiche dans une console web. Pensé pour les équipes qui gèrent le réseau de nombreux clients.

- **Zyxel d'abord** : pare-feux ZLD et uOS (USG FLEX, ATP), switchs, bornes, Nebula. Cisco, Ubiquiti et Fortinet viendront sous forme d'extensions.
- **Tri déterministe** : chaque log reçoit un score de 0 à 100 (bénin, moyen, grave, critique), et le calcul est affiché pour chaque incident.
- **IA locale en option** (Ollama) pour donner un avis sur les incidents moyens et graves. Les critiques partent sans attendre le modèle.
- **Extensions** : constructeurs, CRM (Odoo) et notifications (Telegram, mail), configurées pas à pas.
- **Zéro dépendance** : Node.js 20 ou plus, un fichier serveur, un fichier console.

## Démarrer

```sh
git clone https://github.com/Nesaris/syslens.git && cd syslens
node syslens.js
```

Ensuite, ouvrez la console sur <http://localhost:8514/console>.

Le port 514 demande des droits sur Linux. Sur macOS, il fonctionne tel quel en écoute sur toutes les interfaces. Pour n'accepter que les logs de vos équipements :

```sh
ALLOW=10.10.10.49/32,192.168.1.0/24 node syslens.js
```

| Variable | Rôle | Défaut |
|---|---|---|
| `PORT` | Port syslog (UDP et TCP) | `514` |
| `WEB` | Port de la console (écoute sur 127.0.0.1 seulement) | `8514` |
| `ALLOW` | Sources autorisées, en CIDR séparés par des virgules | toutes |
| `SYSLENS_AUTOUPDATE` | `0` pour couper la mise à jour automatique | activée |

## Côté Zyxel

Dans le pare-feu : Configuration > Log & Report > Log Settings > Remote Server. Format **CEF/Syslog**, adresse de la machine SysLens, port 514, facility Local 1, catégories en « normal ».

## Mises à jour

SysLens vérifie les releases de ce dépôt toutes les heures. Quand une nouvelle version est publiée, il :

1. télécharge les fichiers de la release et vérifie chacun avec `SHA256SUMS` ;
2. lance la nouvelle version en test (`--selftest`) avant de toucher à quoi que ce soit ;
3. garde l'ancienne version dans `.previous/`, remplace les fichiers et redémarre.

Les logs et les réglages locaux ne sont jamais touchés. Pour revenir en arrière, copiez le contenu de `.previous/` à la place des fichiers, puis relancez.

Pour publier une version (mainteneurs) :

```sh
./release.sh 0.2.0 "Ce qui change"
```

## Données

Les logs restent sur la machine, dans `logs/`. Ce dossier ne doit jamais être poussé sur le dépôt : il contient des adresses IP et des identifiants de vos clients.

## Licence

MIT
