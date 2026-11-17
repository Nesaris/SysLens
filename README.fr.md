<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="medias/logo-sombre.svg">
    <img src="medias/logo-clair.svg" alt="SysLens" height="56">
  </picture>
</p>

<p align="center"><img src="medias/affiche.png" alt="Affiche de SysLens" width="100%"></p>

# SysLens

SysLens reçoit les logs des équipements réseau d'un parc de clients, note chaque log de 0 à 100 et regroupe ce qui compte en incidents, avec le détail du calcul. Zyxel d'abord ; les autres marques arrivent sous forme d'extensions.

- **Note déterministe.** Un référentiel construit à partir de la documentation du constructeur, puis des modificateurs fixes : pare-feu de tête, source publique, répétition, hors plage ouvrée, même source vue chez plusieurs clients. Mêmes entrées, même note, et chaque incident montre son calcul.
- **Quatre niveaux.** Bénin (moins de 30), moyen (30), grave (60), critique (85). Les relevés de routine (statistiques d'interfaces, charge, paquets bloqués par la règle par défaut) restent bénins et n'ouvrent jamais d'incident.
- **IA au choix, jamais aux commandes.** Ollama, Mistral, ChatGPT, Claude, Gemini, Hermes ou Grok, par clé API ou avec un abonnement ChatGPT, Claude ou Google via Codex, Claude Code ou Gemini CLI. L'IA donne son avis sur les incidents moyens et graves ; les critiques partent sans l'attendre, et une IA hors du réseau reste coupée pour un client tant qu'il ne l'a pas autorisée par écrit (RGPD, art. 28).
- **Pensé pour un grand parc.** Les clients viennent du CRM (extension Odoo, avec règles d'import), le choix du client passe par une recherche, et un équipement qui se tait ouvre un incident.
- **Extensions.** Constructeurs, CRM et notifications (Telegram, mail) se branchent par un manifeste et se configurent pas à pas, une question par écran.
- **Mise à jour automatique** depuis les releases de ce dépôt, fichiers vérifiés par empreinte.

## Aperçu

<table>
<tr><td align="center" width="50%"><img src="medias/capture-accueil.png" alt="Vue d'ensemble"><br><sub>Vue d'ensemble</sub></td><td align="center" width="50%"><img src="medias/capture-incident.png" alt="Incident et calcul du score"><br><sub>Incident et calcul du score</sub></td></tr>
<tr><td align="center" width="50%"><img src="medias/capture-logs.png" alt="Flux de logs"><br><sub>Flux de logs</sub></td><td align="center" width="50%"><img src="medias/capture-extensions.png" alt="Extensions"><br><sub>Extensions</sub></td></tr>
<tr><td align="center" width="50%"><img src="medias/capture-configuration.png" alt="Configuration pas à pas"><br><sub>Configuration pas à pas</sub></td><td align="center" width="50%"><img src="medias/capture-ia.png" alt="Fournisseurs d’IA"><br><sub>Fournisseurs d’IA</sub></td></tr>
</table>

## Installation

Node.js 20 ou plus, rien d'autre.

```bash
git clone https://github.com/Nesaris/SysLens && cd SysLens
ALLOW=192.168.1.0/24 node syslens.js
```

La console s'ouvre sur <http://localhost:8514/console>. Elle n'écoute que sur la machine elle-même (127.0.0.1).

Le port 514 est privilégié sur Linux : lancer avec les droits nécessaires, ou autoriser Node une fois avec `sudo setcap cap_net_bind_service=+ep "$(command -v node)"`. Sur macOS, le port 514 s'ouvre sans droits particuliers tant que SysLens écoute sur toutes les interfaces (c'est le cas par défaut).

### Réglages

| Variable | Rôle | Par défaut |
|---|---|---|
| `PORT` | Port syslog, en UDP et en TCP | `514` |
| `BIND` | Adresse d'écoute du syslog | `0.0.0.0` |
| `WEB` | Port de la console (127.0.0.1 seulement) | `8514` |
| `ALLOW` | Sources acceptées, en CIDR séparés par des virgules ; le reste est ignoré et compté | toutes |
| `RETENTION_DAYS` | Jours de logs gardés ; les jours passés sont compressés, les plus vieux supprimés | `90` |
| `WORKERS` | Processus de réception en plus, pour les très gros parcs | `0` |
| `RAW_GZIP` | `0` pour écrire le brut sans compression | compressé |
| `SYSLENS_AUTOUPDATE` | `0` pour couper la mise à jour automatique | activée |
| `SYSLENS_REPO` | Dépôt dont les releases sont suivies | `Nesaris/SysLens` |

Mettez toujours `ALLOW` sur un réseau partagé : sans lui, n'importe quelle machine peut injecter des logs.

## Côté Zyxel

Sur un pare-feu ZLD (USG FLEX, ATP, USG) :

1. *Configuration › Log & Report › Log Settings*, ligne **Remote Server 1**, puis *Edit*.
2. **Active**, format **CEF/Syslog** (le format Syslog simple écrit l'année hors de la norme RFC 3164), adresse de la machine SysLens, port 514, facility **Local 1**.
3. Catégories en « normal » ; *Traffic Log* sur « disable », sauf si le contrat du client le demande.
4. *OK*, puis *Apply*.

Réglez aussi l'heure (NTP et fuseau) : SysLens horodate chaque log à la réception, mais une heure fausse sur l'équipement gêne la lecture des logs bruts.

## Référentiel

`referentiel.json` décrit les logs Zyxel connus (pare-feu ZLD et uOS, switchs, bornes, Nebula) : catégorie, message, note de base, plancher, signification et action. L'ordre fait la priorité : la première entrée qui correspond note le log.

Chaque type reçu est classé :

- **règle précise** : une entrée du référentiel le décrit ;
- **catégorie connue** : seule sa catégorie est connue, et sa gravité est faible ;
- **type appris** : classé par l'IA ou par un technicien, puis validé (`logs/ref-appris.json`) ;
- **à qualifier** : rien ne le décrit, ou sa catégorie seule ne suffit pas (gravité error ou plus). Il est noté avec la gravité annoncée par l'équipement, grave au plus.

Les types à qualifier sont envoyés à l'IA choisie dans la console, par lots de 25, sous forme de gabarits : adresses IP et MAC, comptes, noms de machine et de domaine sont masqués. Tant qu'un technicien ne l'a pas validée, une proposition de l'IA peut monter la note (grave au plus), jamais la baisser.

## Données

Tout reste sur la machine :

- `logs/raw-AAAA-MM-JJ.log.gz` : toutes les lignes reçues, telles quelles, compressées au fil de l'eau (`zcat` pour les lire) ;
- `logs/events-AAAA-MM-JJ.jsonl` : les événements utiles (référentiel, ou gravité moyen et plus), décodés, notés, avec leur ligne brute ;
- `logs/types.json` : tous les types de logs vus depuis l'installation, avec leur couverture ;
- `logs/ref-appris.json` : les types classés par l'IA ou un technicien, et les notes de base corrigées.

Ces fichiers contiennent des adresses IP et des identifiants des clients : le `.gitignore` les tient hors du dépôt, et rien n'est envoyé ailleurs. Les logos des extensions sont récupérés une fois sur le site officiel de chaque marque et gardés dans `extensions/` ; ils ne sont pas redistribués avec le code.

## Capacité

Mesuré sur une machine à 2 cœurs (qui envoyait aussi les logs) : **30 000 logs/s sans perte avec un seul processus**, en UDP, brut compressé compris. Un pare-feu Zyxel exposé à Internet envoie environ 1,3 log/s : un processus suit donc plus de 10 000 pare-feu. Au-delà, `WORKERS` ajoute des processus de réception, un par cœur libre.

- Seuls les événements utiles remontent au processus principal (incidents, console, IA) ; les bénins sont comptés, archivés et échantillonnés pour le flux de la console.
- Les incidents sont regroupés côté serveur (`/api/incidents`), par type, équipement et source.
- Les équipements derrière une même IP (routeur et switch d'un site en NAT) sont séparés par leur nom d'hôte.
- Disque : sur un vrai pare-feu, le brut se compresse environ 40 fois. Comptez de l'ordre de 7 Go par jour pour 10 000 pare-feu bavards, beaucoup moins avec le *Traffic Log* coupé.

## Mises à jour

Toutes les heures, SysLens demande à GitHub la dernière release du dépôt. Si elle est plus récente :

1. il télécharge les fichiers listés dans `SHA256SUMS` à ce tag et vérifie chacun ; un seul écart, et rien n'est remplacé ;
2. il démarre la nouvelle version en essai (`node syslens.js --selftest`) ;
3. il range la version en place dans `.previous/`, remplace les fichiers et redémarre dans le même terminal ;
4. la console ouverte se recharge seule (ou propose de le faire si un formulaire est en cours).

La page *Administration* montre la version installée, la dernière release, les nouveautés et un bouton « Vérifier maintenant ». Pour revenir en arrière : copier le contenu de `.previous/` à la place des fichiers, puis relancer.

### Publier une version

1. Ajouter l'entrée de la version en tête de `nouveautes.json`.
2. `./release.sh 0.3.0 "Ce qui change"` : met `package.json` à jour, lance les essais, calcule `SHA256SUMS`, commite en UTC, tague, pousse et crée la release.

Tout ce qui est publié en release s'exécute ensuite sur chaque installation : la double authentification doit être exigée sur l'organisation et la branche `main` protégée.

## Développement

```bash
npm test
```

Les essais démarrent de vrais serveurs SysLens, leur envoient du vrai syslog en UDP et vérifient la note, le filtre des sources, les refus des appels venus d'autres sites et la mise à jour complète contre un faux GitHub, y compris le refus d'un fichier altéré. La vérification continue (`.github/workflows/verification.yml`) ajoute la recherche de secrets dans l'historique, l'identité des commits et l'analyse statique.

## Licence

[MIT](LICENSE) — fait par [CodeX64](https://codexx64.github.io).
