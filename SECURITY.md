# Sécurité — SysLens

## Signaler une faille

Ne pas ouvrir d'issue publique. Utiliser *Security › Report a vulnerability* sur ce dépôt (signalement privé GitHub), avec la version concernée et de quoi reproduire. Réponse sous sept jours.

## Ce que SysLens protège aujourd'hui

État au 0.2.0, relu sur le code ; ce n'est pas encore un audit complet du référentiel Codex64.

| Sujet | En place |
|---|---|
| Exposition | La console et ses API n'écoutent que sur 127.0.0.1. Seul le syslog écoute sur le réseau. |
| Sources de logs | `ALLOW` (CIDR) écarte toute source non prévue, en UDP comme en TCP ; chaque refus est compté. |
| Appels sensibles | `/api/update`, `/api/tg`, `/api/ai` et `/api/ref` refusent toute requête venue d'une autre origine que la console et tout corps qui n'est pas du JSON ; corps bornés en taille. |
| Mise à jour | Fichiers téléchargés depuis le tag de la release, vérifiés un à un par SHA-256 ; noms de fichiers contrôlés ; nouvelle version démarrée en essai avant tout remplacement ; ancienne version gardée. |
| Secrets | Le jeton Telegram ne passe que dans le corps des requêtes vers l'API Telegram ; il n'est ni écrit sur disque ni journalisé. |
| Logos récupérés | Sources fixées dans le code (site officiel de la marque, ou image directe de la collection LobeHub Icons pour Gemini, Codex, Claude Code et Gemini CLI, et de Wikimedia Commons pour Cisco, dont le site bloque les requêtes automatiques ; surchargeables par `EXT_SITES`), contenu vérifié comme vraie image, taille plafonnée, type d'image contrôlé ; servis avec une CSP `sandbox`. |
| Outils d'abonnement | Codex, Claude Code et Gemini CLI sont installés à la demande depuis npm, avec des noms de paquets fixés dans le code, dans le dossier `outils/` de SysLens (sans droits administrateur). La connexion au compte se fait sur la page officielle du fournisseur ; SysLens ne voit jamais le mot de passe et ne stocke aucun jeton : chaque outil garde le sien. |
| Classement par l'IA | Pour les types de logs pas encore au référentiel, seuls des gabarits partent vers l'IA choisie : IP, MAC, adresses mail, comptes, noms de machine et de domaine remplacés avant l'envoi. La clé API vient de la console à chaque appel et n'est pas écrite sur disque. Une proposition non validée ne peut pas baisser une note. |
| Données | Logs gardés sur la machine, jamais dans le dépôt ; aucune télémétrie. |

## Limites connues

- Pas encore de comptes ni de MFA sur la console : elle repose sur l'écoute en 127.0.0.1. Ne pas la publier derrière un proxy sans authentification.
- Le syslog en UDP n'est ni chiffré ni authentifié (limite du protocole) : `ALLOW` et un réseau de gestion séparé restent nécessaires. Le transport TLS est prévu pour les collecteurs installés chez les clients.
- La confiance dans une mise à jour repose sur l'accès en écriture au dépôt : double authentification exigée sur l'organisation et branche `main` protégée.
