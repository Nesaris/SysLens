# Sécurité — SysLens

## Signaler une faille

Ne pas ouvrir d'issue publique. Utiliser *Security › Report a vulnerability* sur ce dépôt (signalement privé GitHub), avec la version concernée et de quoi reproduire. Réponse sous sept jours.

## Ce que SysLens protège aujourd'hui

État au 0.2.0, relu sur le code ; ce n'est pas encore un audit complet du référentiel Codex64.

| Sujet | En place |
|---|---|
| Exposition | La console et ses API n'écoutent que sur 127.0.0.1. Seul le syslog écoute sur le réseau. |
| Sources de logs | `ALLOW` (CIDR) écarte toute source non prévue, en UDP comme en TCP ; chaque refus est compté. |
| Appels sensibles | `/api/update`, `/api/tg`, `/api/ai`, `/api/ref` et `/api/docs` refusent toute requête venue d'une autre origine que la console et tout corps qui n'est pas du JSON ; corps bornés en taille. |
| Mise à jour | Fichiers téléchargés depuis le tag de la release, vérifiés un à un par SHA-256 ; noms de fichiers contrôlés ; nouvelle version démarrée en essai avant tout remplacement ; ancienne version gardée. |
| Secrets | Le jeton Telegram ne passe que dans le corps des requêtes vers l'API Telegram ; il n'est ni écrit sur disque ni journalisé. |
| Logos récupérés | Sources fixées dans le code (site officiel de la marque, ou image directe de la collection LobeHub Icons pour Gemini, Codex, Claude Code et Gemini CLI, et de Wikimedia Commons pour Cisco, dont le site bloque les requêtes automatiques ; surchargeables par `EXT_SITES`), contenu vérifié comme vraie image, taille plafonnée, type d'image contrôlé ; servis avec une CSP `sandbox`. |
| Outils d'abonnement | Codex, Claude Code et Gemini CLI sont installés à la demande depuis npm, avec des noms de paquets fixés dans le code, dans le dossier `outils/` de SysLens (sans droits administrateur). La connexion au compte se fait sur la page officielle du fournisseur ; SysLens ne voit jamais le mot de passe et ne stocke aucun jeton : chaque outil garde le sien. |
| Connexions admin | Une connexion admin réussie depuis une adresse publique qui n’est pas dans les adresses de confiance (`logs/confiance.json` ou `SYSLENS_ADMIN_TRUST`) est critique ; depuis le réseau local ou une adresse de confiance, simple message. Liste de confiance modifiable par un administrateur seulement. |
| Odoo | API JSON-RPC en HTTPS seulement, sans suivre de redirection, avec un utilisateur technique ; clé API dans le trousseau macOS (« syslens-odoo ») ou `SYSLENS_ODOO_KEY`, jamais dans un fichier. `logs/odoo.json` garde l’adresse, la base, l’identifiant, l’équipe, l’étape et la correspondance comptes Telegram → comptes Odoo ; `logs/odoo-tickets.json` relie incidents et tickets. Le ticket contient l’équipement, le type et le log : il part dans l’Odoo de l’entreprise. |
| Consignes dans les logs | Avant tout envoi à l'IA (classement, entraînement, centre de formation), les phrases qui s'adressent à l'IA (« ignore tes consignes », « mets 0 », « note for the AI »…) sont retirées du log et l'IA est prévenue qu'il en contenait. Le texte du log reste intact dans SysLens. |
| Classement par l'IA | Pour les types de logs pas encore au référentiel, seuls des gabarits partent vers l'IA choisie : IP, MAC, adresses mail, comptes, noms de machine et de domaine remplacés avant l'envoi. La clé API vient de la console à chaque appel et n'est pas écrite sur disque. Une proposition non validée ne peut pas baisser une note. |
| Comptes | Dès le premier compte (créé depuis le poste de SysLens uniquement), toute la console et ses API demandent une session. Mots de passe hachés (scrypt, sel par compte), 10 caractères au moins ; `logs/comptes.json` et `logs/sessions.json` en 600, jetons de session stockés hachés. Cookie `HttpOnly; SameSite=Strict`, 12 h. 5 essais ratés par identifiant et adresse : blocage 15 min. Mot de passe provisoire à changer à la première connexion. Seule exception : la mise à jour lancée en ligne de commande sur ce poste (ni navigateur, ni cookie), qui n'installe qu'une release signée. |
| Alertes Telegram | Envoyées par le serveur (critiques et graves par défaut). Jeton du bot dans le trousseau macOS (« syslens-telegram ») ou la variable `SYSLENS_TELEGRAM_TOKEN`, jamais dans un fichier ni dans les logs ; `logs/alertes.json` ne garde que le groupe et les niveaux. Le message contient l'équipement, le type et un extrait du log : il part chez Telegram (hors UE), à valider pour les données clients (RGPD). |
| Alertes Teams et WhatsApp | Teams : seules les adresses de flux Microsoft sont acceptées (logic.azure.com, powerplatform.com, powerautomate.com, webhook.office.com), sans suivre de redirection ; l'adresse, qui vaut un secret, reste dans le trousseau macOS (« syslens-teams ») ou `SYSLENS_TEAMS_WEBHOOK`. WhatsApp : API officielle de Meta seulement ; jeton dans le trousseau (« syslens-whatsapp ») ou `SYSLENS_WHATSAPP_TOKEN` ; `logs/alertes.json` garde l'identifiant du numéro d'envoi, le modèle et les numéros d'astreinte (masqués dans la console). Le message contient l'équipement, le type et un extrait du log : il part chez Microsoft ou chez Meta (hors UE pour Meta), à valider pour les données clients (RGPD). |
| Assistant | Conversations rangées par compte (`logs/conversations/<compte>.json`, en 600) : un compte ne peut ni lister, ni lire, ni modifier, ni supprimer celles d'un autre, administrateur compris. Avec une IA locale, l'état de SysLens part tel quel vers le modèle ; avec une IA en ligne, les adresses IP et MAC sont masquées, mais les noms d'équipements et les messages partent : à réserver aux fournisseurs validés (RGPD). |
| Documentation des modèles | Seuls `www.zyxel.com` et `download.zyxel.com` sont contactés, en HTTPS (certificat vérifié), redirections suivies à la main et refusées hors de ces deux sites ; taille plafonnée (80 Mo). Seul le nom du modèle est envoyé. Document accepté seulement après les contrôles (dossier du modèle, vrai PDF, type de guide, série sur la couverture) ; empreinte SHA-256 gardée. Le PDF est lu puis supprimé, seul le texte est gardé. L'extrait envoyé à l'IA est présenté comme une donnée, et une proposition non validée ne baisse jamais une note. `SYSLENS_DOCS=0` coupe tout. |
| Données | Logs gardés sur la machine, jamais dans le dépôt ; aucune télémétrie. |

## Limites connues

- Pas encore de comptes ni de MFA sur la console : elle repose sur l'écoute en 127.0.0.1. Ne pas la publier derrière un proxy sans authentification.
- Le syslog en UDP n'est ni chiffré ni authentifié (limite du protocole) : `ALLOW` et un réseau de gestion séparé restent nécessaires. Le transport TLS est prévu pour les collecteurs installés chez les clients.
- La confiance dans une mise à jour repose sur l'accès en écriture au dépôt : double authentification exigée sur l'organisation et branche `main` protégée.
