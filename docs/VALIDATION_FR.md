# Validation effectuée et validation restante

## Exécuté localement

- 22 tests Python : corrélation, cas négatifs, ordre d’arrivée, déduplication, redémarrage, contrôle d’audit, protection du rapport, génération des secrets, portée de la réponse et garde-fous de création des VM.
- 16 scénarios synthétiques comparant les catégories d’incident observées aux résultats attendus. Résultat : 16/16, voir `reports/regression.json`.
- Vérification des empreintes des neuf fichiers officiels Wazuh.
- Analyse XML des règles locales et groupes d’agents ; unicité et plage des identifiants de règles.
- Préparation d’un déploiement neuf avec mots de passe aléatoires et génération des sept propositions Netplan.
- Validation du Compose généré par `docker compose config --quiet`.
- Analyse des scripts d’installation avec `bash -n` sous Ubuntu WSL.
- Validation native du fichier de pare-feu par `nft --check --file`, sans installation ni application des règles.

Ces tests ne donnent pas un taux de détection sur le réseau d’une université. Les 16 scénarios ne constituent pas un corpus indépendant d’attaques réelles ; ils vérifient des exigences explicites du code.

## Non exécuté

- Téléchargement et démarrage de la pile Wazuh complète.
- Validation des règles par le véritable `wazuh-logtest` et remontée des événements par les agents.
- Validation native de Suricata, téléchargement ET Open et observation sur interfaces de VM.
- Acheminement de paquets, segmentation, blocage IPS et expiration réelle des entrées d’isolation.
- Tests des agents Windows/Sysmon, charge prolongée, sauvegarde/restauration et fonctionnement après redémarrage complet.
- Exécution des workflows GitHub Actions : ils sont fournis, mais aucun résultat distant n’est revendiqué.

La contrainte initiale de stockage sur C: a été résolue pour les VM grâce au disque USB G: choisi par l’utilisateur. Sept VM VirtualBox ESIem ont été créées, toutes éteintes. L’image Ubuntu est téléchargée et vérifiée, mais les systèmes invités n’ont pas encore démarré et Wazuh n’y est pas installé. La mémoire disponible ne permet pas actuellement de lancer le SOC ; l’utilisateur demande de reporter les démarrages à la campagne nocturne. Aucune règle de pare-feu n’a été appliquée au réseau de l’utilisateur. Voir `VIRTUALBOX_FR.md` et `OVERNIGHT_FR.md`.

## Reproduire les contrôles

```sh
python -m pip install -r requirements.txt
python -m unittest discover -v
python tools/check_config.py
python tools/evaluate.py
python -m campus prepare --output runtime/validation-soc
docker compose -f runtime/validation-soc/docker-compose.yml config --quiet
sudo nft --check --file infra/gateway/campus.nft
```

Pour les tests lourds : suivre `DEPLOYMENT_FR.md`, puis `ACCEPTANCE_FR.md`. Le workflow `wazuh-integration.yml` est déclenchable manuellement sur un dépôt GitHub disposant des actions ; il teste le manager, sans prétendre reproduire les flux entre toutes les VM.
