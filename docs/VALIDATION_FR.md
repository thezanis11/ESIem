# Validation exécutée — campagne des 10 et 11 novembre 2026

## Résultats

| Domaine | Contrôles réussis | Environnement et preuves |
|---|---:|---|
| Python | 24 | Windows et CI Linux ; isolation des clés entre agents incluse |
| Régression | 16 scénarios | Cas synthétiques positifs et négatifs ; `reports/regression.json` |
| Règles Wazuh | 5 | Véritable `wazuh-logtest` 4.14.10 ; CI et VM SOC ; `reports/wazuh-integration.json` |
| Intégration SIEM | 14 | Manager, indexer, dashboard et agent natifs ; `reports/stack-acceptance.json` |
| Réseau CI | 19 | Paquets traversant nftables et Suricata ; `reports/network-acceptance.json` |
| Réseau VirtualBox | 19 | Ubuntu 24.04.5, noyau 6.8.0-147-generic, 2 Gio, 1 vCPU ; `reports/virtualbox-network-acceptance.json` |
| Pile compacte VirtualBox | 14 | SOC à 3 712 Mio, 4 vCPU, agent de test à 256 Mio ; `reports/compact-stack-acceptance.json` |

La recette SIEM démontre : chargement des règles, fermeture du port d’enrôlement distant, TLS authentifié vers l’indexer et le dashboard, authentification d’un agent, réception de logs SSH, décodage EVE, remontée d’une modification de fichier, corrélation et recherche dans les index. Les événements capturés pendant la recette réseau sont rejoués dans le véritable agent et retrouvés dans l’indexer. Le serveur cible `portal` est résolu à partir de l’adresse de destination.

La recette réseau démontre : séparation étudiants/personnel, refus du WAN simulé, accès au portail, passage de la télémétrie, détection IDS sans blocage, blocage IPS avec preuve EVE `action=blocked`, arrêt du trafic en l’absence de consommateur NFQUEUE, retour arrière, isolation temporaire et maintien de la télémétrie. La durée de **300 secondes est réellement attendue**, sans suppression manuelle de l’entrée avant le test d’expiration.

Les résultats CI versionnés incluent leur lien de campagne et l’empreinte SHA-256 de l’artefact téléchargé. Les tentatives ayant échoué ne sont pas présentées comme des succès. Les contrôles de disponibilité font partie des nombres annoncés : il ne s’agit pas de 19 attaques ni de 14 familles de menaces.

## Origine des données

- Les 16 scénarios Python sont artificiels et vérifient des exigences explicites ; ils ne forment pas un dataset indépendant d’attaques.
- Les échecs SSH de la recette SIEM sont des lignes de test injectées dans le fichier lu par le véritable agent. Il ne s’agit pas d’une compromission d’un serveur.
- La modification du fichier surveillé est réellement effectuée, avec des commentaires n’accordant aucun nouveau privilège.
- Les trois événements de `tests/captured-eve.jsonl` viennent des vrais paquets HTTP de la recette réseau. Leurs marqueurs sont inoffensifs et connus. Le manifeste associé donne leur source et leur empreinte.
- Les adresses sont exclusivement celles du laboratoire ; aucune donnée du réseau réel de l’ESI n’a été collectée.

La réussite de ces contrôles prouve des fonctions de collecte, de traitement et de filtrage. Elle ne donne ni une précision de détection face à des menaces inconnues, ni une certification de sécurité.

## Corrections révélées par les essais

- En-tête YAML requis par Suricata après fusion de sa configuration.
- Sélection d’un mode NFQUEUE pris en charge, distinct du mode AF_PACKET.
- Serveur HTTP de contrôle concurrent pour ne pas confondre une connexion bloquée avec une panne du serveur.
- Conservation du service d’enrôlement local : désactiver tout `authd` désynchronisait les clés et la base d’agents. `remote_enrollment=no` ferme le listener TCP sans supprimer le socket local.
- Permissions des groupes personnalisés et de `merged.mg`, préparées après démarrage du manager.
- Groupes `suricata` et `syscheck` explicitement conservés sur les règles locales pour la corrélation des alertes natives.
- Suppression d’un faux échec de disponibilité causé par SIGPIPE entre `wazuh-control` et `grep -q`.
- Import d’une seule clé dans l’endpoint d’essai, même si le manager possède plusieurs agents.

## Incidents et contraintes locales

Sept VM VirtualBox et leurs disques Ubuntu ont été préparés sur le disque USB G:. Les VM SOC et passerelle ont effectué leur premier démarrage. La pile complète a été validée dans un runner GitHub Linux de 16 Go ; la machine Windows de développement ne pouvait pas allouer simultanément les budgets des sept VM.

Une première tentative réseau locale, avec une passerelle réduite à 1 Gio et 2 vCPU, a produit un soft lockup du noyau. L’arrêt ACPI n’a pas abouti ; seule cette VM dédiée a été arrêtée de force. Après reprise avec 2 Gio, 1 vCPU, arrêt des services concurrents et désactivation du socket de commande Suricata inutile aux tests, les 19 contrôles ont réussi. La cause précise n’est pas attribuée à un seul changement.

Les namespaces isolent les tables de filtrage et le routage des essais. La recette désactive le socket de commande Suricata pour éviter une collision avec une autre instance. La validation des checksums de capture est désactivée uniquement dans ce test sur interfaces veth, à cause des checksums partiels liés à l’offloading ; le profil de déploiement conserve ses réglages normaux.

Le profil compact a passé les 14 contrôles SIEM dans la VM SOC à 3 712 Mio et 4 vCPU, avec un agent conteneurisé plafonné à 256 Mio. L’instantané final relève zéro arrêt par manque de mémoire et zéro redémarrage des quatre conteneurs. Les pics individuels sur leur durée de vie sont conservés dans `reports/compact-resources.json` ; leur somme ne constitue pas un pic simultané. Il n’y avait pas de swap dans l’invité.

Il s’agit d’un essai court à faible charge, pas d’un dimensionnement pour une université. Le PC hôte est descendu à environ 1 Gio disponible, malgré la réserve de 2 Gio vérifiée avant démarrage : cette réserve initiale ne garantit pas une marge continue. Les VM ont été arrêtées proprement après la collecte des preuves. Le minimum officiel et le budget du laboratoire complet restent inchangés.

Un contrôle local de l’API du manager a aussi renvoyé HTTP 401 pour les identifiants par défaut `wazuh:wazuh`. Ce contrôle ponctuel complète les tests TLS ; il ne constitue pas un audit exhaustif des comptes ou des vulnérabilités.

## Hors du périmètre validé

- Sept systèmes invités actifs simultanément et une campagne prolongée à charge universitaire.
- Agents Windows/Sysmon, Active Directory et inspection du contenu de trafic TLS déchiffré.
- Mesure de l’efficacité des signatures ET Open : leur chargement et leur syntaxe sont vérifiés, mais les tests de paquets utilisent les marqueurs locaux.
- Déclenchement automatique de la réponse via `wazuh-execd` : la logique de réponse et le noyau sont testés directement dans un namespace ; le câblage automatique reste désactivé.
- Haute disponibilité, archivage immuable, restauration complète après sinistre et homologation de production.
- Audit exhaustif des vulnérabilités de toutes les images et dépendances système.

## Reproduire

```sh
python -m pip install -r requirements.txt
python -m unittest discover -v
python tools/check_config.py
python tools/evaluate.py
python -m campus prepare
docker compose -f runtime/soc/generate-indexer-certs.yml run --rm generator
docker compose -p campussentinel -f runtime/soc/docker-compose.yml up -d
python tools/test_full_stack.py
```

La recette de paquets exige un Linux jetable, Suricata/nftables/iproute2/PyYAML, root et `ESIEM_DISPOSABLE_LAB=1`. Le workflow `full-lab.yml` permet de lancer séparément `network`, `stack`, ou les deux. Il utilise des runners Linux standard dans un dépôt public, sans hébergement payant.
