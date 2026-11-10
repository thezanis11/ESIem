# Méthode et limites

## Origine et périmètre

L’utilisateur se souvient d’un réseau universitaire interne, de deux serveurs, de postes, d’un pare-feu, d’un IDS/IPS et d’un accès externe. Le reste de l’architecture a été conçu pour ce laboratoire ; aucune topologie historique n’a été retrouvée ou prétendue exacte. Les rôles portail et fichiers sont des choix nouveaux et modifiables.

La pile amont utilisée est Wazuh Docker `v4.14.10`. Les neuf fichiers référencés par `vendor/wazuh-docker/MANIFEST.json` restent inchangés. Le générateur vérifie leurs empreintes avant de produire une copie privée adaptée. Les règles locales réutilisent les décodeurs SSH, JSON et intégrité existants : créer artificiellement de nouveaux décodeurs n’apporterait rien aux formats déjà pris en charge.

## Chemin des données

1. L’agent lit les journaux et événements d’intégrité de sa VM.
2. Le manager authentifie l’agent et analyse les événements avec les règles Wazuh, puis les règles locales.
3. Les alertes sont indexées et consultables dans le dashboard.
4. L’extension lit les alertes JSON, pas les réponses attendues des tests. Elle conserve une représentation normalisée dans SQLite et crée des incidents.
5. Le rapport contient des références d’événements et les raisons de chaque rapprochement. L’analyste revient aux alertes originales dans Wazuh pour enquêter.

La criticité est déclarative dans `config/assets.json`. Le rapprochement réseau-hôte repose sur l’adresse de destination et le nom de l’agent : les noms doivent correspondre exactement. Ne pas faire de NAT entre les segments internes ; sinon le lien de source peut être perdu. Un flux vers une destination inconnue reste inconnu et n’hérite pas de la criticité d’un serveur connu.

## Hypothèses de détection

| Détection | Condition | Limite principale |
|---|---|---|
| SSH guessing | Au moins 5 échecs, même IP, compte et hôte, en 60 s | N’identifie pas le password spraying distribué |
| Login après échecs | Succès après au moins 5 échecs liés en 120 s | Peut être l’utilisateur légitime qui a corrigé son mot de passe |
| Fichier sensible | Changement sur un chemin précis de comptes, sudo ou SSH | La maintenance autorisée doit être vérifiée par l’analyste |
| Login puis intégrité | Même hôte, login dans les 600 s précédentes | Association temporelle, sans attribution du processus ayant modifié le fichier |
| Réseau prioritaire | Alerte réseau de niveau Wazuh ≥ 10 | La qualité dépend des signatures et du contexte local |
| Réseau + hôte | Même source et actif, observation SSH dans les 300 s avant l’alerte réseau | Pas de preuve de causalité ni de campagne attribuée |

Les incidents chevauchants de même type et même entité sont fusionnés. Les identifiants d’incident sont stables dans une base, mais peuvent dépendre de l’ordre d’arrivée lors d’événements retardés ; comparer les détections et les preuves, pas une identité universelle entre bases indépendantes. Au maximum vingt références de preuve sont incluses dans un incident ; la quantité indiquée est une borne informative issue des fenêtres observées, pas un compteur exact de toutes les tentatives d’une campagne longue.

Les techniques MITRE ATT&CK sont des correspondances d’ingénierie de détection, pas une qualification d’attaque confirmée. L’inventaire, la SCA et les événements Windows utilisent les fonctions de Wazuh ; ils ne sont pas tous recouverts par la corrélation SSH/Linux de cette première version.

## Temps, reprise et capacité

Les dates doivent inclure un fuseau horaire. L’événement est dédupliqué à partir de son contenu canonique, de l’identifiant Wazuh et du manager. La rétention des événements normalisés est de 24 h relativement au plus grand horodatage reçu. Les événements plus anciens sont refusés explicitement ; utiliser une base dédiée pour une analyse historique. Une horloge source erronée très en avance peut déplacer cette référence et nécessite une investigation.

À chaque événement, l’extension réévalue l’intervalle affecté pour tenir compte des arrivées retardées. La lecture de contexte est bornée à 10 000 événements par intervalle et actif. Au-delà, la transaction échoue explicitement ; elle ne supprime pas silencieusement les événements en excès. Le code favorise la lisibilité pour un petit laboratoire et n’a pas de capacité industrielle mesurée. En cas de charge élevée, partitionner les flux ou utiliser un moteur de streaming adapté.

La déduplication, l’incident et son audit sont enregistrés dans la même transaction. Les incidents/audits ne sont pas purgés automatiquement. L’ingestion d’un fichier s’arrête sur la première ligne mal formée en indiquant son numéro ; les lignes valides déjà traitées restent validées et leur réimportation est dédupliquée. Cela permet de corriger la source puis de reprendre, sans masquer les erreurs.

## Intégrité et confidentialité

Chaque modification d’incident reçoit une empreinte chaînée. La vérification contrôle aussi la cohérence de la table d’incidents avec le dernier état audité. Un administrateur contrôlant toute la base peut réécrire la chaîne ou la tronquer : conserver périodiquement l’empreinte finale sur un autre système est nécessaire. Les événements normalisés eux-mêmes ne sont pas un journal cryptographiquement immuable.

Les différences de contenu des fichiers sensibles ne sont pas collectées. Aucune vraie donnée étudiante n’est fournie. Les fixtures sont construites artificiellement au format des alertes Wazuh. L’accès au dossier runtime et la durée de conservation doivent être adaptés avant toute utilisation réelle.

## Sources primaires

- [Architecture Wazuh](https://documentation.wazuh.com/current/getting-started/architecture.html)
- [Déploiement Docker et prérequis](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)
- [Personnalisation Docker](https://documentation.wazuh.com/current/deployment-options/docker/container-usage.html)
- [Modification des mots de passe](https://documentation.wazuh.com/current/deployment-options/docker/changing-default-password.html)
- [Tests des règles et décodeurs](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
- [Référence wazuh-logtest](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
- [Groupes d’agents](https://documentation.wazuh.com/current/user-manual/reference/tools/agent-groups.html)
- [Réponse active personnalisée](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)
- [Règles Suricata-Update](https://docs.suricata.io/en/suricata-8.0.3/rule-management/suricata-update.html)
- [IPS Linux et NFQUEUE](https://docs.suricata.io/en/suricata-8.0.1/ips/setting-up-ipsinline-for-linux.html)

Les références « current » peuvent évoluer. Pour reproduire le profil Wazuh, utiliser le numéro de version et le manifeste du dépôt ; pour Suricata/ET Open, conserver les versions et l’empreinte réellement installées dans la campagne de recette.
