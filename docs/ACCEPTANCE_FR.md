# Recette : preuves à produire sur les VM

Créer un dossier local privé pour chaque campagne et noter : date, versions exactes, horloges, interfaces, empreinte ET Open, règles chargées et profil IDS ou IPS. Publier seulement un résumé anonymisé. Les lignes ci-dessous sont des **critères attendus**, pas des résultats déjà obtenus.

| Test | Action dans le laboratoire | Résultat à vérifier |
|---|---|---|
| Wazuh natif | `python tools/test_wazuh.py` sur le SOC | Configuration chargée ; règles et décodeurs attendus pour les cinq exemples |
| Agents | Vérifier état et synchronisation des groupes | Chaque VM remonte sous son nom et son identifiant uniques |
| Collecte SSH | Une connexion volontairement refusée sur files depuis staff01 | Alerte SSH dans Wazuh avec source, compte et hôte corrects |
| Seuil négatif | Moins de cinq échecs pour le même compte | Pas d’incident `ssh_guessing` dans l’extension |
| Seuil positif | Cinq échecs espacés de 5 s pour le même compte de test | Incident `ssh_guessing` ; garder les identifiants des événements |
| Connexion réussie | Se connecter au même compte après ces essais | `login_after_failures` ; vérifier l’authenticité de la connexion |
| Autre compte | Réussite sur un compte différent | Pas d’association avec les échecs du premier compte |
| Intégrité | Modifier de manière réversible un fichier d’essai sous `/etc/sudoers.d/`, sans y ajouter de droits | Alerte d’intégrité et incident sensible ; restaurer depuis la console |
| Hôte différent | Login sur files, changement sur portal | Pas de corrélation login/intégrité entre les deux machines |
| Segmentation | Étudiant vers files:22 | Refus par le pare-feu ; pas de tentative SSH reçue par files |
| Accès autorisé | Personnel vers files:22 et portail HTTP | Accès possible, hors règles de détection actives |
| Accès SOC | Étudiant vers indexer/API/interface | Refus ; l’indexer ne publie aucun port et l’interface reste locale |
| IDS positif | Depuis student01 : `curl --max-time 3 http://10.77.40.10/campus-ids-test` | Réponse HTTP reçue ET alerte Suricata 9900001 dans Wazuh |
| IDS non bloquant | En profil IDS : requête `/campus-ips-test` | Alerte 9900002 ; constater qu’un `drop` en IDS passif ne coupe pas le trafic |
| IPS positif | En profil IPS : requête `/campus-ips-test` | Blocage observé + action blocked dans EVE ; consigner la réponse ou le délai réel |
| IPS négatif | En profil IPS : requête `/` | Réponse HTTP normale, pas de blocage du portail entier |
| Arrêt sonde IPS | Depuis la console, arrêter Suricata avec NFQUEUE actif | Arrêt du trafic transféré attendu ; retirer seulement la règle de queue pour restaurer |
| Événement retardé | Rejouer le cas synthétique dédié dans une base de test | Rapprochement retrouvé sans double incident |
| Redémarrage corrélation | Réimporter le même instantané après arrêt | Événements dédupliqués et audit cohérent |
| Réponse simulée | Déclencher une règle autorisée depuis la plage étudiants | Proposition journalisée ; aucune entrée dans quarantine_v4 |
| Réponse exécutée, facultative | Activer sur la passerelle dédiée après simulation | Entrée avec expiration ; portée limitée au poste concerné |
| Expiration | Attendre plus de 300 s | Entrée disparue sans intervention du script |
| Adresse protégée | Soumettre un cas visant une adresse SOC/administration | Refus de la proposition et aucun changement nftables |
| Reprise et sauvegarde | Restaurer une copie du laboratoire isolé | Configuration, clés et données cohérentes ; preuves documentées |

Le fichier de sudoers d’essai doit être syntaxiquement valide et vide de nouveaux droits : utiliser par exemple un fichier composé uniquement de commentaires, vérifier avec `visudo -cf`, puis le supprimer. Ne pas modifier `/etc/shadow` ou les droits du compte administrateur pour une démonstration.

Une alerte dans l’interface ne prouve pas un blocage. Vérifier à la fois le trafic, la décision EVE et la règle appliquée. Inversement, un délai HTTP peut venir du routage ou du serveur : vérifier le témoin `/`, les journaux et la disponibilité de nginx.

Après les essais, produire `reports/local-acceptance.json` avec les résultats observés, les horodatages et les références d’événements. Le modèle `config/acceptance-template.json` commence à `not_run` pour chaque composant. Ne passer un champ à `passed` qu’avec la preuve correspondante.
