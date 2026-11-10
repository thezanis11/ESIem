# Déploiement du laboratoire

## 1. Inventorier l’hôte

Exécuter `sh tools/host_inventory.sh` sur le futur serveur Linux et relever la mémoire, les cœurs, l’espace disque physique et la version Docker. Si le serveur est un hyperviseur Windows, relever ces valeurs dans ses paramètres. Ne pas envoyer de mots de passe, clés SSH ou fichiers `credentials.json` dans une conversation.

Le PC ayant servi à écrire ce projet ne disposait pas d’assez d’espace pour tirer les images Wazuh. Le disque virtuel WSL annonce une capacité bien supérieure à l’espace physique restant : cela ne permet pas d’y déployer la pile.

Budget proposé :

| VM | vCPU | RAM | Disque |
|---|---:|---:|---:|
| SOC | 4 | 8 Gio | 60 Go |
| Passerelle | 2 | 2 Gio | 16 Go |
| Portail | 1 | 1 Gio | 16 Go |
| Fichiers SSH/SFTP | 1 | 1 Gio | 16 Go |
| Étudiant | 1 | 1 Gio | 12 Go |
| Personnel | 1 | 1 Gio | 12 Go |
| Administration facultative | 2 | 2 Gio | 16 Go |

Prévoir de la marge pour l’hyperviseur, les mises à jour et les instantanés. Le SOC seul peut servir à commencer la collecte d’une VM avant de créer toutes les autres. Un poste Windows facultatif demande un budget supérieur et une licence appropriée ; il n’est pas nécessaire au profil Linux fourni.

## 2. Créer les réseaux et les VM

Créer cinq commutateurs virtuels isolés : management, students, staff, dmz et servers. Créer un sixième commutateur isolé pour le WAN simulé `192.0.2.0/24`. Ne pas les relier à la carte du réseau universitaire.

La passerelle reçoit six cartes réseau, une par commutateur. Chaque autre VM ne reçoit qu’une carte dans sa zone. Une deuxième carte NAT peut servir temporairement à installer les paquets, puis doit être retirée avant les essais pour éviter un contournement du pare-feu.

Installer Ubuntu Server 24.04 LTS. Choisir les noms d’hôte exacts `portal`, `files`, `student01`, `staff01` et `gateway`, ou adapter `config/assets.json`. Activer OpenSSH uniquement avec un compte de laboratoire et une clé SSH. Le serveur `files` utilise le sous-système SFTP fourni par OpenSSH ; il ne joue pas le rôle d’un annuaire Active Directory.

Le plan figure dans `config/lab-topology.json`. Vérifier les noms des interfaces avec `ip -br link` sur chaque VM : `ens3` à `ens8` sont des hypothèses. Modifier le plan et les références correspondantes de `infra/gateway/campus.nft` et du service Suricata si nécessaire.

Générer les propositions de fichiers réseau :

```sh
python tools/render_network.py
```

Depuis la **console de chaque VM**, copier uniquement son fichier dans `/etc/netplan/60-campus.yaml`, lui donner le mode `0600`, puis utiliser `sudo netplan try`. Vérifier les fichiers existants : ne pas conserver deux configurations contradictoires pour la même interface. Ne pas appliquer ces fichiers au PC principal. Les fichiers ne configurent ni DNS externe ni accès Internet ; les essais utilisent les adresses IP. Synchroniser les horloges des VM avec l’hyperviseur avant les tests.

## 3. Installer le SOC

Installer Docker Engine et le module Compose depuis [la documentation Docker pour Ubuntu](https://docs.docker.com/engine/install/ubuntu/). Le compte ayant accès à Docker dispose de droits équivalents à l’administration de l’hôte.

Copier le projet sur la VM SOC, préparer l’environnement Python puis générer une configuration neuve :

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m campus preflight
python -m campus prepare --manager-bind 10.77.10.10
```

Contrôler `runtime/soc/PROVENANCE.json`. Les secrets ne sont pas imprimés. Le fichier `runtime/soc/credentials.json` doit rester sur cette VM. Le générateur refuse de réutiliser un dossier existant pour éviter une rotation incohérente des secrets.

Wazuh exige `vm.max_map_count` d’au moins `262144`. Sur cette VM dédiée :

```sh
sudo sysctl -w vm.max_map_count=262144
docker compose -f runtime/soc/generate-indexer-certs.yml run --rm generator
docker compose -p campussentinel -f runtime/soc/docker-compose.yml config --quiet
docker compose -p campussentinel -f runtime/soc/docker-compose.yml up -d
docker compose -p campussentinel -f runtime/soc/docker-compose.yml ps
python tools/test_wazuh.py
```

Après validation, rendre le réglage noyau persistant via un fichier dédié dans `/etc/sysctl.d/`. Les téléchargements sont effectués avant l’isolement final des VM. Les certificats produits sont propres au laboratoire. Les flux manager-indexer et dashboard-indexer utilisent TLS ; l’agent Wazuh utilise son protocole sécurisé et sa clé propre.

L’indexer n’a aucun port publié. L’API est accessible seulement en boucle locale sur le SOC et l’interface est en boucle locale sur le port 8443. Depuis le poste d’administration, ouvrir un tunnel SSH vers le SOC :

```sh
ssh -L 8443:127.0.0.1:8443 utilisateur@10.77.10.10
```

Pour vérifier aussi le nom du certificat, faire résoudre `wazuh.dashboard` vers `127.0.0.1` sur le poste d’administration et ouvrir `https://wazuh.dashboard:8443`. Faire approuver l’autorité de certification du laboratoire selon la procédure du système. Ne pas désactiver globalement la vérification TLS du navigateur. Utiliser le compte `admin` uniquement pour l’installation et créer ensuite des comptes nominatifs de lecture/analyse dans l’interface Wazuh.

Le profil généré garde l’accès au flux éditeur de vulnérabilités désactivé. L’activer seulement après autorisation des flux sortants et vérification des ressources. Wazuh ne devient pas hautement disponible avec cette pile sur un hôte unique.

## 4. Installer et enrôler les agents

Sur chaque endpoint Ubuntu, pendant la phase d’installation avec accès aux dépôts :

```sh
sudo bash infra/agents/install-agent.sh
```

Ce script configure le dépôt signé de Wazuh, installe l’agent `4.14.10-1`, l’audit Linux et la collecte système. Le gel du paquet évite un changement majeur imprévu ; les mises à jour de sécurité restent une opération à planifier et à retester. Il ne remplace pas la configuration réseau de la VM.

L’enrôlement réseau sur TCP 1515 est fermé. Utiliser l’enrôlement par clé hors ligne :

1. Sur le SOC, ouvrir l’outil interactif du manager :

   ```sh
   docker compose -p campussentinel -f runtime/soc/docker-compose.yml exec wazuh.manager /var/ossec/bin/manage_agents
   ```

2. Ajouter le nom et l’adresse de l’agent, puis extraire sa clé unique. La clé est un secret ; ne pas l’enregistrer dans Git ni dans une capture publiée.
3. Sur l’endpoint, lancer `sudo /var/ossec/bin/manage_agents`, importer cette clé dans l’outil interactif, puis `sudo systemctl enable --now wazuh-agent`. L’outil interactif évite de mettre la clé dans l’historique des commandes.
4. Sur le manager, affecter les groupes avec les identifiants réels des agents :

   ```sh
   docker compose -p campussentinel -f runtime/soc/docker-compose.yml exec -T wazuh.manager /var/ossec/bin/agent_groups -a -i 001 -g linux -q
   ```

   La passerelle reçoit les groupes `linux` **et** `gateway`. Les autres VM Ubuntu reçoivent `linux`. Vérifier les groupes et leur synchronisation avec `agent_groups -s -i 001` et `agent_groups -S -i 001`.

Les configurations sont montées par le chemin de personnalisation officiel `/wazuh-config-mount`, puis copiées par l’image du manager dans son volume de configuration. Vérifier leur présence effective après le premier démarrage. Ne pas modifier uniquement le volume à la main : ces modifications seraient difficiles à reproduire.

Une automatisation Ansible facultative est fournie dans `infra/ansible/`. Elle exige un poste d’administration avec Ansible, les clés SSH des VM et un inventaire adapté. Elle copie uniquement les sources nécessaires et installe les rôles Ubuntu ; elle ne crée pas les VM, ne modifie pas leur réseau et n’importe pas les secrets des agents. Le playbook n’a pas encore été exécuté sur un parc de VM.

Pour Windows : installer l’agent officiel compatible, importer une clé unique, affecter `windows`, activer la stratégie d’audit adaptée. Sysmon est facultatif et doit être installé séparément depuis Microsoft ; sa présence n’est pas simulée par le fichier `agent.conf`. La corrélation Campus Sentinel de cette version cible SSH/Linux ; les alertes Windows restent consultables dans Wazuh.

## 5. Préparer les deux serveurs

Sur `portal` : `sudo bash infra/portal/install-portal.sh`. Vérifier `curl http://10.77.40.10/` depuis le poste personnel. HTTP est ici intentionnel pour observer les marqueurs IDS/IPS, sans données personnelles. Un portail réel exige TLS et la sonde ne verrait alors pas les URI sans point de déchiffrement approprié.

Sur `files`, le service SSH/SFTP de l’installation Ubuntu est suffisant. Créer un compte d’essai séparé de l’administrateur pour les tests d’authentification. N’utiliser que des identifiants de laboratoire. Ne pas ouvrir SSH aux étudiants : le filtrage l’interdit volontairement.

## 6. Passerelle : commencer en IDS

Sur `gateway`, installer les fichiers :

```sh
sudo bash infra/gateway/install-gateway.sh
```

Le script télécharge les règles ET Open via Suricata-Update, conserve l’empreinte du fichier de règles et les informations de construction, puis lance les contrôles de syntaxe. Il ne charge pas le pare-feu et ne modifie pas les interfaces.

Depuis la console de la VM : vérifier les interfaces et l’accès SSH du poste d’administration, puis :

```sh
sudo sysctl -w net.ipv4.ip_forward=1
sudo systemctl disable --now suricata
sudo systemctl enable --now campus-suricata
sudo nft --check --file /etc/campus/campus.nft
sudo nft --file /etc/campus/campus.nft
```

Le service fourni capture initialement la carte DMZ `ens7` en IDS. Le service Suricata de distribution est arrêté pour éviter deux processus concurrents. Le pare-feu est chargé comme une nouvelle table `inet campus`, sans vider les autres tables. Sur un hôte déjà configuré, une autre table peut encore bloquer un flux accepté ici : d’où l’usage d’une VM dédiée.

Pour remplacer une table existante, utiliser une transaction nftables préparée depuis la console, après sauvegarde. Ne pas rejouer aveuglément le fichier de création sur une table déjà présente. Après recette, conserver la configuration validée et le réglage de forwarding pour le redémarrage de cette VM.

## 7. Passer de l’IDS à l’IPS

Après les essais IDS réussis, créer `/etc/default/campus-suricata` contenant `CAPTURE_ARGS="-q 0"`, puis redémarrer `campus-suricata`. Vérifier son état. La sonde attend maintenant la file NFQUEUE ; activer ensuite la chaîne de traitement :

```sh
sudo nft add rule inet campus ips queue num 0
```

La chaîne IPS passe après le filtrage. Seuls les paquets ayant franchi le pare-feu sont inspectés. Il n’y a volontairement pas d’option `bypass` : en l’absence de Suricata, le trafic transféré s’arrête. Tester et documenter ce comportement avant de laisser le profil IPS actif.

Pour revenir au filtrage sans IPS, depuis la console : `sudo nft flush chain inet campus ips`. Cela vide uniquement la chaîne IPS du laboratoire. Revenir ensuite à `CAPTURE_ARGS="-i ens7"` et redémarrer le service pour retrouver l’IDS passif. Ne pas vider le pare-feu entier.

Les règles ET Open contiennent surtout des alertes : leur installation **ne les transforme pas toutes en blocages**. Le seul blocage explicite fourni est le marqueur inoffensif `9900002`. Toute conversion supplémentaire en règle `drop` demande un essai des faux positifs et un plan de retour arrière.

## 8. Corrélation et exploitation

Sur le SOC, après la collecte réelle d’alertes :

```sh
python tools/collect_alerts.py
python -m campus audit
python -m campus report
```

Le collecteur importe un instantané du fichier courant `alerts.json`. Les imports répétés sont dédupliqués. Il doit être lancé avant la rotation journalière des journaux ; pour une exploitation continue, planifier une exécution régulière sur le SOC et vérifier son code de retour. Une analyse d’archives utilise une base distincte pour ne pas se heurter à la fenêtre de rétention du flux courant. Ne pas importer les fixtures de démonstration dans la base des événements réels.

Pour une exécution toutes les trente secondes, installer les fichiers `infra/soc/campus-collect.service` et `.timer` dans `/etc/systemd/system/`, après avoir placé le projet et son environnement Python dans `/opt/campus-siem`. Créer le dossier runtime au mode `0700`, vérifier les chemins, puis activer le timer avec `sudo systemctl enable --now campus-collect.timer`. Vérifier `systemctl list-timers` et `journalctl -u campus-collect.service`. Le service possède les droits Docker de l’administrateur ; ne pas l’exposer par une API réseau. Ses limites de mémoire et de durée conviennent à un petit laboratoire, pas à une charge inconnue.

Conserver l’empreinte finale de l’audit hors de l’hôte. Restreindre l’accès au dossier `runtime`. La base contient des comptes, adresses et références de preuve qui ne doivent pas apparaître dans un dépôt public.

## 9. Réponse active facultative

La recette de l’IPS ne nécessite pas la réponse active Wazuh. Pour tester celle-ci ensuite, copier le projet dans `/opt/campus-siem` sur la passerelle, installer le lanceur `infra/agents/campus-response` dans `/var/ossec/active-response/bin/` avec propriétaire root et groupe wazuh, mode `0750`. Copier `config/response-policy.json` dans `/etc/campus/`, propriétaire root et mode `0640`.

Le fichier garde `execute: false`. Le lanceur écrit les propositions dans `active-responses.log`. Ajouter au manager le contenu de `wazuh/active-response.example.xml` en adaptant l’identifiant réel de la passerelle. Le bloc reste désactivé jusqu’à la recette en simulation. La réponse doit cibler **uniquement cet agent passerelle**.

Après les tests, l’activation exige de modifier explicitement la politique locale et le bloc du manager. L’exécution refuse les plages externes, l’infrastructure, les comptes/règles non autorisés et les durées autres que 300 secondes. Le noyau expire l’entrée `quarantine_v4` après cinq minutes, même si le script s’arrête. Les paquets de télémétrie vers le manager restent autorisés ; vérifier aussi le retour des réponses dans la recette. La réponse n’est pas une isolation de niveau hyperviseur et n’empêche pas les échanges entre deux machines du même sous-réseau qui ne traversent pas la passerelle.

## 10. Rétention, sauvegarde et arrêt

Le fichier `config/retention-policy.json` propose une politique OpenSearch ISM de 14 jours sur les index d’alertes. Il n’est pas appliqué automatiquement : l’administrateur doit examiner sa portée, l’installer dans Index Management et vérifier qu’elle est attachée aux index prévus. [Référence ISM officielle](https://docs.opensearch.org/latest/im-plugin/ism/index/). Cela ne purge ni les fichiers du manager ni la base SQLite.

Surveiller les volumes, réserver une limite disque au laboratoire, examiner les journaux quotidiennement et prévoir un archivage. Les événements de corrélation sont conservés 24 h ; incidents et audit sont conservés jusqu’à archivage manuel. Cette version ne fournit pas d’archivage immuable ni de purge automatisée de ces deux tables. Pour sauvegarder SQLite pendant l’usage, utiliser l’API de sauvegarde SQLite ou arrêter le collecteur ; une copie isolée du fichier sans son journal WAL peut être incohérente.

Sauvegarder les clés des agents, les certificats, les volumes du manager/indexer et la base avec un stockage chiffré hors de la VM. Documenter un test de restauration. Ne jamais sauvegarder ces éléments dans GitHub.

Arrêter sans effacer les données :

```sh
docker compose -p campussentinel -f runtime/soc/docker-compose.yml down
```

L’option `--volumes` effacerait les volumes : elle est réservée à un laboratoire jetable explicitement abandonné. Sur la passerelle, supprimer seulement la chaîne IPS avant l’arrêt de Suricata afin de conserver les communications administratives du laboratoire.
