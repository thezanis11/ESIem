# ESIem sur VirtualBox

## Préparation sur le PC

Le laboratoire est créé dans `G:\ESIem-lab`, sur le disque USB choisi par l’utilisateur. Il doit rester branché pendant les essais. La version locale utilisée pour la création est VirtualBox 7.2.4.

Sept machines distinctes : `ESIem-soc`, `ESIem-admin`, `ESIem-student01`, `ESIem-staff01`, `ESIem-portal`, `ESIem-files`, `ESIem-gateway`. La passerelle possède six interfaces. Les autres machines ont une interface chacune. Tous ces réseaux sont internes à VirtualBox ; aucune carte n’est bridgée vers le réseau physique et aucun dossier hôte n’est partagé.

Le PC dispose d’environ 15,3 Gio de RAM physique. La somme des budgets des VM est de 16 Gio, auxquels il faut ajouter Windows et les applications : **ne pas démarrer les sept machines ensemble sur ce PC**. Une première étape peut utiliser le SOC et un seul agent, après avoir libéré suffisamment de mémoire. Les essais de routage peuvent être réalisés dans une autre phase avec le SOC arrêté. Une démonstration simultanée de toute l’architecture demande un hôte mieux doté.

## Scripts reproductibles

Depuis la racine du projet, avec Python et les dépendances de préparation installés :

```powershell
python -m pip install -r requirements-lab.txt
python tools/virtualbox_lab.py --storage G:\ESIem-lab
# La commande ci-dessus montre le plan. Pour une NOUVELLE installation seulement :
python tools/virtualbox_lab.py --storage G:\ESIem-lab --create
python tools/fetch_ubuntu_image.py --storage G:\ESIem-lab
python tools/render_network.py --topology runtime/virtualbox-topology.json
python tools/seed_virtualbox.py --storage G:\ESIem-lab
```

Ne pas rejouer `--create` sur les machines déjà préparées : le script refuse les noms de VM existants et les dossiers non vides. Il ne remplace, ne supprime et ne démarre aucune machine existante. En cas d’échec partiel, lire le manifeste de progression avant toute réparation ; aucun nettoyage destructif automatique n’est effectué.

`seed_virtualbox.py` vérifie que chaque VM est éteinte et que son fichier de configuration appartient au répertoire exact du laboratoire. Il conserve les petits disques vides initiaux, clone un disque Ubuntu indépendant, agrandit sa capacité et attache un disque d’initialisation NoCloud. Aucune mémoire de VM n’est consommée avant son démarrage.

Sur Windows, les empreintes de mots de passe de console utilisent OpenSSL fourni avec Git ; WSL Ubuntu sert de solution de repli si ce binaire est absent. Sur Linux, le script utilise OpenSSL directement. La clé SSH et les mots de passe de console restent dans `runtime/vm-access`, exclu de Git. Ne pas publier ce dossier ni les ISO d’initialisation.

L’image VMDK officielle est convertie une seule fois en base VDI de 16 Gio, puis chaque VM reçoit une copie indépendante. Cela évite un conflit de registre VirtualBox avec l’UUID nul de certaines images VMDK. Le profil VirtualBox alloue donc au moins 16 Gio par disque système, même si le budget abstrait d’un petit endpoint indique 12 Gio.

## Système invité et accès

L’image Ubuntu Server 24.04 provient du [répertoire officiel des images publiées](https://cloud-images.ubuntu.com/releases/noble/release/). Son empreinte est vérifiée contre `SHA256SUMS`, obtenu par HTTPS. La signature GPG du manifeste n’a pas été vérifiée ; ne pas présenter cette étape comme une vérification de signature. L’URL, l’empreinte et la taille réellement utilisées sont conservées dans `G:\ESIem-lab\images\ubuntu-image.json`.

Au premier démarrage, [cloud-init NoCloud](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html) doit créer le compte `labadmin`, définir les noms et les adresses des interfaces par correspondance MAC, agrandir le système de fichiers et copier les sources du projet dans `/opt/campus-siem`. L’accès SSH par mot de passe et le compte root sont désactivés ; l’accès SSH utilise une clé. Un mot de passe de console unique permet l’administration locale par la console VirtualBox.

Ces étapes ne sont réputées réussies qu’après `cloud-init status --wait` et vérification dans l’invité. Disque attaché ne signifie pas premier démarrage effectué.

## Installation des services

Les machines préparées n’ont initialement aucun accès Internet. Pour installer les paquets, ajouter temporairement une carte NAT **uniquement aux nouvelles VM du laboratoire**, ou utiliser un dépôt miroir isolé. Ne pas remplacer une des interfaces de la passerelle : ses six cartes correspondent aux six zones. Retirer la carte temporaire et sa configuration après installation, avant la recette de segmentation.

L’activation des services Wazuh, l’enrôlement des agents, le chargement du pare-feu et la mise en mode IPS suivent `DEPLOYMENT_FR.md`. Ils ne sont pas effectués par la simple création des VM. La disponibilité mémoire est contrôlée avant tout démarrage.

Le fichier `G:\ESIem-lab\ESIem-lab.json` distingue les machines créées des disques Ubuntu préparés et du premier démarrage validé. Ne pas modifier ces états à la main pour présenter une recette comme réussie.
