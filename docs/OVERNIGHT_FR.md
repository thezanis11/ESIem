# Consignes pour la reprise autonome d’ESIem

> Document de préparation historique. Le signal de départ a ensuite été reçu et la campagne a été exécutée. Consulter `VALIDATION_FR.md` pour les résultats actuels et `VIRTUALBOX_FR.md` pour les commandes ; les constats ci-dessous décrivent l’état avant ce lancement.

## Choix confirmés par l’utilisateur

- Nom public : **ESIem**, en remplacement de Campus Sentinel.
- Réseau universitaire de laboratoire reconstitué : deux serveurs, postes, pare-feu, IDS/IPS et réseau externe simulé.
- Aucune VM ni aucun serveur distant n’était prêt ; création du laboratoire sur le PC.
- Utiliser le disque USB **G:**, dossier dédié `G:\ESIem-lab`.
- Prendre les décisions techniques courantes sans questions supplémentaires pendant la campagne de nuit.
- Ne pas démarrer les essais maintenant : l’utilisateur ne peut pas encore libérer la mémoire. Il prévoit de fermer ses applications avant le lancement nocturne.

## État de préparation

- Sept nouvelles VM VirtualBox créées et enregistrées, toutes éteintes.
- Disques vides dynamiques et réseaux internes, aucun réseau bridgé, aucun partage de dossier hôte.
- Fichiers de configuration VirtualBox sous `G:\ESIem-lab\ESIem\ESIem-<rôle>` ; les disques de données sont sous `G:\ESIem-lab\ESIem-<rôle>`.
- Image Ubuntu Server 24.04 officielle téléchargée dans `G:\ESIem-lab\images`, empreinte SHA-256 vérifiée ; signature GPG non vérifiée.
- Propositions Netplan avec correspondance des adresses MAC dans `runtime/netplan`.
- Les disques système Ubuntu et ISO NoCloud ne sont pas encore attachés. Le script de préparation s’est arrêté avant modification parce que VirtualBox insère le dossier du groupe dans le chemin de configuration. Le contrôle de chemin a été corrigé pour accepter précisément les deux emplacements attendus dans le dossier du laboratoire.
- Une clé SSH privée dédiée est présente dans `runtime/vm-access`, exclue de Git. Aucun mot de passe n’a été imprimé ou publié.
- Aucun premier démarrage invité, aucun service Wazuh et aucun essai IPS n’ont encore été exécutés dans ces VM.

## Procédure au signal de départ

1. Relire le manifeste privé `G:\ESIem-lab\ESIem-lab.json`, vérifier que le disque USB est monté et que les VM ciblées sont bien celles du laboratoire.
2. Vérifier la mémoire libre. Le SOC demande 8 Gio ; viser environ 10 Gio libres avant son démarrage pour garder une marge sur le PC. Ne pas démarrer les sept VM ensemble : leur budget total dépasse la RAM physique disponible une fois Windows compté.
3. Préparer les disques système avec `tools/seed_virtualbox.py`. Les accès privés restent dans runtime. Vérifier le contenu des ISO, la correspondance des cartes et la capacité des disques.
4. Choisir un premier essai réduit : SOC puis un endpoint. Vérifier le premier démarrage et `cloud-init status` avant de considérer Ubuntu prêt.
5. Pour les installations, ajouter si nécessaire une carte NAT temporaire uniquement aux nouvelles VM. Aucune connexion bridgée à un réseau réel. Retirer les chemins de contournement avant les tests réseau.
6. Installer la pile Wazuh épinglée, ses certificats et secrets uniques ; exécuter les contrôles natifs et enrôler un agent. Les sources sont copiées sous `/opt/campus-siem` par le disque NoCloud ; le nom technique du répertoire n’est pas le nom public du projet.
7. Procéder ensuite aux essais de segmentation et IDS/IPS par phases selon la mémoire disponible. Appliquer les règles seulement dans la VM passerelle dédiée. Conserver un accès console pour le retour arrière.
8. Corriger les problèmes rencontrés, relancer seulement les tests concernés puis la recette nécessaire. Consigner les observations réelles séparément des attentes synthétiques.
9. Mettre à jour les rapports et la documentation pour distinguer ce qui a effectivement réussi, échoué ou n’a pas pu être exécuté. Ne pas annoncer le laboratoire terminé tant que les essais requis ne sont pas établis.

## Limites d’intervention

Les choix techniques du laboratoire, ses téléchargements gratuits, son installation et ses essais sont autorisés. Les protections techniques de l’application continuent de s’appliquer. Ne pas les contourner ni modifier leur configuration pour éviter une confirmation.

Ne pas arrêter les applications de l’utilisateur, ses autres VM ou ses services WSL/Docker sans autorisation spécifique. Ne pas modifier le pare-feu du PC hôte, désactiver les protections Windows ou utiliser un hébergement payant pour résoudre une contrainte de ressources. Aucun accès au réseau réel de l’université.

Si une étape dépend d’une confirmation technique indisponible ou des ressources insuffisantes, conserver l’état, consigner le blocage et continuer les vérifications indépendantes possibles. Aucun secret, disque de VM, ISO d’initialisation ou journal réel ne doit être ajouté à un dépôt public.
