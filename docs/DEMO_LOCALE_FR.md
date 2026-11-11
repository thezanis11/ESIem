# Reprendre ESIem sur le PC de développement

## Voir les résultats sans démarrer de VM

Ouvrir `reports/validated-incidents.html` dans un navigateur. Ce rapport autonome contient six incidents de la recette native. Il indique l’origine de laboratoire des événements ; il ne représente pas une intrusion réelle à l’ESI. Les rapports JSON voisins donnent les contrôles et leurs campagnes GitHub.

## Démarrer seulement le SOC déjà préparé

Le disque USB G: doit être branché. Les sept VM sont conservées ; ne pas les recréer et ne pas lancer `prepare` dans le déploiement existant. La passerelle et les cinq autres VM restent arrêtées pour cette démonstration. Depuis la racine du projet, avec les dépendances `requirements-lab.txt` disponibles :

```powershell
python tools/bootstrap_vm.py soc --memory-mib 3712 --start
python tools/vm_ssh.py soc --command "sudo docker ps --format '{{.Names}} {{.Status}}'"
```

Le script refuse le démarrage si la mémoire libre initiale est insuffisante. Laisser quelques minutes aux services pour redémarrer. Le contrôle initial de mémoire ne garantit pas la marge pendant l’exécution : arrêter le laboratoire si Windows manque de mémoire. Le profil compact n’est validé que pour un petit essai, avec un seul agent conteneurisé.

Pour rejouer la recette, qui injecte de nouveaux événements de laboratoire et modifie un fichier surveillé dans l’agent dédié :

```powershell
python tools/vm_ssh.py soc --command "cd /opt/campus-siem && sudo .venv/bin/python tools/test_full_stack.py --endpoint-memory 256m"
python tools/vm_ssh.py soc --command "cd /opt/campus-siem && sudo .venv/bin/python tools/snapshot_resources.py"
```

Les nouveaux résultats restent dans `reports/local-*` dans la VM. Ils ne remplacent pas automatiquement les preuves versionnées de la campagne initiale.

## Accès au dashboard

La redirection SSH de la VM est limitée à `127.0.0.1:22011`. Depuis la racine du projet, ouvrir un second terminal et garder ce tunnel actif :

```powershell
ssh -i runtime/vm-access/id_ed25519 -o UserKnownHostsFile=runtime/vm-access/known_hosts -p 22011 -N -L 127.0.0.1:8443:127.0.0.1:8443 labadmin@127.0.0.1
```

Le dashboard est alors joignable par le tunnel sur le port local 8443. Son certificat de laboratoire est émis pour `wazuh.dashboard`, pas pour `localhost`. Un accès navigateur avec vérification complète nécessite de faire correspondre ce nom à `127.0.0.1` sur le poste et de lui faire reconnaître l’autorité du laboratoire, selon les instructions TLS du guide de déploiement. Aucun changement de confiance ou de résolution de nom n’a été appliqué automatiquement au PC.

Les vrais identifiants de cette VM ont été sauvegardés localement dans **`runtime/vm-access/soc-credentials.json`** : l’utilisateur du dashboard est `admin`, avec la valeur du champ `admin`. Ce fichier est privé, ignoré par Git et distinct de l’ancien fichier de préparation Windows `runtime/soc/credentials.json`. Ne pas le copier dans un rapport, une capture publique ou un dépôt. La clé SSH et les mots de passe de console sont également privés dans `runtime/vm-access`.

## Arrêter proprement

```powershell
python tools/vm_ssh.py soc --command "sudo shutdown -h now"
```

Les volumes Docker, alertes et disques sont conservés. Attendre que VirtualBox affiche la VM éteinte avant de débrancher G:. Fermer ensuite le terminal du tunnel. Ne pas utiliser une commande de suppression de volumes pour arrêter une démonstration.
