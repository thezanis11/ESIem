# Attribution et licences

Campus Sentinel est une adaptation de laboratoire, sans affiliation officielle à Wazuh, à OISF ou à l’ESI.

- Les fichiers sous `vendor/wazuh-docker/` proviennent de [Wazuh Docker v4.14.10](https://github.com/wazuh/wazuh-docker/tree/v4.14.10). Ils sont conservés avec leur licence GPLv2, leurs notices et un manifeste des URL/empreintes. Les copies modifiées ne sont produites que dans `runtime/`, par `campus/deploy.py`.
- Wazuh manager, indexer et dashboard restent les produits de leurs auteurs respectifs. Les images ne sont pas redistribuées dans ce dépôt. Les licences et notices des composants qu’elles contiennent restent applicables.
- Suricata est fourni par OISF sous sa licence propre ; il est installé séparément depuis les paquets de la VM. Les règles ET Open sont téléchargées séparément par Suricata-Update. Conserver leurs notices et licences dans l’installation et les examiner avant redistribution.
- PyYAML 6.0.3 et bcrypt 5.0.0 sont des dépendances de préparation, installées depuis PyPI ; leurs distributions incluent leurs licences respectives.
- Les exemples SSH utilisent le format syslog standard documenté par Wazuh. Les événements de `tests/fixtures.py` sont synthétiques et ne proviennent ni de comptes étudiants ni d’une capture du réseau ESI.

Le code et les configurations propres à ce dépôt sont distribués sous GPL-2.0 pour rester cohérents avec les éléments Wazuh adaptés. Voir `LICENSE`.
