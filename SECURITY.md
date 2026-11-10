# Signalement et périmètre

Ce dépôt est un laboratoire. Il n’est pas déployé ni homologué pour surveiller le réseau réel d’un établissement.

Ne pas mettre de clés d’agent, mots de passe, certificats privés, adresses de personnes ou journaux réels dans une issue publique. En cas de secret publié, le révoquer sur le système concerné ; supprimer seulement sa ligne du dernier commit ne suffit pas.

Les comptes administrateur, les droits Docker et la politique de réponse active doivent être contrôlés par l’administrateur du laboratoire. La réponse est désactivée et simulée par défaut. Elle ne doit viser que les plages privées explicitement autorisées dans le laboratoire isolé.

Les configurations sont versionnées, mais les signatures ET Open et paquets système évoluent. Toute mise à jour demande les contrôles natifs puis les essais de non-régression. Les résultats détaillés sont consignés dans `docs/VALIDATION_FR.md`.
