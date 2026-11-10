import html
import json
from datetime import datetime, timezone
from pathlib import Path


def write_report(incidents, audit, output):
    rows = []
    for item in sorted(incidents, key=lambda i: i["last_seen"], reverse=True):
        row = [item["severity"], item["detection"], item["asset"], item["source_ip"],
               str(item["evidence_count"]), item["explanation"], ", ".join(item["mitre"])]
        rows.append('<tr data-severity="' + html.escape(item["severity"], quote=True) + '">' +
                    "".join("<td>" + html.escape(value) + "</td>" for value in row) + "</tr>")
    document = """<!doctype html><html lang="fr"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESIem — Incidents</title>
<style>body{font:16px system-ui;background:#0c1424;color:#dce5f5;margin:0;padding:4vw}h1{font-size:2.8rem;margin-bottom:0.3em}
.tag{color:#70dfc8}p{max-width:85ch;line-height:1.6}table{border-collapse:collapse;width:100%;margin-top:2rem;font-size:.9rem}
td,th{padding:1rem;text-align:left;border-bottom:1px solid #293c56;vertical-align:top}th{color:#70dfc8}button,select{padding:.7rem;background:#1b2a40;color:white;border:1px solid #49617e;border-radius:5px}
.table{overflow:auto}code{word-break:break-all}footer{margin-top:3rem;color:#a9bad2}</style>
<p class="tag">RÉSEAU UNIVERSITAIRE / SUPERVISION DE SÉCURITÉ</p><h1>ESIem</h1>
<p>Extension de corrélation Wazuh. Les incidents sont des pistes d’investigation : ils ne constituent pas une preuve de compromission.
Ce rapport fonctionne hors ligne et n’envoie aucune donnée à un service externe.</p>
<label>Priorité <select id="priority"><option value="all">Toutes</option><option>critical</option><option>high</option><option>medium</option></select></label>
<p id="count"></p><div class="table"><table><thead><tr><th>Priorité</th><th>Détection</th><th>Actif</th><th>Source</th><th>Preuves</th><th>Motif</th><th>MITRE ATT&amp;CK</th></tr></thead>
<tbody>ROWS</tbody></table></div><footer>Audit local : RECORDS entrées · empreinte à conserver hors du serveur<br><code>HASH</code><p>La chaîne de hachage seule ne protège pas contre un administrateur qui réécrit toute la base.</p></footer>
<script>const s=document.querySelector('#priority');function filter(){let n=0;for(const r of document.querySelectorAll('tbody tr')){r.hidden=s.value!=='all'&&r.dataset.severity!==s.value;if(!r.hidden)n++;}document.querySelector('#count').textContent=n+' incident(s) affiché(s)';}s.onchange=filter;filter();</script></html>"""
    document = document.replace("ROWS", "".join(rows)).replace("RECORDS", str(audit["records"])).replace("HASH", audit["head_sha256"])
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(document, encoding="utf-8")
