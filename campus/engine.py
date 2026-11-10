"""Deterministic, event-time correlation of *actual Wazuh alert schemas*.

No ML claim: thresholds are explicit hypotheses evaluated by regression cases.
SQLite transactions make checkpoints, evidence and incident updates atomic.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def timestamp(value):
    result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Event timestamp must include a timezone")
    return result.timestamp()


def normalize(alert, assets):
    ts = timestamp(alert["timestamp"])
    rule, data = alert.get("rule", {}), alert.get("data", {})
    groups = set(rule.get("groups", []))
    agent = alert.get("agent", {}).get("name", "unknown")
    src = data.get("srcip", data.get("src_ip", ""))
    if src:
        src = str(ipaddress.ip_address(src))
    asset = agent
    destination = data.get("dest_ip", "")
    if destination:
        asset = next((k for k, v in assets.items() if v["ip"] == destination), "unknown:" + destination)
    kind = "other"
    if "authentication_failed" in groups and "sshd" in groups:
        kind = "auth_failure"
    elif "authentication_success" in groups and "sshd" in groups:
        kind = "auth_success"
    elif "suricata" in groups:
        kind = "network"
    elif "syscheck" in groups:
        kind = "integrity"
    if kind in ("auth_failure", "auth_success", "integrity") and agent == "unknown":
        raise ValueError("Host alert has no agent name; refusing ambiguous cross-host correlation")
    if kind == "network" and (not src or not destination):
        raise ValueError("Network alert requires source and destination addresses")
    if destination:
        ipaddress.ip_address(destination)
    level = int(rule.get("level", 0))
    if not 0 <= level <= 16:
        raise ValueError("Invalid Wazuh rule level")
    return {
        "id": digest({"manager": alert.get("manager", {}).get("name", "local"),
                      "wazuh_id": alert.get("id"), "alert": alert}),
        "ts": ts, "kind": kind, "src": src, "asset": asset,
        "user": data.get("dstuser", data.get("srcuser", "")),
        "path": alert.get("syscheck", {}).get("path", ""),
        "level": level, "rule_id": str(rule.get("id", "")),
        "signature_id": str(data.get("alert", {}).get("signature_id", "")),
    }


class Engine:
    def __init__(self, database, assets, retention=86400):
        self.assets = assets
        self.retention = retention
        self.db = sqlite3.connect(database)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS events(
              id TEXT PRIMARY KEY, ts REAL, kind TEXT, src TEXT, asset TEXT,
              username TEXT, payload TEXT);
            CREATE INDEX IF NOT EXISTS event_lookup ON events(asset, ts);
            CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, payload TEXT);
            CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, payload TEXT, previous TEXT, hash TEXT);
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value REAL);
        """)

    def _audit(self, payload):
        last = self.db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        previous = last[0] if last else "0" * 64
        serialized = canonical(payload)
        hashed = hashlib.sha256((previous + serialized).encode()).hexdigest()
        self.db.execute("INSERT INTO audit(payload,previous,hash) VALUES (?,?,?)", (serialized, previous, hashed))

    def _incident(self, detection, events, severity, explanation, techniques):
        events = sorted(events, key=lambda e: (e["ts"], e["id"]))
        first = events[0]
        incident_id = digest([detection, first["asset"], first["src"], first["user"], first["id"]])[:24]
        payload = {"id": incident_id, "detection": detection, "asset": first["asset"],
                   "source_ip": first["src"], "username": first["user"], "severity": severity, "explanation": explanation,
                   "mitre": techniques, "first_seen": events[0]["ts"], "last_seen": events[-1]["ts"],
                   "evidence": [e["id"] for e in events[-20:]], "evidence_count": len(events),
                   "status": "open", "automatic_containment": False}
        self.proposals[incident_id] = payload

    def _save_incident(self, payload):
        incident_id = payload["id"]
        # A late earlier observation must not create a second copy of the same
        # overlapping episode merely because its first evidence hash changed.
        for existing in self.incidents():
            same_entity = all(existing.get(k) == payload.get(k) for k in ("detection", "asset", "source_ip", "username"))
            overlap = payload["first_seen"] <= existing["last_seen"] and existing["first_seen"] <= payload["last_seen"]
            if same_entity and overlap:
                incident_id = existing["id"]
                payload["id"] = incident_id
                payload["first_seen"] = min(payload["first_seen"], existing["first_seen"])
                payload["last_seen"] = max(payload["last_seen"], existing["last_seen"])
                evidence = list(dict.fromkeys(existing["evidence"] + payload["evidence"]))
                payload["evidence_count"] = max(existing["evidence_count"], payload["evidence_count"], len(evidence))
                payload["evidence"] = evidence[-20:]
                break
        old = self.db.execute("SELECT payload FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if old and json.loads(old[0]) == payload:
            return
        self.db.execute("INSERT OR REPLACE INTO incidents VALUES (?,?)", (incident_id, canonical(payload)))
        self._audit({"action": "incident_updated" if old else "incident_created", "incident": payload})

    def _correlate(self, asset, current):
        # Re-evaluate the affected event-time interval: delayed events can corroborate
        # observations already received. Never rescan the complete retention period.
        rows = self.db.execute("SELECT payload FROM events WHERE asset=? AND ts BETWEEN ? AND ? ORDER BY ts,id LIMIT 10001",
                               (asset, current - 1200, current + 600))
        events = [json.loads(r[0]) for r in rows]
        if len(events) > 10000:
            raise ValueError("Correlation density exceeds 10000 events per affected interval; transaction rolled back. Partition the feed or use a streaming backend.")
        for i, event in enumerate(events):
            if event["ts"] < current:
                continue
            preceding = events[:i + 1]
            if event["kind"] in ("auth_failure", "auth_success") and event["src"] and event["user"]:
                failures = [e for e in preceding if e["kind"] == "auth_failure"
                            and e["src"] == event["src"] and e["user"] == event["user"]
                            and 0 <= event["ts"] - e["ts"] <= (60 if event["kind"] == "auth_failure" else 120)]
                if len(failures) >= 5:
                    success = event["kind"] == "auth_success"
                    self._incident("login_after_failures" if success else "ssh_guessing", failures + ([event] if success else []),
                                   "critical" if success else "high",
                                   "Same source, account and host: successful login after repeated failures; investigate account ownership."
                                   if success else "At least five failures for the same source, account and host within 60 seconds.",
                                   ["T1110.001", "T1078"] if success else ["T1110.001"])
            if event["kind"] == "integrity":
                path = event["path"]
                sensitive = path in ("/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config") or path.startswith("/etc/sudoers.d/")
                if sensitive:
                    self._incident("sensitive_file_change", [event], "high", "Sensitive file modified; compare against approved maintenance.", ["T1098"])
                    logins = [e for e in preceding if e["kind"] == "auth_success" and 0 <= event["ts"] - e["ts"] <= 600]
                    if logins:
                        self._incident("login_then_integrity", [logins[-1], event], "critical",
                                       "Same host: sensitive file changed within ten minutes of SSH login. Temporal association is not proof of causation.", ["T1078", "T1098"])
            if event["kind"] == "network" and event["level"] >= 10:
                criticality = self.assets.get(asset, {}).get("criticality", 1)
                self._incident("network_alert", [event], "high" if criticality >= 3 else "medium",
                               "Network sensor alert; priority includes destination asset criticality. A signature match does not prove compromise.", [])
                matching = [e for e in preceding if e["kind"] in ("auth_failure", "auth_success")
                            and e["src"] == event["src"] and event["src"] and 0 <= event["ts"] - e["ts"] <= 300]
                if matching:
                    self._incident("network_host_corroboration", [matching[-1], event], "critical",
                                   "Independent host and network observations share source and destination asset within five minutes.", ["T1110"])

    def ingest(self, alert):
        event = normalize(alert, self.assets)
        with self.db:
            row = self.db.execute("SELECT value FROM meta WHERE key='watermark'").fetchone()
            watermark = max(event["ts"], row[0] if row else event["ts"])
            if event["ts"] < watermark - self.retention:
                raise ValueError("Event older than retention watermark; use a separate database for historical replay")
            cursor = self.db.execute("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?)",
                                     (event["id"], event["ts"], event["kind"], event["src"], event["asset"], event["user"], canonical(event)))
            if cursor.rowcount == 0:
                return False
            self.db.execute("INSERT OR REPLACE INTO meta VALUES ('watermark',?)", (watermark,))
            # Keep only the bounded correlation horizon, but preserve incidents and audit records.
            self.db.execute("DELETE FROM events WHERE ts < ?", (watermark - self.retention,))
            self.proposals = {}
            self._correlate(event["asset"], event["ts"])
            for proposal in self.proposals.values():
                self._save_incident(proposal)
        return True

    def incidents(self):
        return [json.loads(r[0]) for r in self.db.execute("SELECT payload FROM incidents ORDER BY id")]

    def verify_audit(self):
        previous = "0" * 64
        count = 0
        latest = {}
        for row in self.db.execute("SELECT * FROM audit ORDER BY seq"):
            expected = hashlib.sha256((previous + row["payload"]).encode()).hexdigest()
            if row["previous"] != previous or row["hash"] != expected:
                raise ValueError(f"Audit chain broken at record {row['seq']}")
            previous = row["hash"]
            count += 1
            payload = json.loads(row["payload"])
            latest[payload["incident"]["id"]] = payload["incident"]
        if latest != {i["id"]: i for i in self.incidents()}:
            raise ValueError("Incident table differs from the audited state")
        return {"records": count, "head_sha256": previous,
                "limit": "Requires an externally retained head hash to detect truncation or a fully rewritten chain."}

    def close(self):
        self.db.close()
