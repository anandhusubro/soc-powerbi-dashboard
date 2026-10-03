import csv, random, json
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parent
rng = random.Random(42)
snapshot = datetime(2026, 10, 1)
rules = [
    ("Repeated authentication failures", "Identity", "T1110"),
    ("Suspicious PowerShell", "Endpoint", "T1059.001"),
    ("Periodic outbound connection", "Network", "T1071.001"),
    ("Large outbound transfer", "Network", "T1041"),
    ("Suspicious email attachment", "Email", "T1566.001"),
    ("Unusual remote access", "Identity", "T1078"),
]
rows = []
for i in range(1, 1501):
    created = datetime(2026, 9, 1) + timedelta(minutes=rng.randrange(30 * 24 * 60))
    severity = rng.choices(["Critical", "High", "Medium", "Low"], [8, 22, 45, 25])[0]
    target = {"Critical": 15, "High": 30, "Medium": 120, "Low": 240}[severity]
    rule, source, technique = rng.choice(rules)
    status = rng.choices(["Closed", "In Progress", "New"], [72, 18, 10])[0]
    ack = (
        created + timedelta(minutes=rng.randint(2, target * 3))
        if status != "New"
        else None
    )
    closed = (
        ack + timedelta(minutes=rng.randint(10, 1440)) if status == "Closed" else None
    )
    if ack and ack > snapshot:
        ack, closed, status = None, None, "New"
    if closed and closed > snapshot:
        closed, status = None, "In Progress"
    disposition = (
        rng.choices(
            ["True Positive", "False Positive", "Benign Positive"], [32, 48, 20]
        )[0]
        if status == "Closed"
        else "Pending"
    )
    ack_minutes = int((ack - created).total_seconds() / 60) if ack else None
    sla = (
        ("Met" if ack_minutes <= target else "Breached")
        if ack
        else (
            "Breached"
            if (snapshot - created).total_seconds() / 60 > target
            else "Pending"
        )
    )
    rows.append(
        dict(
            AlertID=f"ALT-{i:05}",
            CreatedAt=created.isoformat(" "),
            CreatedDate=created.date().isoformat(),
            AcknowledgedAt=ack.isoformat(" ") if ack else "",
            ClosedAt=closed.isoformat(" ") if closed else "",
            Severity=severity,
            SeverityOrder={"Critical": 1, "High": 2, "Medium": 3, "Low": 4}[severity],
            RuleName=rule,
            Source=source,
            MITRETechniqueCandidate=technique,
            Host=f"WS-{rng.randint(1,60):03}",
            Analyst=(
                rng.choice(["Analyst A", "Analyst B", "Analyst C", "Analyst D"])
                if ack
                else "Unassigned"
            ),
            Status=status,
            Disposition=disposition,
            AckTargetMinutes=target,
            AckMinutes=ack_minutes if ack else "",
            ResolutionMinutes=(
                int((closed - created).total_seconds() / 60) if closed else ""
            ),
            AckSLAStatus=sla,
            SnapshotAt=snapshot.isoformat(" "),
            DataOrigin="Synthetic",
        )
    )
with (ROOT / "soc_alerts.csv").open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
ack_values = [r["AckMinutes"] for r in rows if r["AckMinutes"] != ""]
resolution = [r["ResolutionMinutes"] for r in rows if r["ResolutionMinutes"] != ""]
closed_count = sum(r["Status"] == "Closed" for r in rows)
eligible = sum(r["AckSLAStatus"] != "Pending" for r in rows)
checks = {
    "total_alerts": len(rows),
    "status": dict(Counter(r["Status"] for r in rows)),
    "severity": dict(Counter(r["Severity"] for r in rows)),
    "ack_sla": dict(Counter(r["AckSLAStatus"] for r in rows)),
    "mean_ack_minutes": round(sum(ack_values) / len(ack_values), 2),
    "mean_resolution_minutes": round(sum(resolution) / len(resolution), 2),
    "false_positive_rate_closed": sum(
        r["Disposition"] == "False Positive" for r in rows
    )
    / closed_count,
    "ack_sla_compliance": sum(r["AckSLAStatus"] == "Met" for r in rows) / eligible,
}
assert len({r["AlertID"] for r in rows}) == 1500
assert all(r["Disposition"] == "Pending" for r in rows if r["Status"] != "Closed")
assert all(
    r["ResolutionMinutes"] >= r["AckMinutes"] for r in rows if r["Status"] == "Closed"
)
(ROOT / "validation_totals.json").write_text(json.dumps(checks, indent=2) + "\n")
print(json.dumps(checks, indent=2))
