# SOC Operations & Alert Triage Dashboard

A two-page Power BI dashboard for exploring SOC alert volume, open queues, acknowledgment SLA performance, and detection quality.

Built using Power BI, DAX, and 1,500 synthetic security alerts generated with Python.

> Portfolio simulation: all data is synthetic. This project is not connected to a live SIEM.

## Dashboard Preview

### SOC Overview
<img width="440" height="247" alt="image" src="https://github.com/user-attachments/assets/da6dfadd-2c55-477a-ac89-132875c85100" />


### Triage & Detection Quality
<img width="385" height="214" alt="image" src="https://github.com/user-attachments/assets/d7910b7b-1b5c-402a-80cd-ca813c7e30aa" />

## Dashboard Pages

### SOC Overview
- Total alerts, open alerts, and critical open alerts
- Mean acknowledgment time and acknowledgment SLA compliance
- Daily alert trends
- Alert volume by detection rule, severity, and source
- Date, severity, and source filters

### Triage & Detection Quality
- Closed alerts, false-positive rate, SLA breaches, and mean resolution time
- Open-alert queue with host, analyst, status, and SLA information
- Detection-rule comparison
- Analyst workload by alert status
- Rule, severity, and analyst filters

## Baseline Results

Results with filters and selections cleared:

| Metric | Value |
|---|---:|
| Total alerts | 1,500 |
| Open alerts | 454 |
| Critical open alerts | 31 |
| Closed alerts | 1,046 |
| Mean acknowledgment time | 181.2 minutes |
| Acknowledgment SLA compliance | 29.3% |
| SLA breaches | 1,057 |
| False-positive rate | 46.9% |
| Mean resolution time | 897.8 minutes |

Reporting period: September 2026.  
Snapshot: October 1, 2026, 00:00 UTC.

## Metric Definitions

- **Open alerts:** alerts with a status other than Closed.
- **False-positive rate:** false-positive closed alerts divided by all closed alerts.
- **Acknowledgment SLA compliance:** alerts meeting their acknowledgment target divided by eligible alerts. Pending alerts are excluded.
- **SLA breaches:** late acknowledgments and unacknowledged alerts overdue at the snapshot.
- **Mean acknowledgment time:** average creation-to-acknowledgment duration for acknowledged alerts.
- **Mean resolution time:** average creation-to-closure duration for closed alerts.

Simulated acknowledgment targets: Critical 15 minutes, High 30 minutes, Medium 120 minutes, and Low 240 minutes.

## Example Findings

Within this simulated dataset:
- 454 alerts remain open, including 31 critical alerts.
- Acknowledgment SLA compliance is 29.3%, suggesting a need to investigate queue delays and prioritization.
- Repeated authentication failures have a 52.3% false-positive rate among closed alerts, making the rule a candidate for further tuning analysis.

These observations demonstrate dashboard interpretation; they are not findings from a production SOC.

## Repository Files

| File | Purpose |
|---|---|
| SOC_Operations_Dashboard.pbix | Interactive Power BI report |
| SOC_Operations_Dashboard.pdf | Static dashboard preview |
| soc_alerts.csv | Synthetic alert dataset |
| measures.dax | DAX measure definitions |
| generate_data.py | Reproducible dataset generator |
| soc_theme.json | Power BI theme |

## How to Use

1. Download the repository files.
2. Open `SOC_Operations_Dashboard.pbix` in Power BI Desktop.
3. To refresh the data, update the CSV source path to your local `soc_alerts.csv`.
4. Clear filters and visual selections to view the baseline results.
5. Use the slicers to explore the alert queue and detection quality.

To regenerate the synthetic dataset, run:

    python generate_data.py

## Limitations

- Alerts are not equivalent to confirmed incidents.
- Acknowledgment time does not measure threat detection time.
- Resolution time measures alert closure, not containment or recovery.
- MITRE ATT&CK technique candidates require supporting investigation evidence.
- The SLA targets are fictional values used for this simulation.

## Skills Demonstrated

Power BI reporting, DAX, security metrics, alert prioritization, detection-quality analysis, Python data generation, and technical documentation.
