#!/usr/bin/env python3
"""AWS CloudTrail Audit Guide — investigate like an incident responder.

What this demo does:
  1. Looks up the riskiest API calls of the last 24 hours (StopLogging,
     DeleteTrail, ConsoleLogin failures, ...).
  2. Runs an Athena query over the S3 log archive to find who tampered
     with the trail.
  3. Validates CloudTrail log-file integrity (digest check).

Usage:
    python audit.py            # offline simulator demo (no AWS needed)
    python audit.py --live     # real AWS (needs boto3 + credentials)

Live mode needs an IAM identity with cloudtrail:LookupEvents,
athena:StartQueryExecution / GetQueryResults, s3:GetObject on the
archive bucket, and cloudtrail:ValidateLogs.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone

# --- The events worth waking someone up for -------------------------------
RISKY_EVENTS = [
    "StopLogging",          # someone is trying to blind you
    "DeleteTrail",          # ... or delete the evidence
    "UpdateTrail",          # trail config changed (logging off?)
    "ConsoleLogin",         # failed logins = brute force
    "CreateUser",
    "PutUserPolicy",        # privilege escalation
    "AttachUserPolicy",
    "AuthorizeSecurityGroupIngress",  # 0.0.0.0/0 opened?
    "CreateAccessKey",
    "PutBucketPolicy",      # tampering with the log archive itself
]

ATHENA_TAMPER_QUERY = """
SELECT eventtime, useridentity.arn AS who, sourceipaddress AS ip,
       eventname, errorcode
FROM cloudtrail_logs
WHERE eventname IN ('StopLogging', 'DeleteTrail', 'UpdateTrail')
  AND eventtime >= date_add('day', -7, now())
ORDER BY eventtime DESC
LIMIT 20
""".strip()


# --- Offline simulator (no AWS credentials needed) -----------------------
def simulate_lookup() -> list[dict]:
    """Fake CloudTrail LookupEvents results for the last 24 hours."""
    now = datetime.now(timezone.utc)
    sample = [
        {
            "EventTime": now - timedelta(hours=2, minutes=14),
            "Username": "alice-admin",
            "EventName": "ConsoleLogin",
            "CloudTrailEvent": json.dumps(
                {"responseElements": {"ConsoleLogin": "Success"},
                 "sourceIPAddress": "203.0.113.42"}
            ),
        },
        {
            "EventTime": now - timedelta(hours=5, minutes=3),
            "Username": "root",
            "EventName": "ConsoleLogin",
            "CloudTrailEvent": json.dumps(
                {"responseElements": {"ConsoleLogin": "Failure"},
                 "errorMessage": "Failed authentication",
                 "sourceIPAddress": "198.51.100.7"}
            ),
        },
        {
            "EventTime": now - timedelta(hours=9, minutes=41),
            "Username": "deploy-bot",
            "EventName": "AuthorizeSecurityGroupIngress",
            "CloudTrailEvent": json.dumps(
                {"requestParameters": {"ipPermissions": {"items": [
                    {"ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                     "fromPort": 22, "toPort": 22}]}},
                 "sourceIPAddress": "203.0.113.10"}
            ),
        },
    ]
    return [e for e in sample if e["EventName"] in RISKY_EVENTS]


def simulate_athena() -> list[dict]:
    """Fake Athena results: nobody tampered with the trail this week."""
    return []


def simulate_validate() -> dict:
    return {
        "trail": "org-audit-trail",
        "region": "ap-southeast-1",
        "files_checked": 288,
        "valid": 288,
        "invalid": 0,
    }


# --- Live AWS mode --------------------------------------------------------
def live_lookup(cloudtrail, hours: int = 24) -> list[dict]:
    """LookupEvents for every risky event name in the last N hours."""
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    found = []
    for name in RISKY_EVENTS:
        resp = cloudtrail.lookup_events(
            LookupAttributes=[
                {"AttributeKey": "EventName", "AttributeValue": name}
            ],
            StartTime=start,
            MaxResults=10,
        )
        found.extend(resp.get("Events", []))
    return sorted(found, key=lambda e: e["EventTime"], reverse=True)


def live_athena(athena, database: str, output_bucket: str) -> list[dict]:
    """Run the tamper query against the Athena table over the archive."""
    qid = athena.start_query_execution(
        QueryString=ATHENA_TAMPER_QUERY,
        QueryExecutionContext={"Database": database},
        ResultConfiguration={"OutputLocation": output_bucket},
    )["QueryExecutionId"]
    while True:
        state = athena.get_query_execution(QueryExecutionId=qid)
        status = state["QueryExecution"]["Status"]["State"]
        if status in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(2)
    if status != "SUCCEEDED":
        raise RuntimeError(f"Athena query {status}")
    rows = athena.get_query_results(QueryExecutionId=qid)["ResultSet"]["Rows"]
    header = [c["VarCharValue"] for c in rows[0]["Data"]]
    return [
        dict(zip(header, [c.get("VarCharValue", "") for c in r["Data"]]))
        for r in rows[1:]
    ]


def live_validate(cloudtrail, trail_arn: str, start: datetime) -> dict:
    """Validate log-file digests for the last 24h (prints progress)."""
    cloudtrail.validate_logs(
        TrailARN=trail_arn, StartTime=start, Verbose=False
    )
    return {"note": "validate-logs ran; check the printed validation output"}


# --- Presentation ---------------------------------------------------------
def print_events(events: list[dict]) -> None:
    if not events:
        print("  (none — quiet 24 hours, good)")
        return
    for e in events:
        detail = json.loads(e["CloudTrailEvent"])
        ip = detail.get("sourceIPAddress", "?")
        print(f"  - {e['EventTime']}  {e['Username']:<14} {e['EventName']:<32} from {ip}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true",
                        help="use real AWS (boto3 + credentials)")
    parser.add_argument("--database", default="cloudtrail_db",
                        help="Athena database for the archive table")
    parser.add_argument("--output-bucket", default="s3://athena-results/",
                        help="Athena query results location")
    parser.add_argument("--trail-arn", default="",
                        help="Trail ARN for validate-logs (live mode)")
    args = parser.parse_args()

    print("=" * 68)
    print("CloudTrail audit — last 24 hours")
    print("=" * 68)

    if args.live:
        import boto3  # noqa: PLC0415  (only needed for live mode)

        ct = boto3.client("cloudtrail")
        ath = boto3.client("athena")
        print("\n[1] Risky events (LookupEvents):")
        print_events(live_lookup(ct))
        print("\n[2] Trail tampering, last 7 days (Athena over S3 archive):")
        rows = live_athena(ath, args.database, args.output_bucket)
        if rows:
            for r in rows:
                print(f"  - {r}")
        else:
            print("  (none — nobody touched the trail)")
        if args.trail_arn:
            print("\n[3] Log-file validation:")
            print(" ", live_validate(ct, args.trail_arn,
                                     datetime.now(timezone.utc) - timedelta(hours=24)))
        else:
            print("\n[3] Log-file validation: skipped (pass --trail-arn)")
    else:
        print("(offline simulator — run with --live against real AWS)\n")
        print("[1] Risky events (LookupEvents):")
        print_events(simulate_lookup())
        print("\n[2] Trail tampering, last 7 days (Athena over S3 archive):")
        rows = simulate_athena()
        print("  (none — nobody touched the trail)" if not rows else rows)
        print("\n[3] Log-file validation:")
        v = simulate_validate()
        print(f"  {v['trail']} ({v['region']}): "
              f"{v['valid']}/{v['files_checked']} files valid, "
              f"{v['invalid']} invalid")

    print("\nDone. If [1] or [2] is non-empty, treat it as an incident, "
          "not a curiosity.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
