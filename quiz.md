# Quiz — AWS CloudTrail Audit Guide

5 questions. Answers are collapsed below each question — try first, then check.

---

## 1. The 90-day trap

Your team discovers a suspicious IAM change that happened **120 days ago**. You open the CloudTrail console event history and search for it. What happens?

<details>
<summary>Answer</summary>

You find nothing. Event history only keeps **90 days**. Anything older exists only if you stored it in your **S3 log archive** — which is exactly why the trail must deliver to S3 from day one. No archive, no evidence.

</details>

---

## 2. Who watches the watcher?

An attacker gains admin access and runs `DeleteTrail`, then `StopLogging`, to cover their tracks. Which of these saves you?

A. The trail's CloudWatch Logs delivery
B. The S3 log archive in a **separate logging account** with Object Lock
C. The 90-day event history
D. GuardDuty

<details>
<summary>Answer</summary>

**B.** The archive in a separate account with Object Lock (Compliance mode) can't be deleted by the compromised workload account — the evidence survives. A and C live in the same account and die with it; D detects threats but doesn't preserve logs.

</details>

---

## 3. Data events — the expensive default

You enable **data events** on your busiest S3 bucket "just to be safe". A month later the CloudTrail bill is bigger than the S3 bill. Why?

<details>
<summary>Answer</summary>

Data events are billed **per event**, and a busy bucket generates millions of object reads/writes. Management events (control-plane calls) are the cheap audit baseline; data events should be enabled **selectively** — only on buckets and Lambda functions you would actually investigate.

</details>

---

## 4. What does log file validation actually prove?

You run `validate-logs` and it reports all files valid. What does that guarantee?

<details>
<summary>Answer</summary>

That no log file was **modified or deleted in place** after CloudTrail wrote it — each file carries a signed digest, and validation recomputes it. It does **not** prove the trail was never disabled: if logging was off, there are simply no files for that period. Validation proves integrity of what exists, not completeness of what should exist.

</details>

---

## 5. Alarm on one, or alarm on many?

Your CloudWatch alarm for `DeleteTrail` is set to trigger after **5 occurrences in 10 minutes**, to "avoid false positives". What's wrong with this?

<details>
<summary>Answer</summary>

One `DeleteTrail` is already an emergency — nobody legitimately deletes the audit trail five times. Alarms on trail-tampering events (`StopLogging`, `DeleteTrail`, `UpdateTrail`, privilege escalation) should fire on **a single occurrence**. Thresholds belong on noisy metrics like queue depth, not on someone trying to blind you.

</details>

---

*Back to the [README](README.md).*
