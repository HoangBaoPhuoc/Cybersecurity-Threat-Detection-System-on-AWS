# Privileged Account Incident Response Playbook

## Purpose

Handle anomalous activity from privileged or administrative identities.

## Approved Actions

- RESTRICT_IAM
- RUN_SSM

## Actions

1. Immediately attach a deny-all policy to the impacted IAM user.
2. Execute the IAM containment SSM runbook for validation and rollback tracking.

## Jira Guidance

- Summary: "Privileged Access Anomaly"
- Description: Include user, role, and the specific anomalous activity.
