# Network Abuse Playbook

## Purpose

Contain IP-based abuse or anomalous network activity.

## Approved Actions

- BLOCK_WAF
- RUN_SSM

## Actions

1. Block the suspicious IP in AWS WAF.
2. Run the network containment SSM runbook for affected resources.

## Jira Guidance

- Summary: "Network Abuse Detected"
- Description: Include source IP, destination assets, and matching indicators.
