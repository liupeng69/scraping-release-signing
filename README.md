# Scraping release signing authority

This public repository is the purpose-separated signing authority for bounded
staging deployments from the private `scraping-repo/scraping` repository. It
does not contain or mirror candidate source.

Current cycle roles:

- operator: `liupeng69` (GitHub user ID `30068489`)
- reviewer: `jiayanBayes` (GitHub user ID `33464549`)
- signing environment: `release-signing`

Both mutation workflows run only from protected `main`, require the
`release-signing` environment, reject an actor other than the current operator,
and use keyless GitHub/AWS OIDC. The reviewer approves the environment job and
cannot approve a run she triggered herself. A role swap requires a reviewed
change to this repository and a new candidate in the private repository.

`publish-generic-crawl-activation.yml` creates two independent Ed25519 keys,
publishes the source-bound signed activation and the outbound-capability private
key to two exact AWS Secrets Manager names, and uploads only a redacted receipt.
The activation bundle is written last and its SHA-256 is the deployment input.
The two Secret containers span candidates: their tags contain only stable
project, environment, and ownership metadata. Candidate identity is bound by
the signed content, deterministic version token, VersionId, and receipts, never
by a `CandidateSha` container tag. The private workload Terraform root later
imports only the outbound-key container metadata; this repository remains the
only value/version writer. On an existing container, publication first removes
only the legacy `CandidateSha` tag through the exact-ARN,
`aws:TagKeys=[CandidateSha]`-restricted `UntagResource` permission; the cleanup
is idempotent and occurs before the new version is written.

`authorize-generic-crawl-release.yml` produces the short-lived guardian receipt
after Workload Apply, creates a GitHub build-provenance attestation for that
exact receipt, and uploads only the receipt. A separately owned governance
repository must add its independent custom attestation before Release.

The repository contains no long-lived AWS key and accepts no caller-selected
AWS account, region, secret name, environment, or deployment target.
