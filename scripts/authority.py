#!/usr/bin/env python3
"""Generate the bounded staging activation and guardian subjects.

The script intentionally has no dependency on the private candidate repository.
All candidate bindings are explicit workflow inputs reviewed at the protected
environment boundary. Secret publication belongs to the workflow's narrow AWS
OIDC role; this module never calls AWS and never prints private key bytes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Final, NoReturn


SHA_RE: Final = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE: Final = re.compile(r"^[0-9a-f]{64}$")
RUN_RE: Final = re.compile(r"^[1-9][0-9]{0,19}$")
ATTEMPT_RE: Final = re.compile(r"^[1-9][0-9]{0,9}$")
UUID_RE: Final = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
SIGNATURE_DOMAIN: Final = b"nlp-generic-execution-activation.v1\x00"
ACTIVATION_VALIDITY_SECONDS: Final = 7 * 86_400
GUARDIAN_VALIDITY_SECONDS: Final = 6 * 3_600
MIN_GUARDIAN_REMAINING_SECONDS: Final = 7_200
TARGET_ID: Final = "generic-crawl-lane"
ACCOUNT_ID: Final = "116208987955"
REGION: Final = "us-west-2"
CLUSTER: Final = "sp-stg-sbx"
NAMESPACE: Final = "scraping-staging"
HELM_RELEASE: Final = "scraping-platform"
SIGNER_REPOSITORY: Final = "liupeng69/scraping-release-signing"
SIGNER_REPOSITORY_ID: Final = 1_351_773_155
OPERATOR_LOGIN: Final = "liupeng69"
OPERATOR_ID: Final = "30068489"
REVIEWER_LOGIN: Final = "jiayanBayes"
REVIEWER_ID: Final = "33464549"


class AuthorityError(ValueError):
    """The proposed authority subject is malformed or exceeds its bounds."""


def _reject(message: str) -> NoReturn:
    raise AuthorityError(message)


def _reject_from(message: str, exc: Exception) -> NoReturn:
    raise AuthorityError(message) from exc


def _canonical(value: object, *, pretty: bool = False) -> bytes:
    options: dict[str, object] = {
        "allow_nan": False,
        "ensure_ascii": True,
        "sort_keys": True,
    }
    if pretty:
        options["indent"] = 2
    else:
        options["separators"] = (",", ":")
    return (json.dumps(value, **options) + "\n").encode("ascii")


def _claims_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _write_new(path: Path, raw: bytes, *, mode: int = 0o600) -> None:
    if path.exists() or path.is_symlink():
        _reject(f"refusing to replace output: {path.name}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _require(value: str, pattern: re.Pattern[str], label: str) -> str:
    if pattern.fullmatch(value) is None:
        _reject(f"{label} invalid")
    return value


def _openssl(*arguments: str) -> None:
    try:
        completed = subprocess.run(
            ["openssl", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        _reject_from("OpenSSL execution failed", exc)
    if completed.returncode != 0:
        _reject("OpenSSL rejected the Ed25519 operation")


def _new_ed25519(private_path: Path, public_path: Path) -> None:
    _openssl("genpkey", "-algorithm", "ED25519", "-out", str(private_path))
    os.chmod(private_path, 0o600)
    _openssl(
        "pkey",
        "-in",
        str(private_path),
        "-pubout",
        "-out",
        str(public_path),
    )
    os.chmod(public_path, 0o600)


def _proofs(arguments: argparse.Namespace) -> dict[str, str]:
    result = {
        "hostile_network": arguments.hostile_network_proof_sha256,
        "evidence_lifecycle": arguments.evidence_lifecycle_proof_sha256,
        "provider_governance": arguments.provider_governance_proof_sha256,
        "durable_network_budget": arguments.durable_network_budget_proof_sha256,
        "real_postgres_execution": arguments.real_postgres_execution_proof_sha256,
    }
    for name, digest in result.items():
        _require(digest, DIGEST_RE, f"{name} proof SHA-256")
    if len(set(result.values())) != len(result):
        _reject("the five proof SHA-256 values must be distinct")
    return result


def create_activation(arguments: argparse.Namespace) -> dict[str, object]:
    candidate = _require(arguments.candidate_sha, SHA_RE, "candidate SHA")
    target_sha = _require(
        arguments.functional_target_sha256,
        DIGEST_RE,
        "functional target SHA-256",
    )
    values_sha = _require(
        arguments.functional_target_values_sha256,
        DIGEST_RE,
        "functional target values SHA-256",
    )
    run_id = _require(arguments.run_id, RUN_RE, "run ID")
    run_attempt = _require(arguments.run_attempt, ATTEMPT_RE, "run attempt")
    proofs = _proofs(arguments)
    issued = int(time.time()) if arguments.now_unix is None else arguments.now_unix
    if issued < 1:
        _reject("authority time invalid")
    expires = issued + ACTIVATION_VALIDITY_SECONDS
    output = arguments.output_dir
    output.mkdir(mode=0o700, parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="activation-", dir=output) as temporary:
        root = Path(temporary)
        activation_private = root / "activation-private.pem"
        activation_public = root / "activation-public.pem"
        outbound_private = root / "outbound-private.pem"
        outbound_public = root / "outbound-public.pem"
        claims_path = root / "claims.bin"
        signature_path = root / "signature.bin"
        _new_ed25519(activation_private, activation_public)
        _new_ed25519(outbound_private, outbound_public)

        key_id = f"staging-generic-crawl:{candidate[:12]}:{run_id}"
        claims: dict[str, object] = {
            "environment": "staging",
            "source_revision": candidate,
            "approval_id": f"github:{SIGNER_REPOSITORY}:actions:{run_id}:{run_attempt}",
            "outbound_network_policy_version": "outbound_network_capability.v1",
            "workload_network_policy_version": "nlp_generic_crawl_egress.v1",
            "sensitive_evidence_lifecycle_version": "sensitive_intent_evidence.v1",
            "sensitive_evidence_key_authority_version": (
                "sensitive_evidence_key_authority.aws_kms_dynamodb.v1"
            ),
            "provider_governance_version": "nlp_provider_governance.v1",
            "hostile_network_proof_sha256": proofs["hostile_network"],
            "evidence_lifecycle_proof_sha256": proofs["evidence_lifecycle"],
            "provider_governance_proof_sha256": proofs["provider_governance"],
            "durable_network_budget_proof_sha256": proofs[
                "durable_network_budget"
            ],
            "real_postgres_execution_proof_sha256": proofs[
                "real_postgres_execution"
            ],
            "browser_execution_enabled": False,
            "approved_at_unix": issued,
            "expires_at_unix": expires,
            "schema_version": "nlp_generic_execution_activation.v1",
        }
        claims_path.write_bytes(SIGNATURE_DOMAIN + _claims_bytes(claims))
        os.chmod(claims_path, 0o600)
        _openssl(
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(activation_private),
            "-in",
            str(claims_path),
            "-out",
            str(signature_path),
        )
        signature = base64.urlsafe_b64encode(signature_path.read_bytes()).decode(
            "ascii"
        ).rstrip("=")
        if len(signature) != 86:
            _reject("Ed25519 signature encoding invalid")
        activation_public_pem = activation_public.read_text(encoding="ascii")
        outbound_public_pem = outbound_public.read_text(encoding="ascii")
        if activation_public_pem == outbound_public_pem:
            _reject("activation and outbound keys are not independent")
        signed = {
            "key_id": key_id,
            "claims": claims,
            "signature": signature,
            "schema_version": "signed_nlp_generic_execution_activation.v1",
        }
        bundle = {
            "schema_version": "operator_staging_generic_crawl_activation_bundle.v1",
            "candidate_sha": candidate,
            "functional_target_id": TARGET_ID,
            "functional_target_sha256": target_sha,
            "functional_target_values_sha256": values_sha,
            "signed_activation": signed,
            "activation_public_keys": {key_id: activation_public_pem},
        }
        bundle_raw = _canonical(bundle, pretty=True)
        outbound_raw = outbound_private.read_bytes()
        bundle_sha = hashlib.sha256(bundle_raw).hexdigest()
        outbound_private_sha = hashlib.sha256(outbound_raw).hexdigest()
        activation_public_sha = hashlib.sha256(
            activation_public_pem.encode("ascii")
        ).hexdigest()
        outbound_public_sha = hashlib.sha256(
            outbound_public_pem.encode("ascii")
        ).hexdigest()
        if activation_public_sha == outbound_public_sha:
            _reject("activation and outbound public-key digests are not independent")
        receipt: dict[str, object] = {
            "schema_version": "scraping_release_signing_activation_generation.v1",
            "candidate_sha": candidate,
            "functional_target_id": TARGET_ID,
            "functional_target_sha256": target_sha,
            "functional_target_values_sha256": values_sha,
            "operator": {"login": OPERATOR_LOGIN, "id": OPERATOR_ID},
            "reviewer": {"login": REVIEWER_LOGIN, "id": REVIEWER_ID},
            "signer_repository": SIGNER_REPOSITORY,
            "signer_repository_id": SIGNER_REPOSITORY_ID,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "approved_at_unix": issued,
            "expires_at_unix": expires,
            "proof_sha256": proofs,
            "activation_key_id": key_id,
            "activation_public_key_sha256": activation_public_sha,
            "outbound_capability_key_id": "orchestrator-outbound-network-capability-v1",
            "outbound_capability_public_key_sha256": outbound_public_sha,
            "outbound_private_key_sha256": outbound_private_sha,
            "activation_bundle_sha256": bundle_sha,
        }
        receipt["receipt_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
        _write_new(output / "activation-bundle.json", bundle_raw)
        _write_new(output / "outbound-private-key.pem", outbound_raw)
        _write_new(output / "activation-generation-receipt.json", _canonical(receipt, pretty=True))
        return receipt


def create_guardian(arguments: argparse.Namespace) -> dict[str, object]:
    candidate = _require(arguments.candidate_sha, SHA_RE, "candidate SHA")
    digests = {
        "functional_target_sha256": arguments.functional_target_sha256,
        "functional_target_values_sha256": arguments.functional_target_values_sha256,
        "image_inventory_sha256": arguments.image_inventory_sha256,
        "activation_receipt_sha256": arguments.activation_receipt_sha256,
        "activation_bundle_sha256": arguments.activation_bundle_sha256,
    }
    for name, digest in digests.items():
        _require(digest, DIGEST_RE, name)
    workload_run_id = _require(
        arguments.workload_apply_run_id, RUN_RE, "workload Apply run ID"
    )
    guardian_run_id = _require(arguments.run_id, RUN_RE, "guardian run ID")
    guardian_attempt = _require(
        arguments.run_attempt, ATTEMPT_RE, "guardian run attempt"
    )
    namespace_uid = _require(arguments.namespace_uid, UUID_RE, "namespace UID")
    workflow_commit = _require(arguments.workflow_commit, SHA_RE, "workflow commit")
    issued = int(time.time()) if arguments.now_unix is None else arguments.now_unix
    activation_expires = arguments.activation_expires_at_unix
    if issued < 1 or activation_expires <= issued + MIN_GUARDIAN_REMAINING_SECONDS:
        _reject("activation validity is too short for a guardian handoff")
    expires = min(issued + GUARDIAN_VALIDITY_SECONDS, activation_expires)
    bundle_binding = {
        "schema_version": "operator_staging_generic_crawl_guardian_bundle.v1",
        "candidate_sha": candidate,
        "functional_target_id": TARGET_ID,
        **digests,
        "workload_apply_run_id": workload_run_id,
        "namespace_uid": namespace_uid,
        "signer_repository": SIGNER_REPOSITORY,
        "signer_repository_id": SIGNER_REPOSITORY_ID,
        "signer_workflow_commit": workflow_commit,
        "operator": {"login": OPERATOR_LOGIN, "id": OPERATOR_ID},
        "reviewer": {"login": REVIEWER_LOGIN, "id": REVIEWER_ID},
    }
    receipt: dict[str, object] = {
        "schema_version": "operator_staging_generic_crawl_guardian_receipt.v1",
        "candidate_sha": candidate,
        "functional_target_id": TARGET_ID,
        **digests,
        "workload_apply_run_id": workload_run_id,
        "guardian_install_run_id": guardian_run_id,
        "guardian_install_run_attempt": guardian_attempt,
        "guardian_policy_mode": "two_generation_exact_release_identity",
        "release_identity_schema": "operator_staging_generic_crawl_release_identity.v1",
        "aws_account_id": ACCOUNT_ID,
        "aws_region": REGION,
        "cluster_name": CLUSTER,
        "namespace": NAMESPACE,
        "namespace_uid": namespace_uid,
        "helm_release": HELM_RELEASE,
        "issued_at_unix": issued,
        "expires_at_unix": expires,
        "guardian_bundle_sha256": hashlib.sha256(
            _canonical(bundle_binding)
        ).hexdigest(),
    }
    receipt["receipt_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
    _write_new(arguments.output, _canonical(receipt, pretty=True))
    return receipt


def _add_digest_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--functional-target-sha256", required=True)
    parser.add_argument("--functional-target-values-sha256", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    activation = commands.add_parser("activation")
    _add_digest_arguments(activation)
    activation.add_argument("--hostile-network-proof-sha256", required=True)
    activation.add_argument("--evidence-lifecycle-proof-sha256", required=True)
    activation.add_argument("--provider-governance-proof-sha256", required=True)
    activation.add_argument("--durable-network-budget-proof-sha256", required=True)
    activation.add_argument("--real-postgres-execution-proof-sha256", required=True)
    activation.add_argument("--run-id", required=True)
    activation.add_argument("--run-attempt", required=True)
    activation.add_argument("--now-unix", type=int)
    activation.add_argument("--output-dir", type=Path, required=True)
    guardian = commands.add_parser("guardian")
    _add_digest_arguments(guardian)
    guardian.add_argument("--image-inventory-sha256", required=True)
    guardian.add_argument("--activation-receipt-sha256", required=True)
    guardian.add_argument("--activation-bundle-sha256", required=True)
    guardian.add_argument("--activation-expires-at-unix", type=int, required=True)
    guardian.add_argument("--workload-apply-run-id", required=True)
    guardian.add_argument("--namespace-uid", required=True)
    guardian.add_argument("--workflow-commit", required=True)
    guardian.add_argument("--run-id", required=True)
    guardian.add_argument("--run-attempt", required=True)
    guardian.add_argument("--now-unix", type=int)
    guardian.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    result = (
        create_activation(arguments)
        if arguments.command == "activation"
        else create_guardian(arguments)
    )
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError, ValueError) as exc:
        print(f"release authority rejected: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
