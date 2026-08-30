from __future__ import annotations

from argparse import Namespace
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


_AUTHORITY_PATH = Path(__file__).resolve().parents[1] / "scripts" / "authority.py"
_SPEC = importlib.util.spec_from_file_location("release_signing_authority", _AUTHORITY_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("authority module unavailable")
authority = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(authority)


CANDIDATE = "a" * 40
DIGESTS = [f"{index:064x}" for index in range(1, 9)]
NOW = 1_788_000_000


def _activation_args(tmp_path: Path) -> Namespace:
    return Namespace(
        candidate_sha=CANDIDATE,
        functional_target_sha256=DIGESTS[0],
        functional_target_values_sha256=DIGESTS[1],
        hostile_network_proof_sha256=DIGESTS[2],
        evidence_lifecycle_proof_sha256=DIGESTS[3],
        provider_governance_proof_sha256=DIGESTS[4],
        durable_network_budget_proof_sha256=DIGESTS[5],
        real_postgres_execution_proof_sha256=DIGESTS[6],
        run_id="123",
        run_attempt="1",
        now_unix=NOW,
        output_dir=tmp_path,
    )


class AuthorityTests(unittest.TestCase):
    def test_activation_is_canonical_source_bound_and_key_separated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = authority.create_activation(_activation_args(root))
            bundle_raw = (root / "activation-bundle.json").read_bytes()
            bundle = json.loads(bundle_raw)

            self.assertEqual(receipt["candidate_sha"], CANDIDATE)
            self.assertEqual(
                receipt["activation_bundle_sha256"],
                hashlib.sha256(bundle_raw).hexdigest(),
            )
            self.assertEqual(bundle["candidate_sha"], CANDIDATE)
            self.assertEqual(
                bundle["signed_activation"]["claims"]["environment"], "staging"
            )
            self.assertEqual(
                bundle["signed_activation"]["claims"]["expires_at_unix"],
                NOW + authority.ACTIVATION_VALIDITY_SECONDS,
            )
            self.assertNotEqual(
                receipt["activation_public_key_sha256"],
                receipt["outbound_capability_public_key_sha256"],
            )
            self.assertEqual(bundle_raw, authority._canonical(bundle, pretty=True))
            self.assertTrue(
                (root / "outbound-private-key.pem")
                .read_bytes()
                .startswith(b"-----BEGIN PRIVATE KEY-----")
            )

    def test_activation_rejects_reused_proof_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            arguments = _activation_args(Path(temporary))
            arguments.real_postgres_execution_proof_sha256 = (
                arguments.hostile_network_proof_sha256
            )

            with self.assertRaisesRegex(authority.AuthorityError, "must be distinct"):
                authority.create_activation(arguments)

    def test_guardian_matches_private_candidate_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "guardian.json"
            receipt = authority.create_guardian(
                Namespace(
                    candidate_sha=CANDIDATE,
                    functional_target_sha256=DIGESTS[0],
                    functional_target_values_sha256=DIGESTS[1],
                    image_inventory_sha256=DIGESTS[2],
                    activation_receipt_sha256=DIGESTS[3],
                    activation_bundle_sha256=DIGESTS[4],
                    activation_expires_at_unix=NOW + 86_400,
                    workload_apply_run_id="456",
                    namespace_uid="123e4567-e89b-12d3-a456-426614174000",
                    workflow_commit="b" * 40,
                    run_id="789",
                    run_attempt="2",
                    now_unix=NOW,
                    output=output,
                )
            )
            raw = output.read_bytes()

            self.assertEqual(receipt["guardian_install_run_id"], "789")
            self.assertEqual(receipt["guardian_install_run_attempt"], "2")
            self.assertEqual(
                receipt["expires_at_unix"],
                NOW + authority.GUARDIAN_VALIDITY_SECONDS,
            )
            unsigned = dict(receipt)
            stored = unsigned.pop("receipt_sha256")
            self.assertEqual(
                stored, hashlib.sha256(authority._canonical(unsigned)).hexdigest()
            )
            self.assertEqual(raw, authority._canonical(receipt, pretty=True))


if __name__ == "__main__":
    unittest.main()
