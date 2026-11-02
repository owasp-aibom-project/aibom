import copy
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

DEMO_DIR = Path(__file__).resolve().parents[2] / "src" / "integrity-checker"
sys.path.insert(0, str(DEMO_DIR))

from flows import build_flow_graph, flow_positions
from integrity import KINDS, category, evidence_warnings, inventory, load_manifest, read_json, verify, verify_dummy


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.content = b"approved model\n"
        self.model = {"bom-ref": "model:one", "type": "machine-learning-model",
                      "name": "Model", "version": "1", "hashes": [
                          {"alg": "SHA-256", "content": hashlib.sha256(self.content).hexdigest()}]}
        self.data = {"bom-ref": "data:one", "type": "data", "name": "Data", "version": "1"}
        self.bom = {"bomFormat": "CycloneDX", "components": [self.model, self.data],
                    "dependencies": [{"ref": "model:one", "dependsOn": ["data:one"]}]}
        self.manifest = {"manifestVersion": 1, "baseline": copy.deepcopy(self.bom),
                         "artifactPaths": {"model:one": "model.bin"}}

    def row(self, rows):
        return next(row for row in rows if row["ref"] == "model:one")

    def test_inventory_order_does_not_matter(self):
        self.bom["components"].reverse()
        self.assertFalse(any(row["issues"] for row in verify(self.manifest, self.bom)))

    def test_declarations_are_not_byte_verification(self):
        row = self.row(verify(self.manifest, self.bom))
        self.assertEqual(row["status"], "DECLARATION ONLY")
        self.assertEqual(row["signature"], "Not verified")

    def test_matching_and_altered_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "model.bin"
            path.write_bytes(self.content)
            self.assertEqual(self.row(verify(self.manifest, self.bom, folder))["status"], "BYTES MATCH")
            path.write_bytes(b"substituted")
            row = self.row(verify(self.manifest, self.bom, folder))
            self.assertEqual(row["status"], "FAIL")
            self.assertIn("Artifact bytes changed", row["issues"])

    def test_changed_digest_and_version(self):
        self.model["hashes"][0]["content"] = "0" * 64
        self.model["version"] = "2"
        row = self.row(verify(self.manifest, self.bom))
        self.assertEqual(row["declaration"], "Mismatch")
        self.assertIn("Definition changed", row["issues"])

    def test_addition_and_removal(self):
        self.bom["components"].pop()
        self.bom["dependencies"] = []
        self.bom["components"].append({"bom-ref": "extra", "name": "Extra"})
        rows = verify(self.manifest, self.bom)
        self.assertIn("Missing artifact", next(row for row in rows if row["ref"] == "data:one")["issues"])
        self.assertIn("Unexpected artifact", next(row for row in rows if row["ref"] == "extra")["issues"])

    def test_changed_relationship(self):
        self.bom["dependencies"] = []
        self.assertIn("Relationships changed", self.row(verify(self.manifest, self.bom))["issues"])

    def test_duplicate_ref_rejected(self):
        self.bom["components"].append(self.model)
        with self.assertRaisesRegex(ValueError, "Duplicate bom-ref"):
            inventory(self.bom)

    def test_missing_file_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(self.row(verify(self.manifest, self.bom, folder))["bytes"], "Unavailable")

    def test_path_escape_blocked(self):
        self.manifest["artifactPaths"]["model:one"] = "../outside.bin"
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(self.row(verify(self.manifest, self.bom, folder))["bytes"], "Blocked path")

    def test_nested_components_and_services(self):
        self.bom["services"] = [{"bom-ref": "service:one", "name": "API", "services": [
            {"bom-ref": "service:two", "name": "Nested API"}]}]
        self.model["components"] = [{"bom-ref": "nested", "name": "Nested model"}]
        self.assertEqual(len(inventory(self.bom)), 5)

    def test_signature_mutation_is_definition_change_not_crypto_verification(self):
        self.model["signature"] = {"value": "altered"}
        row = self.row(verify(self.manifest, self.bom))
        self.assertIn("Definition changed", row["issues"])
        self.assertEqual(row["signature"], "Not verified")

    def test_dummy_hash_match_and_reordering(self):
        self.bom["components"].reverse()
        self.bom["dependencies"] = []
        self.model["description"] = "Not checked by the dummy verifier"
        self.assertEqual(self.row(verify_dummy(self.manifest, self.bom))["status"], "MATCH")

    def test_dummy_hash_mismatch(self):
        self.model["hashes"][0]["content"] = "0" * 64
        self.assertEqual(self.row(verify_dummy(self.manifest, self.bom))["status"], "MISMATCH")

    def test_dummy_missing_hash_is_not_a_match(self):
        self.model.pop("hashes")
        self.assertEqual(self.row(verify_dummy(self.manifest, self.bom))["status"], "NO HASH")

    def test_dummy_missing_and_unexpected_artifacts(self):
        self.bom["components"] = [{"bom-ref": "extra", "name": "Extra"}]
        rows = verify_dummy(self.manifest, self.bom)
        self.assertEqual(self.row(rows)["status"], "MISSING")
        self.assertEqual(next(row for row in rows if row["ref"] == "extra")["status"], "UNEXPECTED")

    def test_dummy_invalid_hash_is_localized(self):
        self.model["hashes"][0]["content"] = "broken"
        self.assertEqual(self.row(verify_dummy(self.manifest, self.bom))["status"], "MISMATCH")

    def test_static_dummy_manifest_matches_all_artifacts(self):
        manifest = load_manifest(DEMO_DIR / "manifest.json")
        rows = verify_dummy(manifest, manifest["baseline"])
        self.assertEqual(len(rows), 14)
        self.assertTrue(all(row["status"] == "MATCH" for row in rows))


class EvidenceTests(unittest.TestCase):
    setUp = IntegrityTests.setUp

    def test_required_optional_and_overridden_declarations(self):
        self.manifest["evidenceExpectations"] = {
            "defaults": {
                "publisher_identity": {"required": True, "requiredAssessment": "VERIFIED"},
                "independent_attestation": {"required": False},
            },
            "artifacts": {"model:one": {
                "publisher_identity": {"required": True, "requiredAssessment": "SELF_ASSERTED"},
                "lineage": {"required": True, "requiredAssessment": "VERIFIED"},
            }},
        }
        self.model["properties"] = [{"name": "demo:evidence:publisher_identity", "value": "SELF_ASSERTED"}]
        warnings = evidence_warnings(self.manifest, "model:one", self.model)
        self.assertEqual(warnings, ["lineage: declared NOT_RECORDED; requires VERIFIED."])
        self.model["properties"].append({"name": "demo:evidence:lineage", "value": "SELF_ASSERTED"})
        self.assertIn("declared SELF_ASSERTED", evidence_warnings(self.manifest, "model:one", self.model)[0])
        self.model["properties"][-1]["value"] = "VERIFIED"
        self.assertIn("supporting evidence has not been verified", evidence_warnings(self.manifest, "model:one", self.model)[0])
        self.model["properties"].append(self.model["properties"][-1])
        self.assertIn("AMBIGUOUS", evidence_warnings(self.manifest, "model:one", self.model)[0])
        self.model["properties"] = None
        self.assertTrue(all("NOT_RECORDED" in warning for warning in evidence_warnings(self.manifest, "model:one", self.model)))
        self.model["properties"] = [{"name": "demo:evidence:publisher_identity", "value": "SELF_ASSERTED"}]
        self.manifest["evidenceExpectations"]["artifacts"]["model:one"]["lineage"]["required"] = False
        self.assertEqual(evidence_warnings(self.manifest, "model:one", self.model), [])

    def test_no_policy_has_no_warning(self):
        self.assertEqual(evidence_warnings(self.manifest, "model:one", self.model), [])

    def test_static_samples_warn_without_changing_hash_results(self):
        folder = DEMO_DIR
        manifest = load_manifest(folder / "manifest.json")
        for filename, mismatches in (("aibom-dummy.cdx.json", 0), ("aibom-unmatched.cdx.json", 1)):
            rows = verify_dummy(manifest, read_json(folder / filename))
            self.assertEqual(sum(row["status"] == "MISMATCH" for row in rows), mismatches)
            self.assertTrue(all(row["evidenceWarnings"] for row in rows))
        self.assertTrue(all(row["evidenceWarnings"] for row in verify_dummy(manifest, manifest["baseline"])))


class FlowTests(unittest.TestCase):
    setUp = IntegrityTests.setUp

    def test_independent_translation_flow_stays_green(self):
        manifest = load_manifest(DEMO_DIR / "manifest.json")
        bom = copy.deepcopy(manifest["baseline"])
        inventory(bom)["model:support"]["hashes"][0]["content"] = "0" * 64
        graph = build_flow_graph(bom, verify_dummy(manifest, bom))
        independent = {"model:translation", "dataset:translation", "adapter:translation-lora", "agent:translation"}
        for ref in independent:
            self.assertEqual(graph.nodes[ref]["status"], "MATCH")
            self.assertFalse(graph.nodes[ref]["untrustedDependencies"])
        self.assertEqual(set(graph.subgraph(independent).edges), {
            ("model:translation", "adapter:translation-lora"),
            ("dataset:translation", "adapter:translation-lora"),
            ("model:translation", "agent:translation"),
            ("adapter:translation-lora", "agent:translation"),
        })
        self.assertFalse(any((source in independent) != (target in independent) for source, target in graph.edges))
        positions = flow_positions(graph)
        original = set(graph) - independent
        self.assertLess(max(positions[ref][1] for ref in original), min(positions[ref][1] for ref in independent))

    def test_dependency_arrows_and_local_hash_status(self):
        self.model["hashes"][0]["content"] = "0" * 64
        graph = build_flow_graph(self.bom, verify_dummy(self.manifest, self.bom))
        self.assertIn(("data:one", "model:one"), graph.edges)
        self.assertEqual(graph.nodes["model:one"]["status"], "MISMATCH")
        self.assertEqual(graph.nodes["data:one"]["status"], "NO HASH")

    def test_missing_and_unexpected_nodes_stay_visible(self):
        self.bom["components"] = [{"bom-ref": "extra", "name": "Extra"}]
        self.bom["dependencies"] = []
        graph = build_flow_graph(self.bom, verify_dummy(self.manifest, self.bom))
        self.assertEqual(graph.nodes["model:one"]["status"], "MISSING")
        self.assertEqual(graph.nodes["extra"]["status"], "UNEXPECTED")

    def test_unresolved_reference_is_not_a_match(self):
        self.bom["dependencies"][0]["dependsOn"].append("unknown")
        graph = build_flow_graph(self.bom, verify_dummy(self.manifest, self.bom))
        self.assertEqual(graph.nodes["unknown"]["status"], "UNRESOLVED")

    def test_cycles_and_disconnected_nodes_have_positions(self):
        self.bom["dependencies"].append({"ref": "data:one", "dependsOn": ["model:one"]})
        self.bom["components"].append({"bom-ref": "isolated", "name": "Isolated"})
        graph = build_flow_graph(self.bom)
        positions = flow_positions(graph)
        self.assertEqual(set(positions), set(graph))
        self.assertEqual(len(set(positions.values())), len(graph))
        self.assertTrue(all(node["status"] == "NOT CHECKED" for _, node in graph.nodes(data=True)))

    def test_invalid_dependency_shape_is_rejected(self):
        self.bom["dependencies"] = [{"ref": "model:one", "dependsOn": "data:one"}]
        with self.assertRaisesRegex(ValueError, "dependsOn"):
            build_flow_graph(self.bom)

    def test_inventory_order_does_not_change_positions(self):
        expected = flow_positions(build_flow_graph(self.bom))
        self.bom["components"].reverse()
        self.assertEqual(flow_positions(build_flow_graph(self.bom)), expected)

    def test_matching_dependents_are_at_risk_transitively(self):
        self.bom["components"].extend([
            {"bom-ref": "consumer", "name": "Consumer"},
            {"bom-ref": "independent", "name": "Independent"},
        ])
        self.bom["dependencies"].append({"ref": "consumer", "dependsOn": ["model:one"]})
        rows = [{"ref": ref, "status": "MISMATCH" if ref == "data:one" else "MATCH"}
                for ref in inventory(self.bom)]
        graph = build_flow_graph(self.bom, rows)
        self.assertEqual(graph.nodes["data:one"]["status"], "MISMATCH")
        for ref in ("model:one", "consumer"):
            self.assertEqual(graph.nodes[ref]["status"], "AT RISK")
            self.assertEqual(graph.nodes[ref]["hashStatus"], "MATCH")
            self.assertEqual(graph.nodes[ref]["untrustedDependencies"], ["data:one"])
        self.assertEqual(graph.nodes["independent"]["status"], "MATCH")

    def test_direct_failure_takes_precedence_in_a_cycle(self):
        self.bom["dependencies"].append({"ref": "data:one", "dependsOn": ["model:one"]})
        rows = [{"ref": "data:one", "status": "MATCH"}, {"ref": "model:one", "status": "MISMATCH"}]
        graph = build_flow_graph(self.bom, rows)
        self.assertEqual(graph.nodes["data:one"]["status"], "AT RISK")
        self.assertEqual(graph.nodes["model:one"]["status"], "MISMATCH")
        self.assertEqual(graph.nodes["data:one"]["untrustedDependencies"], ["model:one"])

    def test_other_untrusted_statuses_propagate(self):
        for status in ("MISSING", "NO HASH", "UNEXPECTED", "UNRESOLVED"):
            with self.subTest(status=status):
                rows = [{"ref": "data:one", "status": status}, {"ref": "model:one", "status": "MATCH"}]
                graph = build_flow_graph(self.bom, rows)
                self.assertEqual(graph.nodes["model:one"]["status"], "AT RISK")


class InterfaceTests(unittest.TestCase):
    def test_customtkinter_browser_samples_upload_and_export(self):
        import customtkinter as ctk
        from app import Application

        app = Application()
        app.withdraw()
        errors = []
        app.report_callback_exception = lambda *error: errors.append(error)
        try:
            app.update()
            self.assertIsInstance(app, ctk.CTk)
            self.assertEqual(set(app.type_cards), set(KINDS))
            for kind in KINDS:
                app.type_cards[kind].invoke()
                app.update()
                self.assertEqual(len(app.artifact_buttons), sum(category(record) == kind for record in app.records.values()))
                self.assertIn('"artifact"', app.artifact_detail.get("1.0", "end"))
                app.search.set("not-present")
                self.assertFalse(app.artifact_buttons)
                app.show_cards()
            app.show_page("Verify AIBOM")
            app._sample_action("Matching sample")
            self.assertTrue(all(row["status"] == "MATCH" for row in app.results))
            app._sample_action("Modified sample")
            self.assertEqual(sum(row["status"] == "MISMATCH" for row in app.results), 1)
            self.assertEqual(len(app.result_rows), 14)
            self.assertEqual(len(app.result_badges), 14)
            app.show_artifacts("Models")
            self.assertEqual(len(app.artifact_badges), 2)
            self.assertIn("Evidence warnings", app.artifact_detail.get("1.0", "end"))
            app.show_page("Flows")
            app.update()
            self.assertEqual(len(app.flow_canvas.node_items), 14)
            self.assertEqual(len(app.flow_canvas.warning_items), 14)
            graph = app.flow_canvas.graph
            self.assertIn(("dataset:tickets", "model:support"), graph.edges)
            self.assertEqual(graph.nodes["model:support"]["status"], "MISMATCH")
            self.assertEqual(graph.nodes["agent:support"]["status"], "AT RISK")
            self.assertEqual(graph.nodes["agent:support"]["hashStatus"], "MATCH")
            canvas = app.flow_canvas.canvas
            self.assertEqual(canvas.itemcget(app.flow_canvas.node_items["model:support"], "fill"), "#fae5e9")
            for ref in ("adapter:tone", "agent:support", "service:gateway"):
                self.assertEqual(canvas.itemcget(app.flow_canvas.node_items[ref], "fill"), "#fff0cc")
            self.assertEqual(canvas.itemcget(app.flow_canvas.node_items["dataset:tickets"], "fill"), "#e1f1e7")
            for ref in ("model:translation", "dataset:translation", "adapter:translation-lora", "agent:translation"):
                self.assertEqual(canvas.itemcget(app.flow_canvas.node_items[ref], "fill"), "#e1f1e7")
            self.assertEqual(len(canvas.find_withtag("edge")), graph.number_of_edges())
            before = app.flow_canvas.scale
            app.flow_canvas.zoom(1.2)
            self.assertGreater(app.flow_canvas.scale, before)
            app.flow_canvas.fit()
            app._select_flow_node("model:support", graph.nodes["model:support"])
            self.assertIn("MISMATCH", app.flow_detail.get("1.0", "end"))
            app._select_flow_node("agent:support", graph.nodes["agent:support"])
            self.assertIn("Untrusted dependencies  model:support", app.flow_detail.get("1.0", "end"))
            self.assertIn("publisher_identity", app.flow_detail.get("1.0", "end"))
            app.show_page("Verify AIBOM")
            self.assertFalse(app.result_detail.winfo_manager())
            app._select_result(0)
            self.assertIn("Manifest", app.result_detail.get("1.0", "end"))
            self.assertIn("Evidence warnings", app.result_detail.get("1.0", "end"))
            with tempfile.TemporaryDirectory() as folder:
                exported = Path(folder) / "reference.json"
                with patch("app.filedialog.asksaveasfilename", return_value=str(exported)):
                    app._reference_action("Save example...")
                self.assertEqual(read_json(exported), app.manifest["baseline"])
                with patch("app.filedialog.askopenfilename", return_value=str(exported)):
                    app.open_aibom()
                self.assertEqual(len(app.results), 14)
                self.assertTrue(all(row["status"] == "MATCH" for row in app.results))
                with patch("app.filedialog.askopenfilename", return_value=str(app.manifest_path)):
                    app._reference_action("Open manifest...")
                self.assertIsNone(app.candidate)
                self.assertFalse(app.results)
                self.assertEqual(len(app.type_cards), 10)
                self.assertTrue(all(node["status"] == "NOT CHECKED"
                                    for _, node in app.flow_canvas.graph.nodes(data=True)))
                self.assertFalse(app.result_badges)
            app.manifest.pop("evidenceExpectations")
            app.load_sample()
            self.assertFalse(app.result_badges)
            self.assertFalse(app.flow_canvas.warning_items)
            app.show_artifacts("Models")
            self.assertFalse(app.artifact_badges)
            app.update()
            self.assertFalse(errors, errors)
        finally:
            app.destroy()


if __name__ == "__main__":
    unittest.main()