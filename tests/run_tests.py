"""Standard-library test entry point for environments without pytest."""

from __future__ import annotations

import importlib
import shutil
import sys
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))


def main() -> int:
    modules = [
        importlib.import_module(name)
        for name in ("test_timeutil", "test_parser", "test_integration", "test_security", "test_acceptance_audit", "test_adapters", "test_archive", "test_investigation", "test_workbench", "test_graph", "test_evtx", "test_evtx_integration_runner", "test_report", "test_assistant", "test_auth")
    ]
    no_path_tests = [
        (modules[0], "test_offset_is_preserved_and_normalized"), (modules[0], "test_missing_time_is_explicit"),
        (modules[1], "test_parser_is_provenance_preserving_and_warns_per_record"), (modules[3], "test_archive_traversal_is_rejected"),
        (modules[4], "test_archive_member_and_content_detection"), (modules[5], "test_json_array_and_csv_adapters"), (modules[5], "test_windows_and_sysmon_xml_adapters_reject_entities_and_map_events"), (modules[5], "test_malformed_encoding_is_isolated"), (modules[5], "test_non_jsonl_adapters_enforce_record_bound"),
        (modules[10], "test_evtx_xml_field_mapping_timestamps_and_provenance"), (modules[10], "test_evtx_xml_parsing_is_deterministic_and_reports_incomplete_records"), (modules[10], "test_evtx_optional_dependency_missing_is_clear"), (modules[10], "test_evtx_security_bounds_and_unsupported_fields"), (modules[11], "test_evtx_status_matrix_is_explicit_and_partial"), (modules[11], "test_evtx_status_only_can_scope_a_family_and_human_output"), (modules[11], "test_evtx_fixture_exit_contract_for_missing_and_invalid_inputs"), (modules[11], "test_evtx_runner_reports_optional_dependency_as_blocked"),
        (modules[8], "test_workbench_theme_text_and_focus_contrast"),
        (modules[8], "test_mobile_workbench_controls_have_touch_targets"),
        (modules[8], "test_windows_startup_launcher_is_checkout_relative_and_has_runtime_fallback"),
    ]
    path_tests = [
        (modules[2], "test_sample_case_vertical_slice"), (modules[2], "test_repeated_analysis_is_deterministic"), (modules[3], "test_source_is_not_modified"),
        (modules[3], "test_analysis_rejects_source_hardlinked_as_derived_output"),
        (modules[3], "test_analysis_preserves_preexisting_archive_scratch_folder"),
        (modules[3], "test_analysis_rejects_linked_import_root_when_supported"),
        (modules[3], "test_prompt_injection_is_data_only"), (modules[4], "test_manifest_provenance_and_references"), (modules[4], "test_pivot_and_replay_expose_review_state"), (modules[4], "test_explicit_device_file_correlation"), (modules[6], "test_archive_import_is_read_only_and_deterministic"), (modules[6], "test_archive_traversal_and_ratio_rejection"), (modules[7], "test_analyst_objects_are_separate_and_reference_checked"),
        (modules[8], "test_workbench_sample_case_workflows"), (modules[8], "test_workbench_report_export_formats_redaction_bounds_and_source_safety"), (modules[8], "test_workbench_handles_malformed_backend_data_safely"), (modules[8], "test_workbench_static_ui_is_local_and_untrusted_content_is_not_interpolated"),
        (modules[9], "test_bounded_graph_supports_entity_event_and_thread_starts"), (modules[9], "test_graph_api_bounds_results_and_exposes_provenance"), (modules[9], "test_graph_malformed_case_data_is_structured"),
        (modules[10], "test_evtx_decoder_shim_enters_existing_analysis_relationships_and_threads"),
        (modules[12], "test_report_is_deterministic_provenance_preserving_and_raw_free"), (modules[12], "test_report_scopes_graph_and_investigation_objects"), (modules[12], "test_report_redaction_html_security_and_source_protection"), (modules[12], "test_report_cli_writes_json_html_and_markdown"),
        (modules[13], "test_assistant_is_disabled_by_default_and_audit_excludes_raw_sensitive_data"), (modules[13], "test_fake_context_is_deterministic_bounded_and_redaction_aware"), (modules[13], "test_prompt_injection_fixture_is_untrusted_data"), (modules[13], "test_citation_validator_rejects_missing_and_analyst_ids"), (modules[13], "test_assistant_tasks_return_structured_insufficient_or_cited_answers"),
        (modules[14], "test_local_account_setup_password_storage_and_reset_are_scoped"), (modules[14], "test_local_login_hashing_throttle_and_short_lived_sessions"), (modules[14], "test_per_user_settings_persist_without_storing_session_tokens"), (modules[14], "test_setup_code_expires_and_failed_guesses_consume_it"),
        (modules[8], "test_workbench_requires_login_csrf_and_sets_restricted_session_cookie"),
    ]
    test_root = ROOT / f"forensickit-test-run-{uuid.uuid4().hex}"
    if test_root.exists():
        raise RuntimeError("The unique test workspace already exists; refusing to reuse it.")
    test_root.mkdir()
    try:
        for module, name in no_path_tests:
            getattr(module, name)()
        for index, (module, name) in enumerate(path_tests):
            path = test_root / f"case-{index}"
            path.mkdir()
            getattr(module, name)(path)
    finally:
        shutil.rmtree(test_root)
    print(f"passed={len(no_path_tests) + len(path_tests)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
