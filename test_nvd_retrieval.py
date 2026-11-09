"""Offline tests for NVD retrieval status, retries and pagination."""

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

import requests

import main
import nvd_api


def cve_record(cve_id):
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [
                {
                    "lang": "en",
                    "value": f"{cve_id} description"
                }
            ],
            "metrics": {}
        }
    }


def nvd_page(total, records, start=0, page_size=None):
    return {
        "resultsPerPage": (
            len(records)
            if page_size is None
            else page_size
        ),
        "startIndex": start,
        "totalResults": total,
        "vulnerabilities": records
    }


class FakeResponse:

    def __init__(
        self,
        payload=None,
        status_code=200,
        json_error=None,
        headers=None
    ):
        self.payload = payload
        self.status_code = status_code
        self.json_error = json_error
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(
                f"HTTP {self.status_code}",
                response=self
            )

    def json(self):
        if self.json_error:
            raise self.json_error
        return self.payload


class FakeSession:

    def __init__(self, responses):
        self.get = Mock(side_effect=responses)
        self.trust_env = True
        self.verify = False
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.closed = True
        return False


def retrieve(responses, max_attempts=3):
    session = FakeSession(responses)

    with patch.object(
        nvd_api,
        "_new_nvd_session",
        return_value=session
    ):
        with patch.object(nvd_api.time, "sleep") as sleep:
            result = nvd_api.search_cves_by_keyword_with_status(
                "mosquitto",
                results_per_page=100,
                max_attempts=max_attempts,
                backoff_seconds=1.0,
                max_retry_delay=5.0
            )

    return result, session, sleep


def detected_component():
    return {
        "Mosquitto": {
            "software": "mosquitto",
            "version": "1.5.5",
            "container": "mosquitto-lab",
            "image": "eclipse-mosquitto:1.5.5"
        }
    }


def retrieval_result(status="COMPLETE", items=None, total=0, error=None):
    items = [] if items is None else items

    return {
        "status": status,
        "items": items,
        "received": len(items),
        "total_results": total,
        "error": error
    }


def applicability_result(status, reason):
    return {
        "status": status,
        "reason": reason,
        "component": {},
        "configurations": [],
    }


def run_main_with_retrieval(retrieval):
    output = io.StringIO()

    with patch.object(
        main,
        "get_available_software",
        return_value=detected_component()
    ):
        with patch.object(
            main,
            "get_vulnerabilities",
            return_value=([], [], retrieval)
        ):
            with patch(
                "builtins.input",
                return_value="1"
            ):
                with redirect_stdout(output):
                    main.main()

    return output.getvalue()


class NvdRetrievalTests(unittest.TestCase):

    def test_session_is_direct_verified_and_closed(self):
        record = cve_record("CVE-1")
        session = FakeSession([
            FakeResponse(nvd_page(1, [record]))
        ])

        with patch.object(
            nvd_api.requests,
            "Session",
            return_value=session
        ):
            with patch.object(nvd_api.time, "sleep"):
                result = nvd_api.search_cves_by_keyword_with_status(
                    "mosquitto",
                    results_per_page=100
                )

        self.assertEqual(result["status"], "COMPLETE")
        self.assertFalse(session.trust_env)
        self.assertTrue(session.verify)
        self.assertTrue(session.closed)
        session.get.assert_called_once()

    def test_session_is_closed_when_request_raises_unexpected_error(self):
        session = FakeSession([
            RuntimeError("unexpected transport failure")
        ])

        with patch.object(
            nvd_api,
            "_new_nvd_session",
            return_value=session
        ):
            with self.assertRaises(RuntimeError):
                nvd_api.search_cves_by_keyword_with_status(
                    "mosquitto"
                )

        self.assertTrue(session.closed)

    def test_successful_single_page(self):
        record = cve_record("CVE-1")
        result, request, sleep = retrieve([
            FakeResponse(nvd_page(1, [record]))
        ])

        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(result["items"], [record])
        self.assertEqual(result["received"], 1)
        self.assertEqual(result["total_results"], 1)
        self.assertIsNone(result["error"])
        request.get.assert_called_once()
        sleep.assert_not_called()

    def test_successful_multi_page(self):
        first = cve_record("CVE-1")
        second = cve_record("CVE-2")
        result, request, sleep = retrieve([
            FakeResponse(nvd_page(2, [first], start=0, page_size=1)),
            FakeResponse(nvd_page(2, [second], start=1, page_size=1))
        ])

        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(
            [item["cve"]["id"] for item in result["items"]],
            ["CVE-1", "CVE-2"]
        )
        self.assertEqual(request.get.call_count, 2)
        self.assertEqual(
            request.get.call_args_list[1].kwargs["params"]["startIndex"],
            1
        )
        self.assertTrue(request.closed)
        sleep.assert_not_called()

    def test_successful_zero_results(self):
        result, _, _ = retrieve([
            FakeResponse(nvd_page(0, []))
        ])

        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(result["items"], [])
        self.assertEqual(result["received"], 0)
        self.assertEqual(result["total_results"], 0)

    def test_first_page_timeout_is_failed_after_bounded_retries(self):
        result, request, sleep = retrieve([
            requests.Timeout("first timeout"),
            requests.Timeout("second timeout"),
            requests.Timeout("third timeout")
        ])

        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["items"], [])
        self.assertEqual(request.get.call_count, 3)
        self.assertEqual(
            [call.args[0] for call in sleep.call_args_list],
            [1.0, 2.0]
        )
        self.assertIn("Timeout", result["error"])

    def test_later_page_failure_keeps_valid_records_as_partial(self):
        record = cve_record("CVE-1")
        result, request, sleep = retrieve([
            FakeResponse(nvd_page(2, [record], start=0, page_size=1)),
            requests.Timeout("page two"),
            requests.Timeout("page two"),
            requests.Timeout("page two")
        ])

        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["items"], [record])
        self.assertEqual(result["total_results"], 2)
        self.assertEqual(request.get.call_count, 4)
        self.assertEqual(len(sleep.call_args_list), 2)
        self.assertIn("Timeout", result["error"])

    def test_http_429_and_5xx_are_retried(self):
        record = cve_record("CVE-1")

        with self.subTest(status=429):
            result, request, sleep = retrieve([
                FakeResponse(
                    status_code=429,
                    headers={"Retry-After": "2"}
                ),
                FakeResponse(nvd_page(1, [record]))
            ], max_attempts=2)

            self.assertEqual(result["status"], "COMPLETE")
            self.assertEqual(request.get.call_count, 2)
            sleep.assert_called_once_with(2.0)

        with self.subTest(status=503):
            result, request, sleep = retrieve([
                FakeResponse(status_code=503),
                FakeResponse(nvd_page(1, [record]))
            ], max_attempts=2)

            self.assertEqual(result["status"], "COMPLETE")
            self.assertEqual(request.get.call_count, 2)
            sleep.assert_called_once_with(1.0)

    def test_permanent_http_errors_are_not_retried(self):
        for status_code in (400, 403):

            with self.subTest(status=status_code):
                result, request, sleep = retrieve([
                    FakeResponse(status_code=status_code)
                ])

                self.assertEqual(result["status"], "FAILED")
                self.assertEqual(request.get.call_count, 1)
                sleep.assert_not_called()
                self.assertIn(
                    str(status_code),
                    result["error"]
                )

    def test_invalid_json_is_malformed(self):
        json_error = requests.exceptions.JSONDecodeError(
            "invalid JSON",
            "<html>",
            0
        )
        result, _, _ = retrieve([
            FakeResponse(json_error=json_error)
        ])

        self.assertEqual(result["status"], "MALFORMED")
        self.assertEqual(result["items"], [])
        self.assertIn("Invalid JSON", result["error"])

    def test_non_object_and_invalid_fields_are_handled(self):
        record = cve_record("CVE-1")

        with self.subTest(case="non-object"):
            result, _, _ = retrieve([
                FakeResponse(payload=[])
            ])
            self.assertEqual(result["status"], "MALFORMED")
            self.assertIsNone(result["total_results"])

        with self.subTest(case="invalid-total"):
            result, _, _ = retrieve([
                FakeResponse(payload={
                    "resultsPerPage": 1,
                    "startIndex": 0,
                    "totalResults": "1",
                    "vulnerabilities": [record]
                })
            ])
            self.assertEqual(result["status"], "PARTIAL")
            self.assertEqual(result["items"], [record])
            self.assertIsNone(result["total_results"])
            self.assertIn("totalResults", result["error"])

        with self.subTest(case="invalid-vulnerabilities"):
            result, _, _ = retrieve([
                FakeResponse(payload={
                    "resultsPerPage": 1,
                    "startIndex": 0,
                    "totalResults": 1,
                    "vulnerabilities": "invalid"
                })
            ])
            self.assertEqual(result["status"], "MALFORMED")
            self.assertIn("vulnerabilities", result["error"])

    def test_malformed_individual_record_retains_valid_records(self):
        valid = cve_record("CVE-VALID")
        result, _, _ = retrieve([
            FakeResponse(nvd_page(2, [valid, {"cve": {}}]))
        ])

        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["items"], [valid])
        self.assertIn("malformed CVE record", result["error"])

    def test_empty_page_before_total_is_partial(self):
        result, _, _ = retrieve([
            FakeResponse(nvd_page(2, [], start=0, page_size=0))
        ])

        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["items"], [])
        self.assertEqual(result["total_results"], 2)
        self.assertIn("empty page", result["error"])

    def test_inconsistent_pagination_metadata_is_partial(self):
        first = cve_record("CVE-1")
        second = cve_record("CVE-2")

        with self.subTest(case="total-changed"):
            result, _, _ = retrieve([
                FakeResponse(nvd_page(2, [first], start=0, page_size=1)),
                FakeResponse(nvd_page(3, [second], start=1, page_size=1))
            ])

            self.assertEqual(result["status"], "PARTIAL")
            self.assertEqual(result["received"], 2)
            self.assertEqual(result["total_results"], 2)
            self.assertIn("totalResults changed", result["error"])

        with self.subTest(case="start-index-mismatch"):
            result, _, _ = retrieve([
                FakeResponse(nvd_page(1, [first], start=5))
            ])

            self.assertEqual(result["status"], "PARTIAL")
            self.assertEqual(result["items"], [first])
            self.assertIn("inconsistent pagination metadata", result["error"])

    def test_duplicate_or_repeated_pages_are_partial(self):
        first = cve_record("CVE-1")
        second = cve_record("CVE-2")
        result, request, _ = retrieve([
            FakeResponse(nvd_page(3, [first, second], start=0)),
            FakeResponse(nvd_page(3, [first, second], start=2))
        ])

        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["received"], 2)
        self.assertEqual(request.get.call_count, 2)
        self.assertIn("duplicate CVE record", result["error"])
        self.assertIn("repeated pagination page", result["error"])

    def test_compatibility_wrapper_returns_only_items(self):
        record = cve_record("CVE-1")
        partial = retrieval_result(
            status="PARTIAL",
            items=[record],
            total=2,
            error="later page failed"
        )

        with patch.object(
            nvd_api,
            "search_cves_by_keyword_with_status",
            return_value=partial
        ):
            result = nvd_api.search_cves_by_keyword("mosquitto")

        self.assertEqual(result, [record])


class MainRetrievalIntegrationTests(unittest.TestCase):

    def test_main_distinguishes_complete_empty_from_failed(self):
        complete_output = run_main_with_retrieval(
            retrieval_result(status="COMPLETE", total=0)
        )
        failed_output = run_main_with_retrieval(
            retrieval_result(
                status="FAILED",
                total=None,
                error="NVD unavailable"
            )
        )

        self.assertIn(
            "completed successfully but returned no matching CVE records",
            complete_output
        )
        self.assertNotIn(
            "could not be completed reliably",
            complete_output
        )
        self.assertIn("NVD unavailable", failed_output)
        self.assertIn(
            "could not be completed reliably",
            failed_output
        )
        self.assertNotIn(
            "returned no matching CVE records",
            failed_output
        )

    def test_partial_retrieval_uses_exact_component_key(self):
        record = cve_record("CVE-PARTIAL")
        retrieval = retrieval_result(
            status="PARTIAL",
            items=[record],
            total=2,
            error="page two timed out"
        )

        with patch.object(
            main,
            "search_cves_by_keyword_with_status",
            return_value=retrieval
        ):
            with patch.object(
                main,
                "evaluate_applicability",
                return_value=applicability_result(
                    "UNKNOWN",
                    "Applicability evidence is incomplete."
                )
            ) as evaluator:
                with redirect_stdout(io.StringIO()):
                    affected, unknown, status = (
                        main.get_vulnerabilities(
                            "ditto",
                            "ditto",
                            "3.9.7"
                        )
                    )

        evaluator.assert_called_once_with(
            record,
            "ditto",
            "3.9.7"
        )
        self.assertEqual(affected, [])
        self.assertEqual(len(unknown), 1)
        self.assertEqual(
            unknown[0]["reason"],
            "Applicability evidence is incomplete."
        )
        self.assertEqual(status["status"], "PARTIAL")

    def test_partial_retrieval_is_prominently_warned(self):
        retrieval = retrieval_result(
            status="PARTIAL",
            items=[cve_record("CVE-PARTIAL")],
            total=2,
            error="page two timed out"
        )
        output = io.StringIO()

        with redirect_stdout(output):
            main.show_retrieval_status(retrieval)

        printed = output.getvalue()
        self.assertIn("Status: PARTIAL", printed)
        self.assertIn("page two timed out", printed)
        self.assertIn("WARNING: NVD retrieval was incomplete", printed)
        self.assertIn(
            "absence of additional vulnerabilities cannot be concluded",
            printed
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
