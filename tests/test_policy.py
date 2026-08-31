import unittest

from policy import *


class T(unittest.TestCase):
    def test_allow(self):
        self.assertEqual(validate_record({"method": "GET", "path": "/health", "headers": {}})["decision"], "ALLOW")

    def test_valid_post_with_content_type_is_allow(self):
        record = {"method": "POST", "path": "/events", "headers": {"Content-Type": "application/json"}, "body": "{}"}
        self.assertEqual(validate_record(record)["decision"], "ALLOW")

    def test_method(self):
        self.assertNotEqual(validate_record({"method": "TRACE", "path": "/", "headers": {}})["decision"], "ALLOW")

    def test_external(self):
        self.assertEqual(validate_record({"method": "TRACE", "path": "https://x.test", "headers": {}})["decision"], "BLOCK")

    def test_protocol_relative_path_is_rejected(self):
        result = validate_record({"method": "GET", "path": "//external.test/path", "headers": {}})
        self.assertTrue(any(item["code"] == "invalid_path" for item in result["findings"]))

    def test_cors(self):
        result = validate_record(
            {
                "method": "GET",
                "path": "/x",
                "headers": {"origin": "https://app.test", "authorization": "Bearer demo"},
                "response_headers": {"access-control-allow-origin": "*"},
            }
        )
        self.assertTrue(any(item["code"] == "credentialed_wildcard_cors" for item in result["findings"]))

    def test_wildcard_without_authorization_is_not_cors_finding(self):
        result = validate_record(
            {
                "method": "GET",
                "path": "/public",
                "headers": {"origin": "https://app.test"},
                "response_headers": {"Access-Control-Allow-Origin": "*"},
            }
        )
        self.assertFalse(any(item["code"] == "credentialed_wildcard_cors" for item in result["findings"]))

    def test_body_bound(self):
        result = validate_record({"method": "POST", "path": "/x", "headers": {}, "body": "12345"}, max_body_bytes=4)
        self.assertTrue(any(item["code"] == "body_too_large" for item in result["findings"]))

    def test_malformed_headers_rejected(self):
        with self.assertRaises(ValueError): validate_record({"method": "GET", "path": "/", "headers": []})

    def test_limiter(self):
        limiter = SlidingWindowLimiter(2, 10)
        self.assertTrue(limiter.allow("a", 0))
        self.assertTrue(limiter.allow("a", 1))
        self.assertFalse(limiter.allow("a", 2))
        self.assertTrue(limiter.allow("a", 11))

    def test_limiter_rejects_non_monotonic_time(self):
        limiter = SlidingWindowLimiter(2, 10)
        self.assertTrue(limiter.allow("a", 5))
        with self.assertRaises(ValueError): limiter.allow("a", 4)


if __name__ == "__main__":
    unittest.main()
