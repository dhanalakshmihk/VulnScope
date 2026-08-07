"""
Quick sanity test for cve_lookup._parse_nvd_response() using a mock payload
that matches NVD API v2.0's real JSON schema. This lets us verify parsing
logic works correctly without needing live network access to NVD.
"""
import sys
sys.path.insert(0, ".")
from cve_lookup import _parse_nvd_response, extract_version

# Mock payload shaped like a real NVD v2.0 API response (structure only,
# not asserting these are live/current CVE records).
MOCK_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-TEST-0001",
                "published": "2023-01-15T10:00:00.000",
                "descriptions": [
                    {"lang": "en", "value": "Example buffer overflow vulnerability in mock service allowing remote code execution."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                    ]
                },
            }
        },
        {
            "cve": {
                "id": "CVE-TEST-0002",
                "published": "2022-05-01T10:00:00.000",
                "descriptions": [
                    {"lang": "en", "value": "Example information disclosure issue in mock service."}
                ],
                "metrics": {
                    "cvssMetricV2": [
                        {"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}
                    ]
                },
            }
        },
    ]
}

def test_parsing():
    findings = _parse_nvd_response(MOCK_NVD_RESPONSE, limit=5)
    assert len(findings) == 2, f"Expected 2 findings, got {len(findings)}"
    # Should be sorted highest CVSS first
    assert findings[0].cve_id == "CVE-TEST-0001"
    assert findings[0].cvss_score == 9.8
    assert findings[0].severity == "CRITICAL"
    assert findings[1].cve_id == "CVE-TEST-0002"
    assert findings[1].cvss_score == 5.0
    print("✓ CVE parsing test passed")
    for f in findings:
        print(f"  {f.cve_id}  [{f.severity} {f.cvss_score}]  {f.description[:60]}")

def test_version_extraction():
    assert extract_version("Apache httpd 2.4.41") == "2.4.41"
    assert extract_version("OpenSSH_8.0") == "8.0"
    assert extract_version(None) is None
    assert extract_version("no version here") is None
    print("✓ Version extraction test passed")

if __name__ == "__main__":
    test_parsing()
    test_version_extraction()
    print("\nAll tests passed.")
