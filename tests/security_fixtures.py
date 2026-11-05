"""Synthetic data used only by tests and the explicitly labelled local preview."""
DEVICES = [
    {"id": 1, "name": "업무 서버 / ERP", "ip_address": "10.60.8.21", "type": "server", "os_version": "Windows Server 2019", "location": "전산실 A"},
    {"id": 2, "name": "백업 서버", "ip_address": "10.60.8.22", "type": "server", "os_version": "Windows Server 2019", "location": "전산실 A"},
    {"id": 3, "name": "Core Switch / 본관", "ip_address": "10.60.8.1", "type": "switch", "os_version": "HPE Comware 7.1.070", "location": "전산실 A"},
    {"id": 4, "name": "2F Access Switch", "ip_address": "10.60.8.12", "type": "switch", "os_version": "HPE Comware 7.1.070", "location": "2층"},
    {"id": 5, "name": "Application Linux", "ip_address": "10.60.9.30", "type": "server", "os_version": "Rocky Linux 9.4 / nginx 1.24", "location": "전산실 B"},
    {"id": 6, "name": "환경 센서", "ip_address": "10.60.8.134", "type": "env", "os_version": "FLS LinkNet V3.0", "location": "전산실 A"},
    {"id": 7, "name": "IPv6 Application", "ip_address": "2001:db8::20", "type": "server", "os_version": "nginx 1.24", "location": "테스트"},
]


def sample_feed(count=135):
    items = []
    products = [("microsoft", "windows_server_2019"), ("hpe", "comware"), ("nginx", "nginx"), ("unknown", "unregistered_product")]
    scores = [9.8, 8.1, 6.5, 3.3, 0.0]
    for i in range(count):
        vendor, product = products[i % len(products)]
        items.append({"cve": {
            "id": f"CVE-2099-{10001 + i}", "published": f"2026-10-{1 + i % 28:02}T00:00:00Z", "lastModified": "2026-11-01T00:00:00Z",
            "descriptions": [{"lang": "en", "value": f"SYNTHETIC PREVIEW DATA. {product.replace('_', ' ')} sample vulnerability {i + 1}. Input validation and access control require review. This is not an actual CVE advisory."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": scores[i % len(scores)], "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
            "weaknesses": [{"description": [{"lang": "en", "value": f"CWE-{79 if i % 2 else 287}"}]}],
            "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": f"cpe:2.3:o:{vendor}:{product}:*:*:*:*:*:*:*:*", "versionEndExcluding": "999.0"}]}]}],
            "references": [{"url": "https://nvd.nist.gov/"}],
        }})
    return {"vulnerabilities": items}
