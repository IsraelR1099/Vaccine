import sys
import argparse
import requests


def make_request(http_method, url, payload):
    try:
        if http_method == "GET":
            response = requests.get(url + payload)
        elif http_method == "POST":
            response = requests.post(url, data=payload)
        else:
            print("Invalid HTTP method.")
            sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
    return response


def detect_success(http_method, url, payload):
    response = make_request(http_method, url, payload)
    error_msgs = [
        "SQL syntax",
        "Warning",
        "mysql_",
        "ORA-",
        "You have an error in your SQL syntax",
        "Unclosed quotation mark",
        "quoted string not properly terminated",
        "Fatal error",
        "unterminated string constant",
        "syntax error",
        ]
    for error_msg in error_msgs:
        if error_msg.lower() in response.text.lower():
            return True
    return False


def check_response(file, response, payload):
    sensitive_keywords = [
            "information_schema",
            "table_schema",
            "table_name",
            "column_name",
            "database()",
            "user()",
            "version()",
            ]
    found_data = []
    for keyword in sensitive_keywords:
        if keyword.lower() in response.text.lower():
            found_data.append(keyword)

    if found_data:
        print(f"[!] Found data: {', '.join(found_data)}")
        with open(file, "a") as f:
            f.write(f"[+] Sensitive data found with payload: {payload}\n")
            for data in found_data:
                f.write(f"   - {data}\n")
        print(f"[!] Sesnsitive data found with payload: {payload}")
        print(f"   - {', '.join(found_data)}")


def analyze_vulnerability(file, http_method, url):
    print("[+] Analyzing vulnerability")
    error_based = "error_based_payload.txt"
    with open(error_based, "r") as f:
        for line in f:
            payload = line.strip()
            response = make_request(http_method, url, payload)
            check_response(file, response, payload)


def scan_url(file, http_method, url):
    error_payloads = "sqli_payload.txt"
    with open(error_payloads, "r") as f:
        for line in f:
            payload = line.strip()
            if detect_success(http_method, url, payload):
                print(f"[!] Potential vulnerability found: {line.strip()}")
                analyze_vulnerability(file, http_method, url)
            else:
                print(f"[+] Not vulnerable with payload: {line.strip()}")


if __name__ == "__main__":
    default_file = "data.txt"
    if len(sys.argv) < 2:
        print("Please provide a valid input.")
        print("./vaccine [-oX] URL")
        print(" -o : Output file name")
        print(" -X : Request type")
        sys.exit(1)
    parser = argparse.ArgumentParser(
            description="Vaccine SQL Injection Tool",
            epilog="Please use this tool for educational purposes only.")
    parser.add_argument("-o", "--output", help="Output file name", default=default_file)
    parser.add_argument("-X", "--request", help="Request type", default="GET")
    parser.add_argument("url", help="URL to test")
    args = parser.parse_args()
    output_file = args.output
    request_method = args.request.upper()
    target_url = args.url
    scan_url(output_file, request_method, target_url)
