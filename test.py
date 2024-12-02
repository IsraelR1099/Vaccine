import sys
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

session = requests.Session()
session.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

def make_request(http_method, url, payload):
    try:
        if http_method == "GET":
            response = requests.get(url, params=payload)
        elif http_method == "POST":
            response = requests.post(url, params=payload)
        else:
            print("Invalid HTTP method.")
            sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
    return response


def vulnerable(response):
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
    print(f"testing response {response.content}")
    for error_msg in error_msgs:
        if error_msg in response.content.decode().lower():
            return True
    return False


def get_forms(url):
    soup = BeautifulSoup(session.get(url).content, "html.parser")
    return soup.find_all("form")


def form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value,
        })
    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details


def scan_url(file, http_method, url):
    error_payloads = "syntax.txt"
    forms = get_forms(url)
    with open(error_payloads, "r") as f:
        for form in forms:
            details = form_details(form)
            for line in f:
                payload = line.strip()
                data = {}
                for input_tag in details["inputs"]:
                    if input_tag["type"] == "hidden" or input_tag["value"]:
                        data[input_tag['name']] = input_tag["value"] + line
                    elif input_tag["type"] != "submit":
                        data[input_tag['name']] = f"test{line}"

                action_url = details['action']
                print(f"Submitting to {action_url} with data {data}")
                if details["method"] == "POST":
                    res = session.post(url, data=data)
                elif details["method"] == "GET":
                    print(f"url y data {url} {data}")
                    res = session.get(url, params=data)
                else:
                    print(f"No method {details['method']}")
                if vulnerable(res):
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
