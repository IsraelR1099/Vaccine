import sys
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def make_request(url, method):
    response = None
    if method == "GET":
        response = requests.get(url)
    elif method == "POST":
        response = requests.post(url)
    return response


def extract_forms(url):
    try:
        response = requests.get(url)
    except Exception as e:
        print(f"Failed to connect to {url}. Error: {e}")
        return []
    if response.status_code == 404:
        print(f"Page not found: {url}")
        return []
    soup = BeautifulSoup(response.content, "html.parser")
    return soup.find_all("form")


def get_fields(form):
    form_data = {}
    try:
        form_data["action"] = form.attrs.get("action").lower()
    except:
        form_data["action"] = None
    form_data["method"] = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value
        })
    form_data["inputs"] = inputs
    return form_data


def vulnerable(response):
    error_msgs = [
        "SQL syntax",
        "Warning",
        "mysql_",
        "ORA-",
        "You have an error in your SQL syntax",
        "Unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "Fatal error",
        "unterminated string constant",
        "syntax error",
        ]
    print(f"Response is: {response.content.decode().lower()}")
    for msg in error_msgs:
        if msg in response.content.decode().lower():
            return True
    return False


def scan_url(url, method, output_file):
    error_payloads = "syntax.txt"
    forms = extract_forms(url)
    for form in forms:
        action = form.get("action") or url
        method = form.get("method", "GET").upper()
        fields = get_fields(form)
        print(f"Testing form with fields: {fields} and action: {action}")
        with open(error_payloads, "r") as f:
            for line in f:
                payload = line.strip()
                test_fields = fields.copy()

                for field_name in test_fields:
                    if field_name.lower() in ["submit", "button"]:
                        continue
                    test_fields[field_name] = payload
                    print(f"Injecting payload: {payload} into field: {field_name}")
                    full_url = action if action.startswith("http") else url + action
                    if method.upper() == "GET":
                        response = requests.get(full_url, params=test_fields)
                    elif method.upper() == "POST":
                        response = requests.post(url, data=test_fields)
                    else:
                        print("Unsupported method.")
                        continue
                    print(f"Sent {method} request to {full_url} with data: {test_fields}")
                    if vulnerable(response):
                        print(f"[!] Potential SQL Injection vulnerability found with payload: {payload}")
                    else:
                        print("[-] No SQL Injection vulnerability found.")


def scan_url2(url, method, output_file):
    forms = extract_forms(url)
    print(f"Found {len(forms)} forms.")
    for form in forms:
        form_data = get_fields(form)
        for i in "\"'":
            data = {}
            names = []
            for input_tag in form_data["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    try:
                        data[input_tag["name"]] = input_tag["value"] + i
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    if input_tag["name"] != "user_token":
                        names.append(input_tag["name"])
                    data[input_tag["name"]] = f"test{i}"
            url = urljoin(url, form_data["action"])
            if form_data["method"] == "post":
                response = requests.post(url, data=data)
            elif form_data["method"] == "get":
                response = requests.get(url, params=data)
            if vulnerable(response):
                print(f"[+] SQL Injection vulnerability found: {url}")
                print(f"[*] Form: {form_data}")
                print(f"[*] Data: {data}")
                break
            else:
                print(f"[-] No SQL Injection vulnerability found: {url}")
                print(f"[*] Form: {form_data}")
                print(f"[*] Data: {data}")


if __name__ == "__main__":
    default_file = "data.txt"
    if len(sys.argv) < 2:
        print("Please provide a valid input.")
        print("./vaccine [-oX] URL")
        print(" -o: Output file name")
        print(" -X: Request method")
        sys.exit(1)
    parser = argparse.ArgumentParser(
            description="Vaccine SQL Injection Tool",
            epilog="Please use this tool for educational purposes only."
    )
    parser.add_argument(
            "-o", "--output",
            help="Output file name",
            default=default_file)
    parser.add_argument(
            "-X", "--method",
            help="Request method",
            default="GET")
    parser.add_argument(
            "url",
            help="Target URL")
    args = parser.parse_args()
    output_file = args.output
    method = args.method
    url = args.url
    scan_url2(url, method, output_file)
