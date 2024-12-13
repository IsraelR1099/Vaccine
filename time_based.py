import requests
from colorama import Style, Fore
from urllib.parse import urljoin


def send_request(url, data, method):
    print(f"url: {url}")
    print(f"data time based:: {data}")
    try:
        if method.lower() == "post":
            return requests.post(url, data=data)
        elif method.lower() == "get":
            return requests.get(url, params=data)
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Error during request: {e}{Style.RESET_ALL}")
        return None


def time_based(form_data, url, method, output_file):
    try:
        with open("exploit/time_based_payload.txt", 'r') as file:
            payloads = file.readlines()
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Time-Based SQL Injection file not found{Style.RESET_ALL}")
        return
    print(f"{Fore.LIGHTYELLOW_EX}[*] Testing Time-Based SQL Injection...{Style.RESET_ALL}")
    for payload in payloads:
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
            data[input_tag["name"]] = f"test{payload}"
        action_url = (
            urljoin(url, form_data["action"])
            if form_data["action"] and form_data["action"] != "#" else url
        )
        print(f"payload: {payload}")
        response = send_request(url, data, method)
        # print(f"response: {response.content}")
