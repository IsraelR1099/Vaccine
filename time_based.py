import requests
import time
from colorama import Style, Fore
from urllib.parse import urljoin
from utils import write_to_file


def send_request(url, data, method):
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


def time_based(form_data, url, method, output_file):
    try:
        with open("exploit/time_based_payload.txt", 'r') as file:
            payloads = file.readlines()
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Time-Based SQL Injection file not found{Style.RESET_ALL}")
        return
    print(f"{Fore.LIGHTYELLOW_EX}[*] Testing Time-Based SQL Injection...{Style.RESET_ALL}")
    write_to_file(
        output_file,
        f"[*] Testing Time-Based SQL Injection..."
    )
    for payload in payloads:
        for input_tag in form_data["inputs"]:
            if input_tag["type"] == "submit":
                continue
            data = {}
            for tag in form_data["inputs"]:
                if tag["type"] == "hidden" or tag["value"]:
                    data[tag["name"]] = tag["value"]
                elif tag["type"] != "submit":
                    data[tag["name"]] = "test1"
            if input_tag["name"]:
                data[input_tag["name"]] = payload.strip()
            action_url = (
                urljoin(url, form_data["action"])
                if form_data["action"] and form_data["action"] != "#" else url
            )
            start_time = time.time()
            response = send_request(action_url, data, method)
            if response is None:
                return False
            end_time = time.time()
            elapsed_time = end_time - start_time
            print(f"{Fore.CYAN}[*] Response time: {elapsed_time} seconds{Style.RESET_ALL}")
            if elapsed_time >= 3:
                print(f"{Fore.GREEN}[+] Vulnerable to Time-Based SQL Injection{Style.RESET_ALL}")
                print(f'{Fore.LIGHTBLUE_EX}[*] Vulnerable field: {input_tag["name"]}')
                write_to_file(
                    output_file,
                    f"[+] Vulnerable to Time-Based SQL Injection"
                )
                return True

    write_to_file(
        output_file,
        f"[-] No SQLi vulnerabilities found using Time-Based SQLi"
    )
    print(f"{Fore.RED}[-] No SQLi vulnerability found using Time-Based: {url}{Style.RESET_ALL}")
    return False
