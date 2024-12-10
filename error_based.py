import requests
import sys
from colorama import Fore, Style
from utils import vulnerable, write_to_file
from test_mysql import test_mysql
from urllib.parse import urljoin


def error_based(form_data, url, http_method, output_file):
    try:
        with open("exploit/generic_errorbased.txt", 'r') as file:
            lines = file.readlines()
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Error-Based SQL Injection file not found{Style.RESET_ALL}")
        sys.exit(1)
    print(f"{Fore.LIGHTYELLOW_EX}[*] Testing Error-Based SQL Injection...{Style.RESET_ALL}")
    for line in lines:
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
                data[input_tag["name"]] = f"test{line}"
            action_url = (
                urljoin(url, form_data["action"])
                if form_data["action"] and form_data["action"] != "#" else url
            )
            if form_data["method"] == "post":
                response = requests.post(action_url, data=data)
            elif form_data["method"] == "get":
                response = requests.get(action_url, params=data)
            else:
                continue
            if vulnerable(response):
                print(f"{Fore.GREEN}[+] {url} is vulnerable to Error-Based attacks")
                write_to_file(
                    output_file,
                    f"[+] {url} - Error-Based SQLi vulnerability found"
                )
                test_mysql(action_url, form_data["method"], data, input_tag["name"], output_file)
                return True

    print(f"{Fore.RED}[-] No SQL Injection vulnerability found: {url}{Style.RESET_ALL}")
    write_to_file(
        file,
        f"[-] {url} - No SQLi vulnerabilities found using Error-Based SQLi"
    )

    return False
