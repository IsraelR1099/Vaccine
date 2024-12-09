import requests
from colorama import Fore, Style
from utils import vulnerable


def error_based(form_data, url, http_method):
    try:
        with open("exploit/generic_errorbased.txt", 'r') as file:
            lines = file.readlines()
    except FileNotFoundError:
        print(f"File not found: {e}")
        sys.exit(1)
    print(f"{Fore.BLUE}[*]Testing Error-Based SQL Injection...{Style.RESET_ALL}")
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
                response= requests.get(action_url, params=data)
            else:
                continue
            if vulnerable(response):
                print(f"{Fore.GREEN}[+]SQL Injection vulnerability found: {url}{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}[-]No SQL Injection vulnerability found: {url}{Style.RESET_ALL}")
    return False

