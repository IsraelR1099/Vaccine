import re
from bs4 import BeautifulSoup
from colorama import Fore, Style


def get_fields(response):
    soup = BeautifulSoup(response.content, 'html.parser')
    return soup.find_all("pre")


def extract_data(response, file, payload, vulnerable_field):
    file_name = file
    with open(file, "+a") as file:
        file.seek(0)
        fields = get_fields(response)
        print(f"{Fore.LIGHTBLUE_EX}[*] Vulnerable field: {vulnerable_field}{Style.RESET_ALL}")
        written_values = set(file.read().splitlines())
        file.write(f"[*] Payload: {payload}" + '\n')
        file.write(f"[*] Vulnerable field: {vulnerable_field}" + '\n')
        for field in fields:
            text = field.get_text(separator=" ").strip()
            found = None
            if re.search(r'\b(database|schema_name)\b', text, re.IGNORECASE):
                found = f"Database: {text}"
            elif re.search(r'\b(user|USER\(\))\b', text, re.IGNORECASE):
                found = f"User: {text}"
            elif re.search(r'\b(version|@@version)\b', text, re.IGNORECASE):
                found = f"Version: {text}"
            elif re.search(r'\btable_name\b', text, re.IGNORECASE):
                found = f"Table name: {text}"
            else:
                print(f"{Fore.YELLOW}[-] Unmatched field:{Style.RESET_ALL} {text}")
            if found:
                if found not in written_values:
                    print(f"{Fore.GREEN}[*] Found new data! Writing to file{Style.RESET_ALL}")
                    file.write(found + '\n')
                    written_values.add(found)
                else:
                    print(f"{Fore.YELLOW}[-] Data already written to file: {file_name}{Style.RESET_ALL}")
