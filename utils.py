def vulnerable(response):
    if response is None:
        return False
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


def write_to_file(filename, content):
    try:
        with open(filename, "a") as file:
            file.write(content + "\n")
    except OSError as e:
        print({f"[-] Error writing on file: {filename}"})
