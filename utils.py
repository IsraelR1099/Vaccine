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
