from bs4 import BeautifulSoup


def get_fields(response):
    soup = BeautifulSoup(response.content, 'html.parser')
    return soup.find_all("pre")


def extract_data(response):
    fields = get_fields(response)
    print(fields)
