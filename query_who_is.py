import os
import sys
import urllib.parse
import http.client
import validators
import getpass
import json

def check_valid_domain():
    while True:
        d_param = input("Please provide a valid domain name: ")
        if validators.domain(d_param):
            return d_param
        else:
            print("You did not provide a valid domain name! Please try again or type 'exit' to quit.")
            if d_param.lower() == 'exit':
                sys.exit("Exiting the program")

def collect_api_key():
    k_param = os.environ.get("IP2WHOIS_API_KEY")
    if k_param is None or k_param == '':
        k_param = getpass.getpass("Please provide a valid license key for ip2whois.com by entering it here or setting an environment variable called IP2WHOIS_API_KEY. Type 'exit' to quit this application:")
        if k_param.lower() == 'exit':
            print("Exiting the application. Thank you for your time.")
            sys.exit()
    return k_param

def make_request(p):
    conn = http.client.HTTPSConnection("api.ip2whois.com")
    conn.request("GET", "/v2?" + urllib.parse.urlencode(p))
    res = conn.getresponse()
    data = res.read()

    response_json = json.loads(data.decode('utf-8'))
    
    try:
        if 'error' in response_json:
            error_message = response_json['error']['error_message']
            print(f"Error: {error_message}")
            if error_message == "API key not found.":
                print("Please check your API key and make sure it's entered correctly.")
            return True
    except json.JSONDecodeError:
        print("Error decoding JSON response. Please try again or check your inputted domain and API key.")
        return True
    print(data)
    return False

if __name__ == "__main__":
    p = { 'key': collect_api_key(), 'domain': check_valid_domain(), 'format': 'json' }
    if not make_request(p):
        sys.exit("You're in main with no data. Exiting application.")