import requests
import urllib
import base64
import json
import secrets
import os
from dotenv import load_dotenv

load_dotenv()

BASE_URL = os.environ.get('BASE_URL')
# for API clients use function get_token
API_CLIENT_ID = os.environ.get('API_CLIENT_ID')
API_CLIENT_SECRET = os.environ.get('API_CLIENT_SECRET')
OAUTH_CLIENT_ID = os.environ.get('OAUTH_CLIENT_ID')
OAUTH_CLIENT_SECRET = os.environ.get('OAUTH_CLIENT_SECRET')

# for user login use function get_user_token
PRIVX_USERNAME = os.environ.get('PRIVX_USERNAME')
PRIVX_PASSWORD = os.environ.get('PRIVX_PASSWORD')


def get_login_token():
    """
    Gets login token from redirect url
    :return: login_token
    """
    login_state = secrets.token_urlsafe(32)
    url = f"{BASE_URL}/auth/api/v1/oauth/authorize"

    headers = {
        "Content-Type": "application/json"
    }

    params = {
        "user_agent": "privx-ui",
        "response_type": "code",
        "client_id": "privx-ui",
        "redirect_uri": "/privx/oauth-callback",
        "state": login_state
    }

    response = requests.get(url,  params=params, headers=headers, verify="cert.pem")
    redirect_url = response.request.url.split("=")
    login_token = redirect_url[1][:-9]

    return login_token


def login(login_token):
    """
    Uses user credentials to get authorization code, requires login token
    :param login_token:
    :return: authorization code for use with the get_user_token function
    """
    url = f"{BASE_URL}/auth/api/v1/login"

    payload = {
        "username": PRIVX_USERNAME,
        "password": PRIVX_PASSWORD,
        "token": login_token
    }

    headers = {
        "Content-Type": "x-www-form-urlencoded"
    }

    response = requests.post(url,  json=payload, headers=headers,  verify="cert.pem")
    auth_code = json.loads(response.text).get('code')

    return auth_code


def get_user_token():
    """
    Gets token based off of user credentials, depends on login() and get_login_token() functions
    :return: token string
    """
    url = f"{BASE_URL}/auth/api/v1/oauth/token"

    login_token = get_login_token()
    auth_code = login(login_token)

    payload = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "client_id": "privx-ui",
        "redirect_uri": "/privx/oauth-callback",
    }

    response = requests.post(url, data=payload, verify="cert.pem")
    token = json.loads(response.text).get('access_token')

    return token


def get_token():
    """
    Gets token based off of API_Client credentials
    :return: token string
    """
    url = f"{BASE_URL}/auth/api/v1/oauth/token"

    payload = {
        "grant_type": "password",
        "username": f"{API_CLIENT_ID}",
        "password": f"{API_CLIENT_SECRET}"
    }

    basic_auth = base64.b64encode(
        f"{OAUTH_CLIENT_ID}:{OAUTH_CLIENT_SECRET}".encode('utf-8')
    )

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {basic_auth.decode('utf-8')}"
    }

    response = requests.request("POST", url, data=urllib.parse.urlencode(payload), headers=headers, verify="cert.pem")

    if response.status_code == 200:
        return json.loads(response.text).get('access_token')
    else:
        print(f'Error {response.status_code}: {response.text}')


def get_roles(token):
    """
    :param token: retrieved by function get_user_token or get_token
    :return: json object containing role information
    """
    url = f'{BASE_URL}/role-store/api/v1/roles'

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}"
    }

    response = requests.request("GET", url, headers=headers, verify="cert.pem")

    return json.loads(response.text)


def print_roles(roles):
    print("---ROLES---")
    for role in roles['items']:
        print(role['name'])
    print("-----------")


def get_hosts(token):
    """
    :param token: retrieved by function get_user_token or get_token
    :return: json object containing host information
    """
    url = f"{BASE_URL}/host-store/api/v1/hosts"

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}"
    }

    response = requests.request("GET", url, headers=headers, verify='cert.pem')

    return json.loads(response.text)


def print_hosts(hosts):
    print("---HOSTS---")
    for host in hosts['items']:
        print(host['common_name'] + "\t" + host['services'][0]['service'] + '=' + host['services'][0]['status'])
    print("-----------")


def get_users(token):
    """
    :param token: retrieved by function get_user_token or get_token
    :return: json object containing user information
    """
    url = f"{BASE_URL}/local-user-store/api/v1/users"

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}"
    }

    response = requests.request("GET", url, headers=headers, verify='cert.pem')

    return json.loads(response.text)


def print_users(users):
    print('---USERS---')
    for user in users['items']:
        print(user['username'])
    print('-----------')


def get_license(token):
    """
    prints text containing license information

    :param token: retrieved by function get_user_token or get_token
    :return: None
    """
    url = f"{BASE_URL}/license-manager/api/v1/license"

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}"
    }

    response = requests.request("GET", url, headers=headers, verify='cert.pem')

    print(response.text)


def deactivate_license(token):
    """
    Deactivates license

    :param token: retrieved by function get_user_token or get_token
    :return: None
    """
    url = f"{BASE_URL}/license-manager/api/v1/license/deactivate"

    headers = {
        "Authorization": f"Bearer {token}"
    }

    response = requests.request("POST", url, headers=headers, verify='cert.pem')

    if response.status_code == 200:
        print("License Deactivated")
    else:
        print(f"{response.status_code}: {response.text}")


def activate_license(token, license_code):
    """
    activates license

    :param token: retrieved by function get_user_token or get_token
    :param license_code: license code to activate
    :return: Json object containing license information
    """
    url = f"{BASE_URL}/license-manager/api/v1/license"

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/octet-stream"
    }

    response = requests.request("POST", url, headers=headers, data=license_code, verify="cert.pem")

    return json.loads(response.text)


def main():
    # use only one of the below functions to get token
    token = get_user_token()
#    token = get_token()

    roles = get_roles(token)
    print_roles(roles)

    hosts = get_hosts(token)
    print_hosts(hosts)

    users = get_users(token)
    print_users(users)

    get_license(token)


if __name__ == '__main__':
    main()
