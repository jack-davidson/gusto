"""
Gusto Auth & API SDK Interface
"""

import os
from urllib.parse import quote
import requests

KEY_AUTHCODE = "code"
BASE_URL = "https://api.gusto-demo.com"
CALLBACK_URL = "http://localhost:5000/callback"

CLIENT_ID = os.environ["CLIENT_ID"]
SECRET = os.environ["SECRET"]
AUTHORIZE_URL = f"{BASE_URL}/oauth/authorize?client_id={CLIENT_ID}&amp;redirect_uri={quote(CALLBACK_URL, safe='')}&amp;response_type=code"

class UnauthorizedException(Exception):
    pass


class GustoAuth:
    """
    Interface to Gusto's Auth servers. Makes oauth requests and deals with managing tokens.
    Takes an optional `refresh_token` argument to set the initial refresh token.
    """
    def __init__(self, refresh_token=None):
        self.refresh_token = refresh_token

    def put(self, new_token):
        """
        Update the current refresh token to `new_token`.
        """
        self.refresh_token = new_token

    def get(self):
        """
        Get the current refresh token.
        """
        return self.refresh_token

    def oauth(self, token, refresh=False):
        """
        Internal method for making authentication requests. If refresh is left unset,
        `GustoAuth.oauth()` will treat `token` as an authorization code sent from gusto--the first
        step in the oauth flow--and will return an access code from that authorization code.
        If refresh is set to `True`, `GustoAuth.oauth()` will treat `token` as a refresh code
        and will use the refresh code to request another access code from gusto.
        `GustoAuth.oauth()` will automatically update the current refresh token internally
        for further requests.
        """
        data = {
            "client_id": CLIENT_ID,
            "client_secret": SECRET,
            "redirect_uri": CALLBACK_URL
        }

        if refresh:
            data["grant_type"] = "refresh_token"
            data["refresh_token"] = token
        else:
            data["grant_type"] = "authorization_code"
            data["code"] = token

        response = requests.post(
            BASE_URL + "/oauth/token", json=data, headers={
                "Content-Type": "application/json"
            })

        if "error" in response.json().keys():
            raise Exception(response.json()["error"], response.json()[
                            "error_description"])

        refresh_token = response.json()["refresh_token"]
        self.put(refresh_token)

        access_token = response.json()["access_token"]

        return access_token

    def authorize(self, token):
        """
        Given a `token`, from the Gusto user auth page, get an access token from Gusto.
        """
        return self.oauth(token)

    def access_token(self):
        """
        With the current stored refresh token, request
        a new access token and replace the old refresh token.

        Gets the current refresh token and passes it to `GustoAuth.oauth()` to get
        another access token.

        Calls `GustoAuth.oauth(self.get(), refresh=True)`
        """
        return self.oauth(self.get(), refresh=True)

    def __str__(self):
        return self.refresh_token


class Gusto:
    """
    Client Interface to Gusto's resource servers. Makes API requests.
    Takes one positional argument `access_token` to authenticate with Gusto's API servers.
    """
    def __init__(self, access_token):
        self.access_token = access_token

    def me(self):
        """
        Makes a request to Gusto API `/v1/me` and returns the deserialized json response.
        """
        response = requests.get(BASE_URL + "/v1/me", headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {self.access_token}"
        })
        return response.json()

    def company_id(self):
        """
        Calls `Gusto.me()` and returns the company the user is a part of.
        """
        return self.me()["roles"]["payroll_admin"]["companies"][0]["id"]

    def get_contractors(self):
        """
        Makes a request to the Gusto API to get all contractors of company `Gusto.company_id()`
        and returns deserialized json response.
        """
        response = requests.get(
            BASE_URL + f"/v1/companies/{self.company_id()}/contractors",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.access_token}"
            })
        return response.json()

    def get_employees(self):
        """
        Makes a request to the Gusto API to get all employees of company `Gusto.company_id()` and returns
        deserialized json response.
        """
        response = requests.get(
            BASE_URL + f"/v1/companies/{self.company_id()}/employees",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.access_token}"
            })
        employees = response.json()
        return employees
