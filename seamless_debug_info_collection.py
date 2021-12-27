#!/usr/bin/env python3
import requests
import argparse
import urllib3
import sys
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RedfishSession(requests.Session):
    def __init__(self, cli_args):
        super().__init__()

        self.prefix = "https://" + cli_args.IP
        self.verify = cli_args.verify

        # Authenticate and get session cookie
        token_request = self.post(
            "/redfish/v1/SessionService/Sessions",
            json={
                "UserName": cli_args.username,
                "Password": cli_args.password})
        x_auth_token = token_request.headers["X-Auth-Token"]
        self.location = token_request.headers["Location"]
        self.headers.update({"X-Auth-Token": x_auth_token})

    def request(self, method, url, *pargs, **kwargs):
        try:
            resp = super().request(method, self.prefix + url, *pargs, **kwargs)
        except requests.exceptions.SSLError:
            sys.exit('''SSL verification failed. Please check your certificates.
You can optionally skip SSL certificate verification with '--no-verify'.''')
        resp.raise_for_status()
        return resp

    def __exit__(self, *pargs):
        self.delete(self.location)
        super().__exit__(pargs)


class Debug_Info_Collection(object):
    """
    Wrapper Class for Inband and OOB system data collection
    """

    def __init__(self) -> None:
        super().__init__() 

if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sut_ip", help="sut IP Address")
    parser.add_argument("--bmc_ip", help="BMC IP Address")
    parser.add_argument('-u', '--username', default='debuguser')
    parser.add_argument('-p', '--password', default='0penBmc1')
    parser.add_argument(
        "--no-verify",
        dest='verify',
        action="store_false",
        default=False,
        help="Set session verification to false")
    args = parser.parse_args()
