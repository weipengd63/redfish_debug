#!/usr/bin/env python3
from logging import exception
import requests
import argparse
import urllib3
import sys
import time
import os
import configparser
from remote_ssh import paramikoServer

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RedfishSession(requests.Session):
    def __init__(self, ip, user, password, ifVerify):
        super().__init__()

        self.prefix = "https://" + ip
        self.verify = ifVerify

        # Authenticate and get session cookie
        token_request = self.post(
            "/redfish/v1/SessionService/Sessions",
            json={
                "UserName": user,
                "Password": password})
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
    parser.add_argument('-m', "--data", default='All')
    parser.add_argument(
        "--no-verify",
        dest='verify',
        action="store_false",
        default=False,
        help="Set session verification to false")
    args = parser.parse_args()

    #created ssh connection to SUT and get its BMC IP
    
    sut_IP=args.sut_ip
    sut_username="root"
    sut_password="password"
    bmc_IP=args.bmc_ip
    bmc_username=args.username
    bmc_password=args.password

    sut_command= "sh /home/Set_BMC_User.sh"
    curPath = os.path.abspath(os.path.dirname(__file__))
    print(curPath)
    script_local_path=curPath+"/Set_BMC_User.sh"

    if bmc_IP is None:
        try:
            sutserver = paramikoServer(sut_IP, sut_username, sut_password)
            print("Establish ssh seesion to {}.\n".format(sut_IP))
            sutserver.connectSsh()
            if not sutserver.isFileExists("/home/Set_BMC_User.sh"):
                try:
                    print("script doesn't exist on SUT, upload from host")
                    sutserver.sendFile(script_local_path,"/home/Set_BMC_User.sh")
                except:
                    print("Error during sending files to SUT")
            print("Run command: {}.\n".format(sut_command))
            stdout = sutserver.runCommand(sut_command)
        except:
            print("Error inside ssh and execute")
        finally:
            sutserver.closeSSH()

        bmc_IP=str(stdout[-1]).replace('\n', '')
    print(bmc_IP)
    
    cf = configparser.ConfigParser()
    cf.read(curPath+"/ingredient.cfg")
    secs = cf.sections()
    #print(secs)

    #create redfish connection and collect system metadata
    with RedfishSession(ip=bmc_IP,user=bmc_username,password=bmc_password,ifVerify=args.verify) as redfish_session:
    # Print some basic BMC info.
        for section in secs:
            data_name = section.strip()
            print(data_name)
            data_category = cf.get(data_name,"Category")
            print(data_category)
            data_path = cf.get(data_name,"Path")

            if data_category == 'version':
                #print("start read data")
                data_key = cf.get(data_name,"Key").split(',')
                data_raw = redfish_session.get(data_path).json()
                print(data_key)
                data = "{}: ".format(data_name)
                for k in data_key:
                    data += "{}, ".format(data_raw[k])
                print(data+"\n")
            elif data_category == 'log': 
                #data_path += str(cf.get(data_name,"Skip"))  
                print(data_path)           
                while data_path is not None:
                    data_raw = redfish_session.get(data_path).json()
                    for entry in data_raw['Members']:
                        print('{}: {}, severity: {}'.format(entry['Created'], entry['Message'],entry['Severity']))
                    data_path = data_raw.get('Members@odata.nextLink')
                    print(data_raw.get('Members@odata.count'))
                    #data_path = None
            elif data_category == 'HWinfo':
                data_raw = redfish_session.get(data_path).json()
                data_key = cf.get(data_name,"Key").split(',')
                members = data_raw["Members"]
                for m in members: 
                    item_path = m["@odata.id"]
                    item_name = item_path.split('/')[-1]
                    #print(item_name)
                    try:
                        m_raw = redfish_session.get(item_path).json()
                        #print(m_raw)
                        data = "{}: ".format(item_name)
                        for k in data_key:
                            data += "{}, ".format(m_raw[k])
                        print(data)
                    except Exception as e:
                        #print("Memory {} info has error {} that can't be proccessed".format(item_name,e))
                        print("No DIMM on {} slot".format(item_name))
                        continue
            
        """
        bmc_data = redfish_session.get("/redfish/v1/Managers/bmc").json()
        description = bmc_data["Description"]
        model = bmc_data["Model"]
        version = bmc_data["FirmwareVersion"]
        print(f"{description}: {model}, {version}")
        """