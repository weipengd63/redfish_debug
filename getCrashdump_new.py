import requests
import argparse
import urllib3
import sys
import time
from pathlib import Path

requests.packages.urllib3.disable_warnings()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument("IP", help="BMC IP Address")
parser.add_argument('-u', '--username', default='debuguser')
parser.add_argument('-p', '--password', default='0penBmc1')
parser.add_argument(
    "--trigger",
    action="store_true",
    default=False,
    help="Trigger an On-Demand Crashdump before retrieving logs")
parser.add_argument(
    "--clear",
    action="store_true",
    default=False,
    help="Clear logs when completed")
parser.add_argument(
    "--no-verify",
    dest='verify',
    action="store_false",
    default=False,
    help="Set session verification to false")
args = parser.parse_args()

with requests.session() as redfish_session:
    bmc_url_prefix = "https://{}".format(args.IP)
    trigger_crashdump = "/redfish/v1/Systems/system/LogServices/Crashdump/Actions/Oem/Crashdump.OnDemand"
    clear_logs = "/redfish/v1/Systems/system/LogServices/Crashdump/Actions/LogService.ClearLog"
    entries_path = "/redfish/v1/Systems/system/LogServices/Crashdump/Entries"
    try:
        token_request = redfish_session.post(
            bmc_url_prefix +
            "/redfish/v1/SessionService/Sessions",
            json={
                "UserName": args.username,
                "Password": args.password},
            verify=args.verify)
    except requests.exceptions.SSLError:
        sys.exit('''SSL verification failed. Please check your certificates.
You can optionally skip SSL certificate verification with '--no-verify'.''')

    token_request.raise_for_status()
    x_auth_token = token_request.headers["X-Auth-Token"]
    location = token_request.headers["Location"]
    redfish_session.headers.update({"X-Auth-Token": x_auth_token})
    try:
        # Trigger a new crashdump if requested
        if args.trigger:
            try:
                trigger_response = redfish_session.post(
                    bmc_url_prefix + trigger_crashdump, verify=args.verify)
                trigger_response.raise_for_status()
                # Get the Task Monitor
                #print(trigger_response)
                task_mon = trigger_response.headers["Location"]
                print("Task Monitor: {}".format(task_mon))
                task_mon_response = redfish_session.get(
                    bmc_url_prefix + task_mon, verify=args.verify)
                # Wait for the crashdump to complete (task monitor will return
                # non-202 result)
                while task_mon_response.status_code == requests.codes.accepted:
                    # Wait a few seconds then check again
                    time.sleep(3)
                    #print("recheck")
                    task_mon_response = redfish_session.get(
                        bmc_url_prefix + task_mon, verify=args.verify)
            except Exception as e:
                print(e)
        
        # Get all the crashdump log entries
        entries_response = redfish_session.get(
            bmc_url_prefix + entries_path, verify=args.verify)
        entries_response.raise_for_status()
        entries_json = entries_response.json()
        # Go through each crashdump log entry and download it
        #print (entries_json)
        for entry in entries_json["Members"]:
            print(entry["Message"])
            entry_response = redfish_session.get(
                bmc_url_prefix + entry["Message"], verify=args.verify)
            entry_response.raise_for_status()
            # Write the crashdump content with the file name provided in the
            # "AdditionalDataURI" field
            #print(entry_response.content)
            output_file = entry["Message"].rpartition('/')[-1].replace(':', '_')
            output_file_path = Path.cwd(
            ) / "results/{}".format(output_file)
            output_file_path.write_bytes(entry_response.content)
            print("crashdump json file {} has been collected".format(output_file))

        # Clear the crashdumps if requested
        if args.clear:
            clear_response = redfish_session.post(
                bmc_url_prefix + clear_logs, verify=args.verify)
            clear_response.raise_for_status()
            print("crash dump log has been cleared as request")
    finally:
        logout_request = redfish_session.delete(bmc_url_prefix + location)
        logout_request.raise_for_status()
