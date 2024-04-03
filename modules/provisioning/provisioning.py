import requests
import json
import os
import platform
import time

MAX_RETRIES = 3
TIMEOUT_MS = 20000
WIDEVINE_UUID = "EDEF8BA979D64ACEL-A3C827DCD51D21EDL"
PROXY_URL = "https://widevine-proxy.appspot.com/proxy"

class WidevineProvisioner:
    def __init__(self):
        self.run_attempt_count = 0

    def build_user_agent_string(self):
        parts = [
            "AndroidRemoteProvisioner",
            platform.system(),
            platform.release(),
            platform.version(),
            platform.machine()
        ]
        return "/".join(parts)

    def is_widevine_provisioning_needed(self):
        try:
            if not os.path.exists("/system/lib64/libdrmclearkeyplugin.so"):
                # Not a provisioning 4.0 device.
                print("Not a WV provisioning 4.0 device. No provisioning required.")
                return False
            system_id = int(os.popen("getprop ro.boot.widevine.system_id").read().strip())
            if system_id != -1:
                print("This device has already been provisioned with its WV cert.")
                # First stage provisioning probably complete
                return False
            return True
        except Exception as e:
            print("Error while checking provisioning status:", e)
            return False

    def provision_widevine(self):
        try:
            request_data = {
                "request": {
                    "mediaDrmUuid": WIDEVINE_UUID
                }
            }
            headers = {
                "User-Agent": self.build_user_agent_string(),
                "Content-Type": "application/json"
            }
            response = requests.post(PROXY_URL, data=json.dumps(request_data), headers=headers, timeout=TIMEOUT_MS / 1000)
            response_data = response.json()
            if response.status_code == 200 and response_data.get("status") == "success":
                print("Provisioning successful.")
                return "success"
            else:
                print("WV Provisioning failed.")
                return "failure"
        except requests.exceptions.Timeout:
            print("Request timed out during WV Provisioning.")
            return "retry"
        except Exception as e:
            print("Unexpected error during WV Provisioning:", e)
            return "retry"

    def do_work(self):
        if self.is_widevine_provisioning_needed():
            print("Starting WV provisioning. Current attempt:", self.run_attempt_count)
            while self.run_attempt_count < MAX_RETRIES:
                result = self.provision_widevine()
                if result == "success":
                    return "success"
                elif result == "failure":
                    return "failure"
                else:
                    print("Retrying WV provisioning after 5 seconds.")
                    time.sleep(5)
                    self.run_attempt_count += 1
            print("Reached maximum retry attempts for WV provisioning.")
            return "failure"
        return "success"

provisioner = WidevineProvisioner()
result = provisioner.do_work()
print("Result:", result)
