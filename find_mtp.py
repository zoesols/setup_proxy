import subprocess
import re
import requests

def send_discord_webhook(msg):
    webhook_url = 'https://discord.com/api/webhooks/1230519482301026435/qs0bd41cNqdVsfyWqKfK45zh6Q6rEekxYs4V6S_c-yi3G4PC9-_n5JP-gXZiEF5cUuOZ' # kmarket
    payload = {"content" : msg}
    response = requests.post(webhook_url, json=payload)

try:
    mtp = subprocess.check_output("hwinfo --usb | grep -A 2 MTP", shell=True).decode('utf-8')
    serials = re.compile(r'Serial ID: "([\s\S]+?)"').findall(mtp)
    serials = list(set(serials))
    host = subprocess.check_output("hostname").decode('utf-8').strip()
    if len(serials) > 0:
        msg = f'**[{host}]**'
        for s in serials:
            m = f'\n- {s} : MTP'
            msg += m
        send_discord_webhook(msg)

except:
    pass