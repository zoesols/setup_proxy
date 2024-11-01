import subprocess
import re
import requests

def send_discord_webhook(msg):
    webhook_url = 'https://discord.com/api/webhooks/1230519482301026435/qs0bd41cNqdVsfyWqKfK45zh6Q6rEekxYs4V6S_c-yi3G4PC9-_n5JP-gXZiEF5cUuOZ' # kmarket
    payload = {"content" : msg,
  }
    response = requests.post(webhook_url, json=payload)

try:
    tether = subprocess.check_output("hwinfo --usb | grep -A 2 tethering", shell=True).decode('utf-8')
    serials_tether = re.compile(r'Serial ID: "([\s\S]+?)"').findall(tether)
    serials_tether = list(set(serials_tether))
    mtp = subprocess.check_output("hwinfo --usb | grep -A 2 MTP", shell=True).decode('utf-8')
    serials_mtp = re.compile(r'Serial ID: "([\s\S]+?)"').findall(mtp)
    serials_mtp = list(set(serials_mtp))
    host = subprocess.check_output("hostname").decode('utf-8').strip()
    if len(serials_tether) > 0 or len(serials_mtp) > 0:
        qty = len(serials_tether) + len(serials_mtp)
        msg = f'**[{host}]**\n* Connected Device : {qty}'
        if len(serials_tether) > 0:
            msg += f'\n- Tethering({len(serials_tether)}) : '
            for t in serials_tether:
                msg += t + ', '
            msg = msg[:-2]
        if len(serials_mtp) > 0:
            msg += f'\n- MTP({len(serials_mtp)}) : '
            for s in serials_mtp:
                msg += s + ', '
            msg = msg[:-2]
        send_discord_webhook(msg)
    else:
        msg = f'**[{host}]**\n__* No Device Connected__'

except:
    pass