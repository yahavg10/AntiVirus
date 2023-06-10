import time
import yara
import firebase_admin
from firebase_admin import db
import json
import subprocess
import os
import subprocess

def run_yara_on_file(address, rules, md5):
    report = ""

    # checking malicuos ips an urls
    ips = yara.compile(filepath="yara_rules/ip_rules.yara").match(address)
    db_ips = db.reference("/MaliciousIpsAndUrls/MaliciousIPs").get()
    #for ip in ips['main'][0]['strings']:
     #   print(ip['data'] in db_ips)
     #   if ip['data'] in db_ips:
     #       report += "ip: " + ip['data']

    #for ip in ips['main'][1]['strings']:
    #    print(ip['data'] in db_ips)
     #   if ip['data'] in db_ips:
    #        report += "url: " + ip['data']

    output = rules.match(address, rules)

    # //checking file for malicous api calls and asm instructions
    for file in output.keys():
        for rule in output[file]:
            report = report + rule['rule'] + ":" + str(rule['matches']) + '\n'
    print(address)
    print(report)
    if report == "":
        report = "None"
        """
    db.reference("/Results").child(md5).update({"StaticReport": report})
"""




def handleFakingVMInput():
    subprocess.call(args=["C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage","controlvm","SandBoxVM","keyboardputstring","maor@gmail.com"])
    time.sleep(10)






def main():
    cred_obj = firebase_admin.credentials.Certificate("../keys/virusbustersdb-firebase-adminsdk-ythhu-e28926a1ed.json")
    default_app = firebase_admin.initialize_app(cred_obj, {
        'databaseURL': 'https://virusbustersdb-default-rtdb.europe-west1.firebasedatabase.app/'
    })
    ref = db.reference("/FileQueue")
    rules = yara.compile(filepaths={
        'namespace1': 'yara_rules/virus_identification_rules/keylogger_rules.yara',
        'namespace2': 'yara_rules/virus_identification_rules/dll_injection_rules.yara',
        'namespace3': 'yara_rules/virus_identification_rules/ProcessHiding_rules.yara'
    })

    while True:
        addresses = ref.get()
        for key, value in addresses.items():
            run_yara_on_file(value["address"], rules, key)


        time.sleep(2)  # switch this with DB trigger,perhaps will be more efficent


if __name__ == '__main__':
    main()
