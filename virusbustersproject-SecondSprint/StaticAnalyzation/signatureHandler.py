import time
import firebase_admin
from firebase_admin import db
import hashlib
import json


def calculate_md5(file):
    with open(file, "br") as f:
        return hashlib.md5(f.read()).hexdigest()


def handleSignature(file, shouldDoDynamic, session):
    md5 = calculate_md5(file)
    session = db.reference("/Sessions/" + session)
    session.update(md5)

    md5_data_ref = db.reference("/Results")
    if db.reference("/Results/" + md5).get() is not None:
        db.reference("/StaticQueue").set('{"' + file + '":{"md5":' + '"' + md5 + '"}}')


def main():
    cred_obj = firebase_admin.credentials.Certificate("../keys/virusbustersdb-firebase-adminsdk-ythhu-e28926a1ed.json")
    default_app = firebase_admin.initialize_app(cred_obj, {
        'databaseURL': 'https://virusbustersdb-default-rtdb.europe-west1.firebasedatabase.app/'
    })

    ref = db.reference("/FileQueue")
    while True:
        files = ref.get()
        for key, value in files.items():
            handleSignature(key, value['shouldDoDynamic'])

        time.sleep(2)


if __name__ == '__main__':
    main()
