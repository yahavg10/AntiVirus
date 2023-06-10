#This file is responsible for making sure that all the fields in the registration process of a
 #new user are indeed correct and there is no attempt to "break" 
 #the registration system in any possible way
import re
from email_validator import validate_email, EmailNotValidError
 
def check(email):
    try:
      # validate and get info
        v = validate_email(email)
        # replace with normalized form
        email = v["email"] 
        print("True")
    except EmailNotValidError as e:
        # email is not valid, exception message is human-readable
        print(str(e))

password = ""
if re.fullmatch(r'^(?=(.*[a-z]){3,})(?=(.*[A-Z]){2,})(?=(.*[0-9]){2,})(?=(.*[!@#$%^&*()\-__+.]){1,}).{8,}$', password):
    print("True")
else:
    print("false")