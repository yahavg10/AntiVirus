# Import hashlib library (md5 method is part of it)
import hashlib

# File to check
file_name = 'filename.exe'
  

# Open,close, read file and calculate MD5 on its contents 
with open(file_name, 'rb') as file_to_check:
    # read contents of the file
    data = file_to_check.read()    
    # pipe contents of the file through
    filemd5 = hashlib.md5(data).hexdigest()
#check env var