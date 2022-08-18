from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


with open("private_key.der","rb") as f:
  key = RSA.import_key(f.read())
with open("offsite_database.txt","rb") as f:
  content = f.read()
  h = SHA256.new(content)
  signature = pkcs1_15.new(key).sign(h)
with open("offsite_database_signature.txt","wb") as k:
  k.write(signature)