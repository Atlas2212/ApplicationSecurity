from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
def check_signature(public_key,signature,message_file,modified_message_file):
  with open(public_key,"rb") as f:
    key = RSA.import_key(f.read())
  with open(signature,"rb") as s:
    signature = s.read()
  with open(message_file,"rb") as m:
    message = m.read()
  with open(modified_message_file,"rb") as m:
    message_modified = m.read()
  h = SHA256.new(message)
  h_modified = SHA256.new(message_modified)

  try:
    pkcs1_15.new(key).verify(h, signature)
    valid_signature = True
  except (ValueError, TypeError):
    valid_signature = False

  try:
    pkcs1_15.new(key).verify(h_modified, signature)
    valid_signature_modified = True
  except (ValueError, TypeError):
    valid_signature_modified = False

  return(valid_signature,valid_signature_modified)