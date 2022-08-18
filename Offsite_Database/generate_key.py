from Crypto.PublicKey import RSA

key = RSA.generate(2048)
f = open('private_key.der','wb')
f.write(key.export_key('DER'))
public_key = key.public_key()
f = open('public_key.der','wb')
f.write(public_key.export_key('DER'))
f.close()
