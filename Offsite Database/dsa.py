from ecdsa import SigningKey
private_key = SigningKey.generate() # uses NIST192p curve method
signature = private_key.sign(b"Educative authorizes this shot")
public_key = private_key.verifying_key
 
print("Verified:", public_key.verify(signature, b"Educative authorizes this shot"))