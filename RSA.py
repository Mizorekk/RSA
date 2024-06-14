from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA3_256
from PIL import Image
import io

# Importowanie funkcji z pliku trng_generator
from trng_gen import generate_random_data

class TRNG:
    def __init__(self):
        self.allBytes = bytes(generate_random_data())
        self.offset = 0

    def getRandomBytes(self, n):
        self.offset += n
        if self.offset > len(self.allBytes):
            self.allBytes = bytes(generate_random_data())
            self.offset = n
        return self.allBytes[self.offset - n:self.offset]

def generate_rsa_keys(trng):
    # Generate RSA keys using the TRNG instance
    key = RSA.generate(2048, randfunc=trng.getRandomBytes)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    return private_key, public_key

def sign_message(private_key, message):
    rsa_key = RSA.import_key(private_key)
    h = SHA3_256.new(message)
    signature = pkcs1_15.new(rsa_key).sign(h)
    return signature

def verify_signature(public_key, message, signature):
    rsa_key = RSA.import_key(public_key)
    h = SHA3_256.new(message)
    try:
        pkcs1_15.new(rsa_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

if __name__ == "__main__":
    # Load the image and convert it to bytes
    with Image.open('cat.jpg') as img:
        byte_arr = io.BytesIO()
        img.save(byte_arr, format='JPEG')
        byte_arr = byte_arr.getvalue()

    with Image.open('eepyCat.jpg') as img:
        byte_arr2 = io.BytesIO()
        img.save(byte_arr2, format='JPEG')
        byte_arr2 = byte_arr2.getvalue()

    # Create a TRNG instance
    trng = TRNG()

    # Generate RSA keys using the TRNG instance
    private_key, public_key = generate_rsa_keys(trng)

    # Save the private key
    with open("private_key.pem", "wb") as f:
        f.write(private_key)

    # Save the public key
    with open("public_key.pem", "wb") as f:
        f.write(public_key)

    # Hash the image data
    image_hash = SHA3_256.new(byte_arr).digest()
    image_hash2 = SHA3_256.new(byte_arr2).digest()

    # Sign the hashed image data
    signature = sign_message(private_key, image_hash)
    signature2 = sign_message(private_key, image_hash2)

    #check if signatures are the same // integralność
    print("Integrity test - Signatures are the same: ", signature == signature2)

    private_key2, public_key2 = generate_rsa_keys(trng)

    # Save the private key 2
    with open("private_key2.pem", "wb") as f:
        f.write(private_key2)

    # Save the public key 2
    with open("public_key2.pem", "wb") as f:
        f.write(public_key2)

    image_hash3 = SHA3_256.new(byte_arr).digest()
    signature3 = sign_message(private_key2, image_hash3)

    #check sign1 and sign3 // niezbywalność
    print("Inalienability - Signatures are the same: ", signature == signature3)




