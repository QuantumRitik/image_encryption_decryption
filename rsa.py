from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image
import io
import os

# Symmetric encryption using AES (for the image)
def encrypt_image_with_aes(input_image_path, output_image_path, aes_key):
    # Load the image
    image = Image.open(input_image_path)
    # Convert the image to bytes
    img_byte_array = io.BytesIO()
    image.save(img_byte_array, format=image.format)
    img_bytes = img_byte_array.getvalue()

    # Generate a random IV
    iv = get_random_bytes(AES.block_size)
    # Initialize AES cipher
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    # Encrypt the image data with padding
    padded_data = pad(img_bytes, AES.block_size)
    encrypted_data = iv + cipher.encrypt(padded_data)

    # Write the encrypted data to the output image file
    with open(output_image_path, 'wb') as f:
        f.write(encrypted_data)
    
    print(f"Image encrypted and saved to {output_image_path}")

def decrypt_image_with_aes(input_image_path, output_image_path, aes_key):
    # Read the encrypted data
    with open(input_image_path, 'rb') as f:
        encrypted_data = f.read()

    # Separate the IV from the encrypted data
    iv = encrypted_data[:AES.block_size]
    encrypted_data = encrypted_data[AES.block_size:]

    # Initialize AES cipher
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    # Decrypt the image data
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    # Convert decrypted bytes to image
    decrypted_image = Image.open(io.BytesIO(decrypted_data))
    # Save the decrypted image
    decrypted_image.save(output_image_path, format=decrypted_image.format)
    print(f"Image decrypted and saved to {output_image_path}")

# RSA Key Pair Generation
def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# RSA Encryption of the AES Key
def encrypt_aes_key_with_rsa(aes_key, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key

# RSA Decryption of the AES Key
def decrypt_aes_key_with_rsa(encrypted_key, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)
    return aes_key

if __name__ == "__main__":
    choice = input("Enter 'e' to encrypt or 'd' to decrypt using RSA and AES: ").lower()

    if choice == 'e':
        # Encryption process
        input_image_path = input("Enter the path of the image to encrypt: ")
        output_image_path = input("Enter the output path for the encrypted image: ")
        
        # Generate AES key for encrypting the image
        aes_key = get_random_bytes(16)  # AES 128-bit key

        # Encrypt the image with AES
        encrypt_image_with_aes(input_image_path, output_image_path, aes_key)

        # Generate RSA key pair for key sharing
        private_key, public_key = generate_rsa_keypair()

        # Encrypt the AES key using RSA public key
        encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)

        # Save the encrypted AES key and RSA keys
        with open("encrypted_aes_key.bin", 'wb') as f:
            f.write(encrypted_aes_key)

        with open("public_key.pem", 'wb') as f:
            f.write(public_key)

        with open("private_key.pem", 'wb') as f:
            f.write(private_key)

        print("Image encryption successful.")
        print("Encrypted AES key saved to 'encrypted_aes_key.bin'.")
        print("RSA public key saved to 'public_key.pem'.")
        print("RSA private key saved to 'private_key.pem'.")

    elif choice == 'd':
        # Decryption process
        input_image_path = input("Enter the path of the encrypted image: ")
        output_image_path = input("Enter the output path for the decrypted image: ")

        # Load the encrypted AES key and RSA private key
        with open("encrypted_aes_key.bin", 'rb') as f:
            encrypted_aes_key = f.read()

        with open("private_key.pem", 'rb') as f:
            private_key = f.read()

        # Decrypt the AES key using RSA private key
        aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)

        # Decrypt the image using AES
        decrypt_image_with_aes(input_image_path, output_image_path, aes_key)

        print("Image decryption successful.")

    else:
        print("Invalid choice. Please enter 'e' for encryption or 'd' for decryption.")
