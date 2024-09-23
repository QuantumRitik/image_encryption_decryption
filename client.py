import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from PIL import Image
import io

# Function to encrypt AES key using RSA
def encrypt_aes_key(aes_key, public_key_path):
    public_key = RSA.import_key(open(public_key_path).read())
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    return encrypted_aes_key

# Function to encrypt the image using AES
def encrypt_image_with_aes(image_path, aes_key):
    image = Image.open(image_path)

    # Convert the image to bytes
    img_byte_array = io.BytesIO()
    image.save(img_byte_array, format="JPEG")  # Save the image explicitly as JPEG
    img_bytes = img_byte_array.getvalue()

    # Generate IV and encrypt the image using AES
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(img_bytes, AES.block_size))

    return encrypted_data, iv

# Set up the client to send encrypted data over a socket
def rsa_client():
    # Generate AES key
    aes_key = get_random_bytes(16)  # AES 128-bit key

    # Encrypt the image with AES
    encrypted_image_data, iv = encrypt_image_with_aes('original.jpg', aes_key)

    # Encrypt AES key with server's RSA public key
    encrypted_aes_key = encrypt_aes_key(aes_key, "public_key.pem")

    # Set up socket and connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65432))

    # Send the encrypted AES key
    client_socket.send(encrypted_aes_key)

    # Send the IV
    client_socket.send(iv)

    # Send the encrypted image data in chunks
    client_socket.sendall(encrypted_image_data)

    print("AES key, IV, and encrypted image data sent to server.")

    client_socket.close()

if __name__ == "__main__":
    rsa_client()
