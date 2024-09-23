import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import unpad
from PIL import Image
import io

# Function to decrypt AES key using RSA
def decrypt_aes_key(encrypted_aes_key, private_key_path):
    private_key = RSA.import_key(open(private_key_path).read())
    rsa_cipher = PKCS1_OAEP.new(private_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)
    return aes_key

# Function to decrypt the image using AES
def decrypt_image_with_aes(encrypted_data, aes_key, iv):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    
    # Debugging: Check the length of decrypted data
    print(f"Decrypted image data size: {len(decrypted_data)} bytes")

    # Try to open the decrypted data as an image
    try:
        decrypted_image = Image.open(io.BytesIO(decrypted_data))
        return decrypted_image
    except Exception as e:
        # Debugging: If an error occurs, save the raw decrypted data to a file for inspection
        with open("decrypted_image_raw.bin", "wb") as f:
            f.write(decrypted_data)
        print(f"Error: {str(e)}")
        print("Raw decrypted data saved to 'decrypted_image_raw.bin' for inspection.")
        raise

# Set up the server to receive data over a socket
def rsa_server():
    # Initialize socket for network communication
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('192.168.150.144', 65432))  # Bind to localhost and port 65432
    server_socket.listen(1)
    
    print("Server listening for incoming connections...")

    client_socket, client_address = server_socket.accept()
    print(f"Connection established with {client_address}")

    # Receive the encrypted AES key
    encrypted_aes_key = client_socket.recv(256)  # RSA-encrypted AES key (usually 256 bytes for RSA-2048)

    # Decrypt the AES key using the server's RSA private key
    aes_key = decrypt_aes_key(encrypted_aes_key, "private_key.pem")

    # Receive the IV (initialization vector) used for AES encryption
    iv = client_socket.recv(16)  # IV should be 16 bytes for AES

    # Receive the encrypted image data
    encrypted_image_data = b""
    while True:
        packet = client_socket.recv(4096)
        if not packet:
            break
        encrypted_image_data += packet

    # Debugging: Check the size of received encrypted image data
    print(f"Encrypted image data size: {len(encrypted_image_data)} bytes")

    # Decrypt the image using the AES key and IV
    decrypted_image = decrypt_image_with_aes(encrypted_image_data, aes_key, iv)

    # Save the decrypted image
    decrypted_image.save("decrypted_image.png", format="PNG")
    print("Image decrypted and saved as 'decrypted_image.png'.")

    client_socket.close()

if __name__ == "__main__":
    rsa_server()
