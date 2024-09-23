from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from PIL import Image
import io
import os
from Crypto.Hash import SHA256, HMAC

def encrypt_image(input_image_path, output_image_path, key):
    # Load the image
    image = Image.open(input_image_path)
    # Generate a random IV
    iv = get_random_bytes(AES.block_size)
    # Get a unique identifier from the filename
    image_hash = SHA256.new(os.path.basename(input_image_path).encode("utf-8")).hexdigest()
    # Combine key-specific value with random string (nonce) using HMAC
    key_specific = HMAC.new(key, msg=image_hash.encode("utf-8"), digestmod=SHA256).digest()
    unique_iv = HMAC.new(key_specific, msg=os.urandom(16), digestmod=SHA256).digest()[:16]
    if len(unique_iv) != 16:
        raise ValueError("Unexpected IV length. Encryption aborted.")
    # Convert the image to bytes
    img_byte_array = io.BytesIO()
    image.save(img_byte_array, format=image.format)
    img_bytes = img_byte_array.getvalue()
    # Initialize AES cipher
    cipher = AES.new(key, AES.MODE_CBC, unique_iv)
    # Encrypt the image data with padding
    padded_data = pad(img_bytes, AES.block_size)
    encrypted_data = iv + cipher.encrypt(padded_data)
    # Write the encrypted data to the output image file
    with open(output_image_path, 'wb') as f:
        f.write(encrypted_data)
    # Save the IV to a separate file with a filename related to the image
    iv_path = os.path.join(os.path.dirname(output_image_path), f"{os.path.basename(input_image_path)}.iv")
    with open(iv_path, 'wb') as f:
        f.write(unique_iv)
    print(f"Encryption successful. Encrypted image saved to '{output_image_path}'.")
    print(f"IV file saved to '{iv_path}'.")

def decrypt_image(input_image_path, output_image_path, key, iv_path):
    # Read the IV from the separate file
    with open(iv_path, 'rb') as f:
        unique_iv = f.read()
    # Read the encrypted data
    with open(input_image_path, 'rb') as f:
        encrypted_data = f.read()
    # Separate the IV from the encrypted data
    iv = encrypted_data[:AES.block_size]
    encrypted_data = encrypted_data[AES.block_size:]
    # Initialize AES cipher
    cipher = AES.new(key, AES.MODE_CBC, unique_iv)
    # Decrypt the image data
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    # Convert decrypted bytes to image
    decrypted_image = Image.open(io.BytesIO(decrypted_data))
    # Save the decrypted image
    decrypted_image.save(output_image_path, format=decrypted_image.format)
    print(f"Decryption successful. Decrypted image saved to '{output_image_path}'.")


if __name__ == "__main__":
    choice = input("Enter 'e' to encrypt or 'd' to decrypt: ").lower()
    key = 'UZ4i59vPgLRT16s8FZ4i81vPgLRT16qk'
    key = bytes(key, encoding="utf-8")

    if choice == 'e':
        input_image_path = input("Enter the path of the image to encrypt: ")
        output_image_path = input("Enter the output path for the encrypted image: ")
        encrypt_image(input_image_path, output_image_path, key)
    
    elif choice == 'd':
        input_image_path = input("Enter the path of the encrypted image: ")
        output_image_path = input("Enter the output path for the decrypted image: ")
        iv_path = input("Enter the path of the IV file: ")
        decrypt_image(input_image_path, output_image_path, key, iv_path)
    
    else:
        print("Invalid choice. Please enter 'e' for encryption or 'd' for decryption.")
