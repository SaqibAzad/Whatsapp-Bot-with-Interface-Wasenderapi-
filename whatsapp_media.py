import base64
import requests
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def get_decryption_keys(media_key_b64, media_type='image', length=112):
    info_strings = {
        'image': b'WhatsApp Image Keys',
        'video': b'WhatsApp Video Keys',
        'audio': b'WhatsApp Audio Keys',
        'document': b'WhatsApp Document Keys',
    }
    info = info_strings[media_type]
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(base64.b64decode(media_key_b64))

def decrypt_whatsapp_media(media_key, url, output_path, media_type='image'):
    resp = requests.get(url)
    resp.raise_for_status()
    enc_file = resp.content

    keys = get_decryption_keys(media_key, media_type)
    iv = keys[:16]
    cipher_key = keys[16:48]
    ciphertext = enc_file[:-10]  # Remove last 10 bytes (MAC)

    cipher = Cipher(algorithms.AES(cipher_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(output_path, 'wb') as f:
        f.write(plaintext)
    return output_path