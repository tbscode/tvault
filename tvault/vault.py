import base64
import signal
import getpass
import sys
import shutil
import zipfile
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import inquirer
import time

def find_available_vaults():
    return [name for name in os.listdir() if os.path.isdir(name) and name.endswith('.tvault')]

def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode("latin-1"))
    key = SHA256.new(key).digest()
    IV = source[:AES.block_size]
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])
    padding = data[-1]
    if data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid padding...")
    return data[:-padding]

def decrypt_folder(key, folder_name):
    with open(f"{folder_name}.encrypted", "rb") as f:
        data = f.read()
        decrypted = decrypt(bytes(key, "utf-8"), data, False)

    with open(f"{folder_name}.decrypted.zip", "wb") as f:
        f.write(decrypted)
        f.close()

    shutil.unpack_archive(f"{folder_name}.decrypted.zip", folder_name)
    os.remove(f"{folder_name}.decrypted.zip")
    os.remove(f"{folder_name}.encrypted")

def encrypt(key, source, encode=True):
    key = SHA256.new(key).digest()
    IV = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size
    source += bytes([padding]) * padding
    data = IV + encryptor.encrypt(source)
    return base64.b64encode(data).decode("latin-1") if encode else data

def encrypt_folder(key, folder_path):
    shutil.make_archive(f"{folder_path}.toencrypt", 'zip', folder_path)
    with open(f"{folder_path}.toencrypt.zip", "rb") as f:
        encrypted = encrypt(bytes(key, "utf-8"), f.read(), False)

    with open(f"{folder_path}.encrypted", "wb") as f:
        f.write(encrypted)
        f.close()

    os.remove(f"{folder_path}.toencrypt.zip")
    shutil.rmtree(folder_path)

def do_decrypt(vault, interactive=True, password=None):
    assert os.path.exists(f"{vault}.encrypted"), f"File not found, '{vault}.encrypted'"

    if interactive:
        password = getpass.getpass(prompt="Enter password:")
    decrypt_folder(password, vault)

    return password

def do_encrypt(vault, interactive=True, password=None):
    assert os.path.exists(f"{vault}"), f"File not found, '{vault}'"

    if interactive:
        password = getpass.getpass(prompt="Enter password:")
    encrypt_folder(password, vault)

    return password

def main():
    CONTEXT = sys.argv[1] if len(sys.argv) > 1 else None
    
    if CONTEXT is None:
        CONTEXT = "open"

    NO_INQUIRY = sys.argv[2] if len(sys.argv) > 2 else False

    AVAILABLE_CONFIGS = find_available_vaults()

    if NO_INQUIRY:
        if CONTEXT == "open":
            vault = NO_INQUIRY
            password = do_decrypt(vault, interactive=True)
            with open(f"{vault}/.password", "w+") as f:
                print("Cached password inside the vault.")
                f.write(password)
                f.close()
        elif CONTEXT == "close":
            vault = NO_INQUIRY
            with open(f"{vault}/.password", "r") as f:
                password = f.read()
                f.close()
            os.remove(f"{vault}/.password")
            print("Password cached inside the vault is used.")
            do_encrypt(vault, interactive=False, password=password)
    else:
        if CONTEXT == "open":
            questions = [
              inquirer.List('which_vault_to_decrypt',
                            message="Which Vault would you like to decrypt?",
                            choices=AVAILABLE_CONFIGS
                        ),
            ]

            inquiry = inquirer.prompt(questions)
            vault = inquiry["which_vault_to_decrypt"]

            password = do_decrypt(vault, interactive=True)

            print(f"Vault '{vault}' decrypted successfully!")
            print(f"The vault will be auto closed in 2 minutes. ( If you don't cancel this script )")

            def signal_handler(sig, frame):
                print('You pressed Ctrl+C!')
                print("Should I close the vault? (y/n)")
                close = input()
                if close.lower() == "y":
                    do_encrypt(vault, interactive=False, password=password)
                    sys.exit(0)
                else:
                    print("Vault will not be closed.")
                    with open(f"{vault}/.password", "w+") as f:
                        f.write(password)
                        f.close()
                    print("therefore password inside the vault. Close via `./vault.py close vault`")
                    sys.exit(0)

            signal.signal(signal.SIGINT, signal_handler)

            count = 120
            print(f"Time left: {count}", end='\r')
            while count > 0:
                count -= 1
                time.sleep(1)
                padded_count = str(count).zfill(3)
                print(f"Time left: {padded_count}", end='\r')
            do_encrypt(vault, interactive=False, password=password)

        elif CONTEXT == "close":
            questions = [
              inquirer.List('which_vault_to_encrypt',
                            message="Which Vault would you like to encrypt?",
                            choices=AVAILABLE_CONFIGS
                        ),
            ]

            inquiry = inquirer.prompt(questions)
            vault = inquiry["which_vault_to_encrypt"]

            do_encrypt(vault, interactive=True)

if __name__ == "__main__":
    main()