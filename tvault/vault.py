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
import json
import stat
from subprocess import call, STDOUT
import os

def find_available_vaults(context="open"):
    context_suffix = ".tvault.encrypted" if context == "open" else ".tvault"
    return [name.replace(".encrypted", "") for name in os.listdir() if name.endswith(context_suffix)]

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
    
    has_permissions = os.path.exists(f"{folder_name}/.permissions.json")
    if has_permissions:
        # Restore file permissions
        with open(f"{folder_name}/.permissions.json", "r") as f:
            permissions = json.load(f)
            f.close()

        for file, perm in permissions.items():
            os.chmod(os.path.join(folder_name, file), perm)
        
        os.remove(f"{folder_name}/.permissions.json")

def encrypt(key, source, encode=True):
    key = SHA256.new(key).digest()
    IV = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size
    source += bytes([padding]) * padding
    data = IV + encryptor.encrypt(source)
    return base64.b64encode(data).decode("latin-1") if encode else data

def encrypt_folder(key, folder_path):
    # Save file permissions
    permissions = {}
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            filepath = os.path.join(root, file)
            permissions[os.path.relpath(filepath, folder_path)] = os.stat(filepath).st_mode

    with open(f"{folder_path}/.permissions.json", "w") as f:
        json.dump(permissions, f)
        f.close()

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

def update_vault_db(vault_path, context="open"):
    user = os.environ.get('USER')
    vault_db_path = f"/home/{user}/.tvault_vault_db.json"
    vault_db_present = os.path.exists(vault_db_path)
    if not vault_db_present and (context == "open"):
        with open(vault_db_path, "w+") as f:
            json.dump([], f)

    if context == "open":
        with open(vault_db_path, "r") as f:
            vault_db = json.load(f)
            f.close()
        vault_db.append(vault_path)
        with open(vault_db_path, "w") as f:
            json.dump(vault_db, f)
            f.close()
    elif context == "close":
        with open(vault_db_path, "r") as f:
            vault_db = json.load(f)
            f.close()
        vault_db.remove(vault_path)
        with open(vault_db_path, "w") as f:
            json.dump(vault_db, f)
            f.close()
        if len(vault_db) == 0:
            os.remove(vault_db_path)

VAULT_ACTIONS = ["create", "closeall", "lock"]

def main():
    CONTEXT = sys.argv[1] if len(sys.argv) > 1 else None

    if CONTEXT is None:
        CONTEXT = "open"
        
    NO_INQUIRY = sys.argv[2] if len(sys.argv) > 2 else False
    CWD = os.getcwd()
    
    # Parse additional arguments for password
    PASSWORD_ARG = None
    if len(sys.argv) > 3 and sys.argv[3] == "--password" and len(sys.argv) > 4:
        PASSWORD_ARG = sys.argv[4]

    if not (CONTEXT in ["open", "close"]):
        assert CONTEXT in VAULT_ACTIONS, f"Invalid context '{CONTEXT}'"
        if CONTEXT == "closeall":
            with open(f"/home/{os.environ.get('USER')}/.tvault_vault_db.json", "r") as f:
                vault_db = json.load(f)
                f.close()

            for full_vault_path in vault_db:
                vault_dir = "/".join(full_vault_path.split("/")[:-1])
                vault_name = full_vault_path.split("/")[-1]
                print(f"Closing vault '{vault_name}' in '{vault_dir}'")
                os.chdir(vault_dir)
                try:
                    with open(f"{vault_name}/.password", "r") as f:
                        password = f.read()
                        f.close()
                    do_encrypt(vault_name, interactive=False, password=password)
                    update_vault_db(full_vault_path, context="close")
                except Exception as e:
                    print(f"Failed to close vault '{vault_name}'")
        elif CONTEXT == "lock":
            with open(f"/home/{os.environ.get('USER')}/.tvault_vault_db.json", "r") as f:
                vault_db = json.load(f)
                f.close()
            for full_vault_path in vault_db:
                current_date_time = time.strftime("%Y%m%d-%H%M%S")
                close_success = False
                vault_dir = "/".join(full_vault_path.split("/")[:-1])
                vault_name = full_vault_path.split("/")[-1]
                print(f"Closing vault '{vault_name}' in '{vault_dir}'")
                os.chdir(vault_dir)
                # check if it's a git directory
                try:
                    with open(f"{vault_name}/.password", "r") as f:
                        password = f.read()
                        f.close()
                    do_encrypt(vault_name, interactive=False, password=password)
                    update_vault_db(full_vault_path, context="close")
                    close_success = True
                except Exception as e:
                    print(f"Failed to close vault '{vault_name}'")
                if close_success:
                    # check if it's a git dir
                    if os.path.exists(f".git"):
                        print(f"Git directory found. Committing and pushing changes...")
                        try:
                            call(["git", "add", f"{vault_name}.encrypted"], stdout=open(os.devnull, 'wb'), stderr=STDOUT)
                            call(["git", "commit", "-m", f"Vault update {current_date_time}"], stdout=open(os.devnull, 'wb'), stderr=STDOUT)
                            call(["git", "push"], stdout=open(os.devnull, 'wb'), stderr=STDOUT)
                        except Exception as e:
                            print(f"Failed to commit and push changes for '{vault_name}'")
        elif CONTEXT == "create":
            if not NO_INQUIRY:
                print("Please provide a vault name.")
                sys.exit(1)
            vault = NO_INQUIRY
            if not vault.endswith(".tvault"):
                vault = f"{vault}.tvault"
            if os.path.exists(vault):
                print(f"Vault '{vault}' already exists.")
                sys.exit(1)
            print(f"Please set a password to encrypt the vault.")
            if not PASSWORD_ARG:
                password1 = getpass.getpass(prompt="Enter password 1st time:")
                password2 = getpass.getpass(prompt="Enter password 2nd time:")
                assert password1 == password2, "Passwords do not match."
            else:
                password1 = PASSWORD_ARG
            os.mkdir(vault)
            print(f"Vault '{vault}' created successfully.")
            with open(f"{vault}/.password", "w+") as f:
                f.write(password1)
                f.close()
            print(f"Password cached inside the vault. Run `tvault close {vault}` to close the vault.")
            update_vault_db(f"{CWD}/{vault}", context="open")
        return
        
    print(f"Context: '{CONTEXT}'")
    AVAILABLE_CONFIGS = find_available_vaults(context=CONTEXT)

    if NO_INQUIRY:
        if CONTEXT == "open":
            vault = NO_INQUIRY
            # Use provided password if available, otherwise prompt interactively
            if PASSWORD_ARG:
                password = do_decrypt(vault, interactive=False, password=PASSWORD_ARG)
            else:
                password = do_decrypt(vault, interactive=True)
            with open(f"{vault}/.password", "w+") as f:
                print("Cached password inside the vault.")
                f.write(password)
                f.close()
            update_vault_db(f"{CWD}/{NO_INQUIRY}", context="open")
        elif CONTEXT == "close":
            if NO_INQUIRY == "all":
                AVAILABLE_CONFIGS = find_available_vaults(context="close")
                for vault in AVAILABLE_CONFIGS:
                    pw_files_exists = os.path.exists(f"{vault}/.password")
                    if pw_files_exists:
                        with open(f"{vault}/.password", "r") as f:
                            password = f.read()
                            f.close()
                        print(f"Password cached inside the vault '{vault}' is used. Closing...")
                        
                        do_encrypt(vault, interactive=False, password=password)
                    else:
                        print(f"Not closing '{vault}' as password is not cached.")
                return

            vault = NO_INQUIRY
            with open(f"{vault}/.password", "r") as f:
                password = f.read()
                f.close()
            os.remove(f"{vault}/.password")
            print("Password cached inside the vault is used.")
            do_encrypt(vault, interactive=False, password=password)
            update_vault_db(f"{CWD}/{NO_INQUIRY}", context="close")
    else:
        if CONTEXT == "open":
            questions = [
              inquirer.List('which_vault_to_decrypt',
                            message="Which Vault would you like to decrypt?",
                            choices=AVAILABLE_CONFIGS
                        ),
            ]

            inquiry = inquirer.prompt(questions)

            if not inquiry:
                print("No vault selected.")
                sys.exit(1)
            vault = inquiry["which_vault_to_decrypt"]

            password = do_decrypt(vault, interactive=True)

            print(f"Vault '{vault}' decrypted successfully!")

            with open(f"{vault}/.password", "w+") as f:
                print("Cached password inside the vault.")
                f.write(password)
                f.close()

            print(f"The vault will be auto closed in 2 minutes. ( If you don't cancel this script )")
            update_vault_db(f"{CWD}/{vault}", context=CONTEXT)

            def signal_handler(sig, frame):
                print('You pressed Ctrl+C!')
                print("Should I close the vault? (y/n)")
                close = input()
                if close.lower() == "y":
                    do_encrypt(vault, interactive=False, password=password)
                    update_vault_db(f"{CWD}/{vault}", context="close")
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
            update_vault_db(f"{CWD}/{vault}", context="close")

        elif CONTEXT == "close":
            questions = [
              inquirer.List('which_vault_to_encrypt',
                            message="Which Vault would you like to encrypt?",
                            choices=AVAILABLE_CONFIGS
                        ),
            ]

            inquiry = inquirer.prompt(questions)
            if not inquiry:
                print("No vault selected.")
                sys.exit(1)
            vault = inquiry["which_vault_to_encrypt"]

            # check if .password exists
            password_file_exists = os.path.exists(f"{vault}/.password")

            if password_file_exists:
                with open(f"{vault}/.password", "r") as f:
                    password = f.read()
                    f.close()
                print("Password cached inside the vault is used. Closing...")
                do_encrypt(vault, interactive=False, password=password)
            else:
                do_encrypt(vault, interactive=True)
            update_vault_db(f"{CWD}/{vault}", context="close")

if __name__ == "__main__":
    main()