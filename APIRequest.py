import os
import json
import csv
import http.client
from cryptography.fernet import Fernet

# File paths for the encrypted config and key
ENCRYPTED_FILE = "config.enc"
KEY_FILE = "key.key"

# Path to your CSV file
CSV_FILEPATH = "device_data.csv"

def load_config():
    """
    Decrypt the encrypted config file and load the contents.
    """
    if not os.path.exists(ENCRYPTED_FILE):
        raise FileNotFoundError(f"Encrypted config file {ENCRYPTED_FILE} not found.")
    if not os.path.exists(KEY_FILE):
        raise FileNotFoundError(f"Key file {KEY_FILE} not found.")

    # Load the encryption key
    with open(KEY_FILE, "rb") as key_file:
        key = key_file.read()
    fernet = Fernet(key)

    # Decrypt the config file
    with open(ENCRYPTED_FILE, "rb") as enc_file:
        encrypted_data = enc_file.read()
    decrypted_data = fernet.decrypt(encrypted_data)

    # Parse and return the config data
    return json.loads(decrypted_data.decode("utf-8"))

def get_access_token(client_id, client_secret):
    """
    Obtain an OAuth2 access token using the client ID and secret.
    """
    conn = http.client.HTTPSConnection("api.eu-1.crowdstrike.com")
    payload = f"client_id={client_id}&client_secret={client_secret}"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    conn.request("POST", "/oauth2/token", payload, headers)
    res = conn.getresponse()
    data = res.read()
    response_json = json.loads(data.decode("utf-8"))
    return response_json.get("access_token")

def hex_to_decimal(hex_value):
    """
    Convert a hexadecimal string to a decimal number.
    """
    return str(int(hex_value, 16))

def process_csv_and_update_policy(access_token):
    """
    Read the CSV file, process each row, and send API requests to update the policy.
    """
    if not os.path.exists(CSV_FILEPATH):
        print(f"Error: The file {CSV_FILEPATH} does not exist.")
        return

    # Open and process the CSV
    with open(CSV_FILEPATH, mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter=',')  # Use comma as the delimiter
        for row in csv_reader:
            try:
                vendor_id_hex = row['Vendor ID'].strip()
                product_id_hex = row['Model/Product ID'].strip()
                serial_number_hex = row['Serial Number'].strip()

                # Convert hexadecimal values to decimal
                vendor_id_decimal = hex_to_decimal(vendor_id_hex)
                product_id_decimal = hex_to_decimal(product_id_hex)
                serial_number_decimal = hex_to_decimal(serial_number_hex)

                # Construct combined_id
                combined_id = f"{vendor_id_decimal}_{product_id_decimal}_{serial_number_decimal}"

                # Define the payload
                payload = json.dumps({
                    "resources": [
                        {
                            "id": "95ebe373b11a49199a0fb057ee6815ff",  # Replace with your policy ID
                            "settings": {
                                "classes": [
                                    {
                                        "id": "MASS_STORAGE",
                                        "action": "BLOCK_ALL",
                                        "exceptions": [
                                            {
                                                "vendor_id": vendor_id_hex,
                                                "vendor_id_decimal": vendor_id_decimal,
                                                "vendor_name": row['Identifier'].strip(),
                                                "product_id": product_id_hex,
                                                "product_id_decimal": product_id_decimal,
                                                "product_name": "Unknown Device",
                                                "serial_number": serial_number_decimal,
                                                "action": "BLOCK_EXECUTE",
                                                "description": f"Blocked device {combined_id}",
                                                "expiration_time": "2027-07-21T18:20:16Z",
                                                "combined_id": combined_id
                                            }
                                        ]
                                    }
                                ]
                            }
                        }
                    ]
                })

                # Send the API request
                headers = {
                    'accept': 'application/json',
                    'authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/json'
                }
                conn = http.client.HTTPSConnection("api.eu-1.crowdstrike.com")
                conn.request("PATCH", "/policy/entities/device-control/v1", payload, headers)
                res = conn.getresponse()
                data = res.read()

                # Print the response
                print(f"Processed entry for {combined_id}: {data.decode('utf-8')}")

            except Exception as e:
                print(f"Error processing row: {row}")
                print(f"Exception: {e}")

# Main script
if __name__ == "__main__":
    try:
        # Step 1: Load the encrypted configuration
        config = load_config()

        # Step 2: Get a new access token
        print("Obtaining access token...")
        access_token = get_access_token(config["client_id"], config["client_secret"])
        print("Access token obtained successfully!")

        # Step 3: Process the CSV and update the policy for each entry
        print(f"Processing CSV: {CSV_FILEPATH}")
        process_csv_and_update_policy(access_token)

    except Exception as e:
        print("An error occurred:", e)
