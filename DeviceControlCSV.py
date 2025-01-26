import os
import json
import csv
import requests
from tkinter import Tk, Label, Entry, Toplevel, filedialog, messagebox
from tkinter.ttk import Button, Style
from cryptography.fernet import Fernet

# File paths
ENCRYPTED_FILE = "config.enc"
KEY_FILE = "key.key"
CSV_FILEPATH = None

# Set Icon Path
ICON_PATH = "csapp.ico"

# Function to set custom icon
def set_window_icon(window, icon_path):
    if os.path.exists(icon_path):
        window.iconbitmap(icon_path)
    else:
        messagebox.showwarning("Warning", f"Icon file not found: {icon_path}")

# Generate a new encryption key
def generate_key():
    try:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        messagebox.showinfo("Success", f"Encryption key generated and saved to {KEY_FILE}.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while generating the key: {e}")

# Load the configuration
def load_config():
    try:
        if not os.path.exists(ENCRYPTED_FILE) or not os.path.exists(KEY_FILE):
            raise FileNotFoundError("Encrypted config file or key file not found.")
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
        fernet = Fernet(key)
        with open(ENCRYPTED_FILE, "rb") as enc_file:
            encrypted_data = enc_file.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode("utf-8"))
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load configuration: {e}")
        return None

# Obtain an access token
def get_access_token(client_id, client_secret):
    try:
        conn = requests.post(
            "https://api.eu-1.crowdstrike.com/oauth2/token",
            data={"client_id": client_id, "client_secret": client_secret},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        conn.raise_for_status()
        return conn.json().get("access_token")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to obtain access token: {e}")
        return None

# Convert hex to decimal
def hex_to_decimal(hex_value):
    return str(int(hex_value, 16))

# Process CSV and update the device control policy
def process_csv_and_update_policy():
    global CSV_FILEPATH, status_label, summary_label  # Reference the status and summary labels
    if not CSV_FILEPATH:
        messagebox.showerror("Error", "No CSV file selected.")
        status_label.config(text="Status: No CSV selected")
        summary_label.config(text="Summary: 0 devices processed")
        return

    config = load_config()
    if not config:
        status_label.config(text="Status: Failed to load config")
        summary_label.config(text="Summary: 0 devices processed")
        return

    access_token = get_access_token(config["client_id"], config["client_secret"])
    if not access_token:
        status_label.config(text="Status: Failed to obtain access token")
        summary_label.config(text="Summary: 0 devices processed")
        return

    try:
        success_count = 0
        failure_count = 0
        total_devices = 0
        failed_devices = []  # To store details of failed devices

        with open(CSV_FILEPATH, mode="r") as csv_file:
            csv_reader = csv.DictReader(csv_file, delimiter=",")
            for row in csv_reader:
                total_devices += 1
                try:
                    vendor_id_hex = row["Vendor ID"].strip()
                    product_id_hex = row["Model/Product ID"].strip()
                    serial_number_hex = row["Serial Number"].strip()

                    vendor_id_decimal = hex_to_decimal(vendor_id_hex)
                    product_id_decimal = hex_to_decimal(product_id_hex)
                    serial_number_decimal = hex_to_decimal(serial_number_hex)

                    combined_id = f"{vendor_id_decimal}_{product_id_decimal}_{serial_number_decimal}"

                    payload = {
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
                                                    "vendor_name": row["Identifier"].strip(),
                                                    "product_id": product_id_hex,
                                                    "product_id_decimal": product_id_decimal,
                                                    "product_name": "Unknown Device",
                                                    "serial_number": serial_number_decimal,
                                                    "action": "BLOCK_EXECUTE",
                                                    "description": f"Blocked device {combined_id}",
                                                    "expiration_time": "2027-07-21T18:20:16Z",
                                                    "combined_id": combined_id,
                                                }
                                            ],
                                        }
                                    ]
                                },
                            }
                        ]
                    }

                    headers = {
                        "accept": "application/json",
                        "authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json",
                    }
                    response = requests.patch(
                        "https://api.eu-1.crowdstrike.com/policy/entities/device-control/v1",
                        json=payload,
                        headers=headers,
                    )

                    if response.status_code == 200:
                        success_count += 1
                        print(f"Successfully processed entry for {combined_id}.")
                    else:
                        failure_count += 1
                        failed_devices.append({
                            "device": combined_id,
                            "status_code": response.status_code,
                            "response": response.text
                        })
                        print(f"Failed to process entry for {combined_id}. Status Code: {response.status_code}")
                        print(f"Response Text: {response.text}")

                except Exception as e:
                    failure_count += 1
                    failed_devices.append({
                        "device": row,
                        "status_code": "N/A",
                        "response": str(e)
                    })
                    print(f"Error processing row: {row}")
                    print(f"Exception: {e}")

        # Save failed devices to a file
        if failed_devices:
            with open("failed_devices.txt", "w") as failed_file:
                for failed in failed_devices:
                    failed_file.write(f"Device: {failed['device']}\n")
                    failed_file.write(f"Status Code: {failed['status_code']}\n")
                    failed_file.write(f"Response: {failed['response']}\n")
                    failed_file.write("=" * 50 + "\n")

        # Update status and summary labels
        status_label.config(text=f"Status: {success_count} succeeded, {failure_count} failed")
        summary_label.config(text=f"Summary: {total_devices} devices processed")
        messagebox.showinfo("Success", f"CSV processed and policy updated.\nFailed devices saved to failed_devices.txt")
    except Exception as e:
        status_label.config(text="Status: Error during processing")
        summary_label.config(text="Summary: 0 devices processed")
        messagebox.showerror("Error", f"An error occurred: {e}")





# Select a CSV file
def select_csv_file():
    global CSV_FILEPATH
    CSV_FILEPATH = filedialog.askopenfilename(
        title="Select CSV File",
        filetypes=[("CSV Files", "*.csv")],
    )
    if CSV_FILEPATH:
        messagebox.showinfo("File Selected", f"Selected file: {CSV_FILEPATH}")

# UI Cleanup
def clear_window():
    for widget in root.winfo_children():
        widget.destroy()

# Main Menu
def main_menu():
    global status_label, summary_label  # Declare the labels as global variables
    clear_window()
    root.title("CrowdStrike Device Control Tool")

    Label(root, text="CrowdStrike Device Control Tool", font=("Segoe UI", 20, "bold"), bg="#F5F5F5").pack(pady=20)
    Button(root, text="Configuration Menu", style="Rounded.TButton", command=open_config_menu).pack(pady=10)
    Button(root, text="Select CSV File", style="Rounded.TButton", command=select_csv_file).pack(pady=10)
    Button(root, text="Process CSV and Update Policy", style="RoundedBlue.TButton", command=process_csv_and_update_policy).pack(pady=10)

    # Create the status label
    status_label = Label(root, text="Status: Waiting for action", font=("Segoe UI", 12), bg="#F5F5F5", fg="#0078D7")
    status_label.pack(pady=5)

    # Create the summary label
    summary_label = Label(root, text="Summary: 0 devices processed", font=("Segoe UI", 12), bg="#F5F5F5", fg="#555555")
    summary_label.pack(pady=5)



# Open Config Menu
def open_config_menu():
    clear_window()
    root.title("Configuration Menu")
    Label(root, text="Configuration Options", font=("Segoe UI", 18, "bold"), bg="#F5F5F5").pack(pady=20)
    Button(root, text="Generate Encryption Key", style="Rounded.TButton", command=generate_key).pack(pady=10)
    Button(root, text="Back to Main Menu", style="RoundedBlue.TButton", command=main_menu).pack(pady=20)

# Main Setup
def main():
    global root
    root = Tk()
    root.geometry("500x500")
    root.configure(bg="#F5F5F5")
    set_window_icon(root, ICON_PATH)

    style = Style()
    style.theme_use("clam")
    style.configure("Rounded.TButton", font=("Segoe UI", 12), padding=10)
    style.configure("RoundedBlue.TButton", font=("Segoe UI", 12), padding=10)

    main_menu()
    root.mainloop()

if __name__ == "__main__":
    main()
