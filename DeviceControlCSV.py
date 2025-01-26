import os
import json
import csv
import requests
import logging
import threading
import stat
import webbrowser  # Handles opening URLs in the default web browser
from tkinter import Tk, Label, filedialog, messagebox, StringVar, Toplevel, Entry
from tkinter.ttk import Button, Style, Combobox
from cryptography.fernet import Fernet

# Configure logging to capture essential information
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s:%(levelname)s:%(message)s'
)


class EncryptionManager:
    """Manages encryption and decryption of configuration files."""

    def __init__(self, key_file="key.key", encrypted_file="config.enc", plain_config="config.json"):
        """Initializes the EncryptionManager with file paths."""
        self.key_file = key_file
        self.encrypted_file = encrypted_file
        self.plain_config = plain_config

    def generate_key(self):
        """Generates a new encryption key and saves it securely."""
        try:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as key_file:
                key_file.write(key)
            os.chmod(self.key_file, stat.S_IRUSR | stat.S_IWUSR)  # Restrict key file permissions
            logging.info(f"Encryption key generated and saved to {self.key_file}.")
        except Exception as e:
            logging.error(f"Error generating key: {e}")
            raise

    def save_and_encrypt_config(self, client_id, client_secret, csv_params=None):
        """
        Saves the configuration (client credentials and optional CSV parameters)
        and encrypts it.
        """
        try:
            config_data = {
                "client_id": client_id,
                "client_secret": client_secret
            }

            # Include CSV parameters if provided
            if csv_params:
                config_data["csv_params"] = csv_params
            else:
                # If not provided, retain existing csv_params if they exist
                existing_config = self.load_config(silent=True)
                if existing_config and "csv_params" in existing_config:
                    config_data["csv_params"] = existing_config["csv_params"]

            with open(self.plain_config, "w", encoding="utf-8") as config_file:
                json.dump(config_data, config_file, indent=4)
            logging.info(f"Configuration saved to {self.plain_config}.")

            if not os.path.exists(self.key_file):
                self.generate_key()

            with open(self.key_file, "rb") as key_file:
                key = key_file.read()
            fernet = Fernet(key)
            with open(self.plain_config, "rb") as config_file:
                config_bytes = config_file.read()
            encrypted_data = fernet.encrypt(config_bytes)

            with open(self.encrypted_file, "wb") as enc_file:
                enc_file.write(encrypted_data)
            logging.info(f"Configuration encrypted successfully and saved as '{self.encrypted_file}'.")

            os.remove(self.plain_config)  # Remove plain config for security
            logging.info(f"Plain configuration file '{self.plain_config}' removed for security.")
        except Exception as e:
            logging.error(f"Error saving and encrypting configuration: {e}")
            raise

    def load_config(self, silent=False):
        """
        Loads and decrypts the configuration.
        If 'silent' is True, errors are not shown via messagebox.
        """
        if not os.path.exists(self.encrypted_file):
            if not silent:
                messagebox.showerror("Error", "Encrypted config file not found.")
            logging.error("Encrypted config file not found.")
            return None
        if not os.path.exists(self.key_file):
            if not silent:
                messagebox.showerror("Error", "Encryption key file not found.")
            logging.error("Encryption key file not found.")
            return None
        try:
            with open(self.key_file, "rb") as key_file:
                key = key_file.read()
            fernet = Fernet(key)
            with open(self.encrypted_file, "rb") as enc_file:
                encrypted_data = enc_file.read()
            decrypted_data = fernet.decrypt(encrypted_data)
            config = json.loads(decrypted_data.decode("utf-8"))
            return config
        except Exception as e:
            if not silent:
                messagebox.showerror("Error", f"Failed to load and decrypt configuration: {e}")
            logging.error(f"Failed to load and decrypt configuration: {e}")
            return None

    def encrypt_config_file(self, config_path="config.json"):
        """Encrypts an existing configuration file."""
        if not os.path.exists(config_path):
            messagebox.showerror("Error", f"'{config_path}' does not exist.")
            logging.error(f"'{config_path}' does not exist.")
            return
        try:
            with open(config_path, "rb") as f:
                config_data = f.read()

            if not os.path.exists(self.key_file):
                self.generate_key()

            with open(self.key_file, "rb") as key_file:
                key = key_file.read()
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(config_data)

            with open(self.encrypted_file, "wb") as enc_file:
                enc_file.write(encrypted_data)

            logging.info(f"'{config_path}' encrypted successfully as '{self.encrypted_file}'.")
            messagebox.showinfo("Success", f"'{config_path}' has been encrypted and saved as '{self.encrypted_file}'.")
        except Exception as e:
            logging.error(f"Error encrypting config file: {e}")
            messagebox.showerror("Error", f"An error occurred during encryption: {e}")

    def decrypt_config(self, output_path="config.json"):
        """Decrypts the encrypted configuration file."""
        if not os.path.exists(self.encrypted_file):
            messagebox.showerror("Error", "Encrypted config file not found.")
            logging.error("Encrypted config file not found.")
            return
        if not os.path.exists(self.key_file):
            messagebox.showerror("Error", "Encryption key file not found.")
            logging.error("Encryption key file not found.")
            return
        try:
            with open(self.key_file, "rb") as key_file:
                key = key_file.read()
            fernet = Fernet(key)
            with open(self.encrypted_file, "rb") as enc_file:
                encrypted_data = enc_file.read()
            decrypted_data = fernet.decrypt(encrypted_data)
            with open(output_path, "wb") as f_out:
                f_out.write(decrypted_data)
            logging.info(f"Config file decrypted successfully and saved as '{output_path}'.")
            messagebox.showinfo("Success", f"Config file decrypted and saved as '{output_path}'.")
        except Exception as e:
            logging.error(f"Error decrypting config file: {e}")
            messagebox.showerror("Error", f"An error occurred during decryption: {e}")


class APIClient:
    """Handles interactions with the CrowdStrike API."""

    def __init__(self, base_url="https://api.eu-1.crowdstrike.com"):
        """Initializes the APIClient with a base URL."""
        self.base_url = base_url
        self.access_token = None

    def get_access_token(self, client_id, client_secret):
        """Obtains an access token using client credentials."""
        try:
            response = requests.post(
                f"{self.base_url}/oauth2/token",
                data={"client_id": client_id, "client_secret": client_secret},
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            self.access_token = response.json().get("access_token")
            logging.info("Access token obtained successfully.")
            return self.access_token
        except requests.HTTPError as http_err:
            logging.error(f"HTTP error occurred while obtaining access token: {http_err}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error obtaining access token: {e}")
            raise

    def get_device_control_policies(self):
        """Retrieves device control policies from the CrowdStrike API."""
        if not self.access_token:
            logging.error("Access token is not set.")
            raise ValueError("Access token is not set.")
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json"
        }
        try:
            response = requests.get(
                f"{self.base_url}/policy/combined/device-control/v1",
                headers=headers
            )
            response.raise_for_status()
            policies = response.json().get("resources", [])
            logging.info(f"Retrieved {len(policies)} device control policies.")
            return policies
        except requests.HTTPError as http_err:
            logging.error(f"HTTP error occurred while retrieving policies: {http_err}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error retrieving policies: {e}")
            raise

    def update_device_control_policy(self, policy_id, payload):
        """Updates a specific device control policy with the provided payload."""
        if not self.access_token:
            logging.error("Access token is not set.")
            raise ValueError("Access token is not set.")
        headers = {
            "accept": "application/json",
            "authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }
        try:
            response = requests.patch(
                f"{self.base_url}/policy/combined/device-control/v1",
                json=payload,
                headers=headers,
            )
            if response.status_code in [200, 201, 204]:
                logging.info(f"Policy {policy_id} updated successfully.")
            else:
                logging.warning(f"Failed to update policy {policy_id}. Status Code: {response.status_code}, Response: {response.text}")
            return response
        except requests.HTTPError as http_err:
            logging.error(f"HTTP error during policy update: {http_err}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error during policy update: {e}")
            raise


class DeviceControlApp:
    """Manages the GUI, user interactions, and coordination between components."""

    def __init__(self, root):
        """Initializes the DeviceControlApp with the main Tkinter window."""
        self.root = root
        self.root.geometry("700x700")
        self.root.configure(bg="#F5F5F5")

        self.init_styles()
        self.encryption_manager = EncryptionManager()
        self.api_client = APIClient()

        self.CSV_FILEPATH = None
        self.selected_policy = StringVar()
        self.policy_id_mapping = {}

        self.status_label = None
        self.summary_label = None
        self.policy_dropdown = None
        self.process_button = None

        # Initialize default CSV import parameters
        self.csv_params = {
            "delimiter": ",",
            "encoding": "utf-8",
            "vendor_id_column": "Vendor ID",
            "model_product_id_column": "Model/Product ID",
            "serial_number_column": "Serial Number"
        }

        # Hide the main window initially
        self.root.withdraw()

        if not os.path.exists(self.encryption_manager.encrypted_file):
            self.setup_config_dialog()
        else:
            # Deiconify the main window before showing the main menu
            self.root.deiconify()
            config = self.encryption_manager.load_config()
            if config and "csv_params" in config:
                self.csv_params = config["csv_params"]
            threading.Thread(target=self.fetch_policies, daemon=True).start()
            self.main_menu()

    def init_styles(self):
        """Initializes the styles for Tkinter widgets."""
        style = Style()
        style.theme_use("clam")
        style.configure("Rounded.TButton", font=("Segoe UI", 12), padding=10)
        style.configure("RoundedBlue.TButton", font=("Segoe UI", 12), padding=10,
                        foreground="#FFFFFF", background="#0078D7")
        style.map("RoundedBlue.TButton",
                  background=[('active', '#005A9E')])
        # Removed Progressbar style since the progress bar is no longer needed
        # style.configure("Progressbar.Horizontal.TProgressbar",
        #                 troughcolor='#F5F5F5', background='#0078D7')

    def setup_config_dialog(self):
        """Prompts the user to enter Client ID and Client Secret."""
        def submit_credentials():
            client_id = client_id_var.get().strip()
            client_secret = client_secret_var.get().strip()

            if not client_id or not client_secret:
                messagebox.showerror("Error", "Both Client ID and Client Secret are required.")
                return

            try:
                self.encryption_manager.save_and_encrypt_config(client_id, client_secret, self.csv_params)
                messagebox.showinfo("Success", "Configuration saved and encrypted successfully.")
                config_window.destroy()
                self.root.deiconify()  # Show the main window
                threading.Thread(target=self.fetch_policies, daemon=True).start()
                self.main_menu()  # Show main menu after successful config
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save configuration: {e}")

        # Create configuration dialog as a Toplevel window
        config_window = Toplevel(self.root)
        config_window.title("Setup Configuration")
        config_window.geometry("500x450")  # Increased height to accommodate all widgets
        config_window.grab_set()  # Make this window modal

        Label(config_window, text="Enter Configuration", font=("Segoe UI", 16, "bold"), bg="#F5F5F5").pack(pady=10)

        info_frame = Label(config_window, bg="#F5F5F5")
        info_frame.pack(pady=(0, 10), padx=10, fill='x')

        info_text = (
            "Enter your API Client ID and Secret.\n"
            "The API needs the following rights:\n"
            "- Device control policies Read and Write.\n"
            "Refer to the CrowdStrike Documentation on how to Create API Clients."
        )
        Label(info_frame, text=info_text, font=("Segoe UI", 10), bg="#F5F5F5",
              wraplength=480, justify="left").pack(pady=(0, 5))

        def open_documentation(event):
            webbrowser.open_new("https://falcon.eu-1.crowdstrike.com/documentation/page/te8afcf6/api-integration")

        hyperlink_label = Label(info_frame, text="Crowdstrike API Client Documentation",
                                font=("Segoe UI", 10, "underline"), fg="blue", cursor="hand2", bg="#F5F5F5")
        hyperlink_label.pack()
        hyperlink_label.bind("<Button-1>", lambda e: open_documentation(e))

        Label(config_window, text="Client ID:", font=("Segoe UI", 12), bg="#F5F5F5").pack(pady=(10, 5))
        client_id_var = StringVar()
        client_id_entry = Entry(config_window, textvariable=client_id_var, width=50)
        client_id_entry.pack(pady=5)

        Label(config_window, text="Client Secret:", font=("Segoe UI", 12), bg="#F5F5F5").pack(pady=(10, 5))
        client_secret_var = StringVar()
        client_secret_entry = Entry(config_window, textvariable=client_secret_var, width=50, show="*")
        client_secret_entry.pack(pady=5)

        Button(config_window, text="Submit", style="RoundedBlue.TButton", command=submit_credentials).pack(pady=20)

        self.root.wait_window(config_window)

    def fetch_policies(self):
        """Fetches device control policies from the CrowdStrike API."""
        try:
            self.update_status("Status: Obtaining access token...")
            config = self.encryption_manager.load_config()
            if not config:
                self.update_status("Status: Failed to load config")
                return

            access_token = self.api_client.get_access_token(config.get("client_id"), config.get("client_secret"))
            if not access_token:
                self.update_status("Status: Failed to obtain access token")
                return

            self.update_status("Status: Retrieving device control policies...")
            policies = self.api_client.get_device_control_policies()
            if not policies:
                self.update_status("Status: No device control policies found.")
                return

            custom_policies = [policy for policy in policies if policy.get("name") != "platform_default"]

            if not custom_policies:
                self.update_status("Status: No custom device control policies available.")
                return

            policy_names = [f"{policy.get('name', 'Unnamed Policy')} ({policy.get('id')})" for policy in custom_policies]
            self.policy_id_mapping = {f"{policy.get('name', 'Unnamed Policy')} ({policy.get('id')})": policy for policy in custom_policies}

            # Update the policy dropdown in the main thread
            self.root.after(0, self.update_policy_dropdown, policy_names)
            self.update_status("Status: Custom policies loaded successfully.")
        except Exception as e:
            logging.error(f"Error fetching policies: {e}")
            self.update_status("Status: Error fetching policies.")
            messagebox.showerror("Error", f"An error occurred while fetching policies: {e}")

    def update_policy_dropdown(self, policy_names):
        """Updates the policy dropdown with fetched policy names."""
        if self.policy_dropdown:
            self.policy_dropdown['values'] = policy_names
            if policy_names:
                self.policy_dropdown.current(0)  # Select the first policy by default
                self.on_policy_select()

    def load_config(self):
        """Loads the encrypted configuration."""
        try:
            config = self.encryption_manager.load_config()
            logging.info("Configuration loaded successfully.")
            # If CSV parameters are missing, retain default settings
            if config and "csv_params" in config:
                self.csv_params = config["csv_params"]
            return config
        except FileNotFoundError as e:
            logging.error(f"Configuration file error: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error loading configuration: {e}")
            messagebox.showerror("Error", f"Unexpected error loading configuration: {e}")
        return None

    def generate_key(self):
        """Generates a new encryption key."""
        try:
            self.encryption_manager.generate_key()
            messagebox.showinfo("Success", "Encryption key generated successfully.")
        except Exception as e:
            logging.error(f"Error generating encryption key: {e}")
            messagebox.showerror("Error", f"An error occurred while generating the encryption key: {e}")

    def encrypt_config_file(self):
        """Encrypts the plain configuration file."""
        if not os.path.exists("config.json"):
            messagebox.showerror("Error", "Could not find 'config.json'. Please ensure it exists in the working directory.")
            return
        try:
            self.encryption_manager.encrypt_config_file()
        except Exception as e:
            logging.error(f"Error encrypting config file: {e}")
            messagebox.showerror("Error", f"An error occurred during encryption: {e}")

    def decrypt_config(self):
        """Decrypts the encrypted configuration file."""
        try:
            self.encryption_manager.decrypt_config()
        except Exception as e:
            logging.error(f"Error decrypting config file: {e}")
            messagebox.showerror("Error", f"An error occurred during decryption: {e}")

    def select_csv_file(self):
        """Opens a dialog to select a CSV file."""
        self.CSV_FILEPATH = filedialog.askopenfilename(
            title="Select CSV File",
            filetypes=[("CSV Files", "*.csv")],
        )
        if self.CSV_FILEPATH:
            messagebox.showinfo("File Selected", f"Selected file: {self.CSV_FILEPATH}")
            logging.info(f"CSV file selected: {self.CSV_FILEPATH}")
            self.update_status(f"Status: Selected CSV - {os.path.basename(self.CSV_FILEPATH)}")
            self.update_summary("Summary: 0 devices processed")

    def process_csv_and_update_policy(self):
        """Processes the selected CSV file and updates the chosen device control policy."""
        if not self.CSV_FILEPATH:
            messagebox.showerror("Error", "No CSV file selected.")
            self.update_status("Status: No CSV selected")
            self.update_summary("Summary: 0 devices processed")
            return

        if not self.selected_policy.get():
            messagebox.showerror("Error", "No policy selected.")
            self.update_status("Status: No policy selected.")
            self.update_summary("Summary: 0 devices processed")
            return

        selected_policy = self.policy_id_mapping.get(self.selected_policy.get())
        if not selected_policy:
            messagebox.showerror("Error", "Selected policy not found.")
            self.update_status("Status: Selected policy not found.")
            self.update_summary("Summary: 0 devices processed")
            return

        policy_id = selected_policy.get("id")

        threading.Thread(target=self._process_csv_and_update_policy_thread, args=(selected_policy,), daemon=True).start()

    def _process_csv_and_update_policy_thread(self, selected_policy):
        """Threaded function to process the CSV and update the policy."""
        try:
            self.update_status("Status: Processing CSV...")
            self.update_summary("Summary: 0 devices processed")

            success_count = 0
            failure_count = 0
            total_devices = 0
            failed_devices = []

            current_classes = selected_policy.get("settings", {}).get("classes", [])
            class_mapping = {cls.get("id"): cls for cls in current_classes}

            with open(self.CSV_FILEPATH, mode="r", encoding=self.csv_params.get("encoding", "utf-8")) as csv_file:
                csv_reader = csv.DictReader(csv_file, delimiter=self.csv_params.get("delimiter", ","))

                # Fetch custom column names from csv_params
                vendor_id_col = self.csv_params.get("vendor_id_column", "Vendor ID")
                model_product_id_col = self.csv_params.get("model_product_id_column", "Model/Product ID")
                serial_number_col = self.csv_params.get("serial_number_column", "Serial Number")

                required_columns = {vendor_id_col, model_product_id_col, serial_number_col, "Identifier"}
                if not required_columns.issubset(csv_reader.fieldnames):
                    missing = required_columns - set(csv_reader.fieldnames)
                    raise ValueError(f"CSV file is missing required columns: {missing}")

                rows = list(csv_reader)
                total_devices = len(rows)
                self.update_summary(f"Summary: {total_devices} devices to process")

                for index, row in enumerate(rows, start=1):
                    try:
                        vendor_id_hex = row.get(vendor_id_col, "").strip()
                        product_id_hex = row.get(model_product_id_col, "").strip()
                        serial_number_hex = row.get(serial_number_col, "").strip()
                        identifier = row.get("Identifier", "").strip()

                        if not all([vendor_id_hex, product_id_hex, serial_number_hex, identifier]):
                            raise ValueError("Missing required CSV fields.")

                        vendor_id_decimal = self.hex_to_decimal(vendor_id_hex)
                        product_id_decimal = self.hex_to_decimal(product_id_hex)
                        serial_number_decimal = self.hex_to_decimal(serial_number_hex)

                        combined_id = f"{vendor_id_decimal}_{product_id_decimal}_{serial_number_decimal}"

                        exception = {
                            "vendor_id": vendor_id_hex,
                            "vendor_id_decimal": vendor_id_decimal,
                            "vendor_name": identifier,
                            "product_id": product_id_hex,
                            "product_id_decimal": product_id_decimal,
                            "product_name": "Unknown Device",
                            "serial_number": serial_number_decimal,
                            "action": "BLOCK_EXECUTE",
                            "description": f"Blocked device {combined_id}",
                            "expiration_time": "2027-07-21T18:20:16Z",
                            "combined_id": combined_id,
                            "match_method": "COMBINED_ID"
                        }

                        cls_id = "MASS_STORAGE"
                        desired_action = "BLOCK_ALL"

                        if cls_id in class_mapping:
                            class_mapping[cls_id]["action"] = desired_action
                            class_mapping[cls_id]["exceptions"].append(exception)
                        else:
                            new_class = {
                                "id": cls_id,
                                "action": desired_action,
                                "exceptions": [exception]
                            }
                            class_mapping[cls_id] = new_class
                            current_classes.append(new_class)

                        payload = {
                            "resources": [
                                {
                                    "id": selected_policy.get("id"),
                                    "settings": {
                                        "classes": list(class_mapping.values())
                                    }
                                }
                            ]
                        }

                        response = self.api_client.update_device_control_policy(selected_policy.get("id"), payload)

                        if response.status_code in [200, 201, 204]:
                            success_count += 1
                        else:
                            failure_count += 1
                            failed_devices.append({
                                "device": combined_id,
                                "status_code": response.status_code,
                                "response": response.text
                            })

                    except Exception as e:
                        failure_count += 1
                        failed_devices.append({
                            "device": row,
                            "status_code": "N/A",
                            "response": str(e)
                        })
                    finally:
                        self.update_summary(f"Summary: {index} of {total_devices} devices processed")

            if failed_devices:
                with open("failed_devices.txt", "w", encoding="utf-8") as failed_file:
                    for failed in failed_devices:
                        failed_file.write(f"Device: {failed['device']}\n")
                        failed_file.write(f"Status Code: {failed['status_code']}\n")
                        failed_file.write(f"Response: {failed['response']}\n")
                        failed_file.write("=" * 50 + "\n")
                logging.warning(f"{len(failed_devices)} devices failed to update.")

            self.update_status(f"Status: {success_count} succeeded, {failure_count} failed")
            self.update_summary(f"Summary: {total_devices} devices processed")
            messagebox.showinfo("Success", f"CSV processed and policy updated.\nFailed devices saved to 'failed_devices.txt'")
        except Exception as e:
            logging.error(f"Error during CSV processing: {e}")
            self.update_status("Status: Error during processing")
            self.update_summary("Summary: 0 devices processed")
            messagebox.showerror("Error", f"An error occurred: {e}")

    def hex_to_decimal(self, hex_value):
        """Converts a hexadecimal string to its decimal representation."""
        try:
            return str(int(hex_value, 16))
        except ValueError:
            logging.warning(f"Invalid hex value encountered: {hex_value}. Defaulting to '0'.")
            return "0"

    def update_status(self, status):
        """Updates the status label with the provided status message."""
        if self.status_label:
            self.status_label.config(text=status)

    def update_summary(self, count):
        """Updates the summary label with the provided count."""
        if self.summary_label:
            self.summary_label.config(text=count)

    def on_policy_select(self, event=None):
        """Enables the process button when a policy is selected."""
        selected = self.selected_policy.get()
        if selected:
            self.process_button.config(state="normal")
            self.update_status(f"Status: Selected Policy - {selected}")
            self.update_summary("Summary: 0 devices processed")
        else:
            self.process_button.config(state="disabled")
            self.update_status("Status: No policy selected")
            self.update_summary("Summary: 0 devices processed")

    def open_config_menu(self):
        """Opens the configuration management menu."""
        self.clear_window()
        self.root.title("Configuration Menu")

        Label(self.root, text="Configuration Options", font=("Segoe UI", 18, "bold"), bg="#F5F5F5").pack(pady=20)

        Button(self.root, text="Generate Encryption Key", style="Rounded.TButton", command=self.generate_key).pack(pady=10)
        Button(self.root, text="Encrypt Config File", style="Rounded.TButton", command=self.encrypt_config_file).pack(pady=10)
        Button(self.root, text="Decrypt Config File", style="Rounded.TButton", command=self.decrypt_config).pack(pady=10)
        Button(self.root, text="CSV Import Settings", style="Rounded.TButton", command=self.open_csv_settings_dialog).pack(pady=10)

        Button(self.root, text="Back to Main Menu", style="RoundedBlue.TButton", command=self.main_menu).pack(pady=20)

    def open_csv_settings_dialog(self):
        """Opens a dialog to set CSV import parameters."""
        def save_settings():
            delimiter = delimiter_var.get()
            encoding = encoding_var.get().strip()
            vendor_id_col = vendor_id_var.get().strip()
            model_product_id_col = model_product_id_var.get().strip()
            serial_number_col = serial_number_var.get().strip()

            # Validate inputs
            if not delimiter:
                messagebox.showerror("Error", "Delimiter cannot be empty.")
                return
            if not encoding:
                messagebox.showerror("Error", "Encoding cannot be empty.")
                return
            if not vendor_id_col:
                messagebox.showerror("Error", "Vendor ID Column Name cannot be empty.")
                return
            if not model_product_id_col:
                messagebox.showerror("Error", "Model/Product ID Column Name cannot be empty.")
                return
            if not serial_number_col:
                messagebox.showerror("Error", "Serial Number Column Name cannot be empty.")
                return

            # Update CSV parameters
            self.csv_params["delimiter"] = delimiter
            self.csv_params["encoding"] = encoding
            self.csv_params["vendor_id_column"] = vendor_id_col
            self.csv_params["model_product_id_column"] = model_product_id_col
            self.csv_params["serial_number_column"] = serial_number_col

            # Load existing config to update
            config = self.encryption_manager.load_config()
            if config:
                config["csv_params"] = self.csv_params
                try:
                    self.encryption_manager.save_and_encrypt_config(
                        config.get("client_id"),
                        config.get("client_secret"),
                        csv_params=self.csv_params
                    )
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to update configuration: {e}")
                    return
            else:
                # If config does not exist, it should have been handled earlier
                messagebox.showerror("Error", "Configuration not loaded. Please reconfigure.")
                return

            messagebox.showinfo("Success", "CSV import settings updated successfully.")
            csv_settings_window.destroy()

        # Create CSV settings dialog as a Toplevel window
        csv_settings_window = Toplevel(self.root)
        csv_settings_window.title("CSV Import Settings")
        csv_settings_window.geometry("400x600")  # Increased height to ensure all widgets are visible
        csv_settings_window.grab_set()  # Make this window modal

        Label(csv_settings_window, text="CSV Import Settings", font=("Segoe UI", 14, "bold"), bg="#F5F5F5").pack(pady=10)

        # Delimiter Setting
        Label(csv_settings_window, text="Delimiter:", font=("Segoe UI", 12), bg="#F5F5F5").pack(pady=(20, 5))
        delimiter_var = StringVar(value=self.csv_params["delimiter"])
        delimiter_entry = Entry(csv_settings_window, textvariable=delimiter_var, width=10)
        delimiter_entry.pack(pady=5)

        # Encoding Setting
        Label(csv_settings_window, text="Encoding:", font=("Segoe UI", 12), bg="#F5F5F5").pack(pady=(20, 5))
        encoding_var = StringVar(value=self.csv_params["encoding"])
        encoding_entry = Entry(csv_settings_window, textvariable=encoding_var, width=30)
        encoding_entry.pack(pady=5)

        # Vendor ID Column Name
        Label(csv_settings_window, text="Vendor ID Column Name:", font=("Segoe UI", 12), bg="#F5F5F5").pack(pady=(20, 5))
        vendor_id_var = StringVar(value=self.csv_params["vendor_id_column"])
        vendor_id_entry = Entry(csv_settings_window, textvariable=vendor_id_var, width=30)
        vendor_id_entry.pack(pady=5)

        # Model/Product ID Column Name
        Label(csv_settings_window, text="Model/Product ID Column Name:", font=("Segoe UI", 12), bg="#F5F5F5").pack(pady=(20, 5))
        model_product_id_var = StringVar(value=self.csv_params["model_product_id_column"])
        model_product_id_entry = Entry(csv_settings_window, textvariable=model_product_id_var, width=30)
        model_product_id_entry.pack(pady=5)

        # Serial Number Column Name
        Label(csv_settings_window, text="Serial Number Column Name:", font=("Segoe UI", 12), bg="#F5F5F5").pack(pady=(20, 5))
        serial_number_var = StringVar(value=self.csv_params["serial_number_column"])
        serial_number_entry = Entry(csv_settings_window, textvariable=serial_number_var, width=30)
        serial_number_entry.pack(pady=5)

        # Save Button (Adjusted to be larger)
        save_button = Button(
            csv_settings_window,
            text="Save Settings",
            style="RoundedBlue.TButton",
            command=save_settings,
            width=20  # Increased width for better visibility
        )
        save_button.pack(pady=30)

    def clear_window(self):
        """Clears all widgets from the main window."""
        for widget in self.root.winfo_children():
            widget.destroy()

    def main_menu(self):
        """Displays the main menu of the application."""
        self.clear_window()
        self.root.title("CrowdStrike Device Control Tool")

        Label(self.root, text="CrowdStrike Device Control Tool", font=("Segoe UI", 20, "bold"), bg="#F5F5F5").pack(pady=20)
        Button(self.root, text="Configuration Menu", style="Rounded.TButton", command=self.open_config_menu).pack(pady=10)
        Button(self.root, text="Select CSV File", style="Rounded.TButton", command=self.select_csv_file).pack(pady=10)
        Button(self.root, text="CSV Import Settings", style="Rounded.TButton", command=self.open_csv_settings_dialog).pack(pady=10)

        Label(self.root, text="Select Device Control Policy:", font=("Segoe UI", 12), bg="#F5F5F5").pack(pady=10)
        self.policy_dropdown = Combobox(self.root, textvariable=self.selected_policy, state="readonly", width=50)
        self.policy_dropdown.pack(pady=5)
        self.policy_dropdown.bind("<<ComboboxSelected>>", self.on_policy_select)

        self.process_button = Button(self.root, text="Process CSV and Update Policy", style="RoundedBlue.TButton", command=self.process_csv_and_update_policy)
        self.process_button.pack(pady=20)
        self.process_button.config(state="disabled")  # Disabled until a policy is selected

        self.status_label = Label(self.root, text="Status: Waiting for action", font=("Segoe UI", 12), bg="#F5F5F5", fg="#0078D7")
        self.status_label.pack(pady=5)
        self.summary_label = Label(self.root, text="Summary: 0 devices processed", font=("Segoe UI", 12), bg="#F5F5F5", fg="#555555")
        self.summary_label.pack(pady=5)

        # Removed the progress bar as per user request
        # self.progress = Progressbar(self.root, style="Progressbar.Horizontal.TProgressbar", mode='determinate')
        # self.progress.pack(pady=10, fill='x', padx=50)

        trademark_label = Label(self.root, text="© Benjamin Lettner", font=("Segoe UI", 10), bg="#F5F5F5", fg="#888888")
        trademark_label.pack(side="bottom", anchor="se", padx=10, pady=10)


def main():
    """Initializes and runs the DeviceControlApp."""
    root = Tk()
    app = DeviceControlApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
