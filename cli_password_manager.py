"""CLI Password Manager: Save all passwords in secure csv file, encrypted with salt. Allows for secure storage, password strength testing, password generation and many more features."""

import base64
import csv
import io
import os
import string
import sys
import random
import re
import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime
from typing import Optional


# Global values for yes or 1 and no or 2 used throughout program
acceptance = ["yes", "1", "y", "YES", "Yes", "yEs", "yeS", "YeS", "Y", "YEs"]
denied = ["no", "2", "n", "No", "nO", "N", "NO"]


class PasswordManager:
    """Creates an instance for user to create files and passwords, store passwords securly, encrypt and decrypt files and adding entries to database."""

    def __init__(self):
        """Assignment values for self to be used throughout method"""
        self.master_password: Optional[str] = None
        self.key: Optional[bytes] = None
        self.salt: Optional[bytes] = None
        self.filepath: Optional[str] = None
        self.data: list[list] = []
        self.fernet: Optional[Fernet] = None

    def set_password(self, password: str, salt: Optional[bytes] = None):
        """
        Derive encryption key from the master password with PBKDF2.
        If salt is not provided (None) or empty, generate a new random 16-byte salt.
        """
        if salt is None or len(salt) == 0:
            salt = os.urandom(16)
        self.salt = salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1_200_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.key = key
        self.fernet = Fernet(self.key)

    def encrypt_data(self):
        """Method for encrypting csv file"""
        # Convert self.data (list of lists) into CSV string
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerows(self.data)
        csv_string = output.getvalue().encode()  # Convert to bytes

        # Asserts values are not None
        assert self.fernet is not None
        assert self.salt is not None
        assert self.filepath is not None

        # Encrypt CSV string
        encrypted_data = self.fernet.encrypt(csv_string)

        # Save encrypted data to file
        with open(self.filepath, "wb") as f:
            f.write(encrypted_data)

        # Save salt to companion file
        with open(f"{self.filepath}.salt", "wb") as s:
            s.write(self.salt)

        return "Data encrypted and saved successfully."

    def decrypt_data(self):
        """Method for decrypting data file"""
        # Load salt
        with open(f"{self.filepath}.salt", "rb") as s:
            salt = s.read()

        # Prompt user for password (or use stored)
        password = (self.master_password or getpass.getpass("Enter master password: ")).strip()
        self.set_password(password, salt)

        # Asserts values are not None
        assert self.fernet is not None
        assert self.salt is not None
        assert self.filepath is not None

        # Load and decrypt encrypted file
        with open(self.filepath, "rb") as f:
            encrypted_data = f.read()

        decrypted_csv = self.fernet.decrypt(encrypted_data).decode()

        # Parse CSV into self.data
        input_buffer = io.StringIO(decrypted_csv)
        reader = csv.reader(input_buffer)
        self.data = list(reader)

        return "Data decrypted and loaded successfully."

    def create_file(self, filename: str, password: str):
        """Method for creating a new csv file in database"""
        files_directory = os.path.join(os.getcwd(), "resources")
        if not os.path.exists(files_directory):
            os.makedirs(files_directory)
        self.filepath = os.path.join(files_directory, f"{filename}.csv")
        self.master_password = password
        self.set_password(password, None)
        self.data = [
            ["Name", "Email", "Username", "Password", "Notes", "Creation", "Modified"]
        ]
        result = self.encrypt_data()
        return result

    def load_file(self, filename: str):
        """Method for loading the file when selected by user in instance"""
        files_directory = os.path.join(os.getcwd(), "resources")
        self.filepath = os.path.join(files_directory, f"{filename}")
        if not self.master_password:
            self.master_password = input("Enter your password: ")
        while True:
            try:
                results = self.decrypt_data()
                return results
            except FileNotFoundError:
                print(f"{filename} or {filename}.salt could not be found.")
                sys.exit(1)
            except InvalidToken:
                print("Incorrect password. Try again.")
                self.master_password = input("Enter your password: ")
            except Exception as e:
                print("Error: ", e)
                sys.exit(1)

    def save_data(self):
        """Calls encryption method to save the data added to csv file"""
        return self.encrypt_data()

    def add_entry(self, name, email, username, password, notes):
        """Method for adding an entry to the file"""
        datetime_stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data.append(
            [name, email, username, password, notes, datetime_stamp, datetime_stamp]
        )
        return "Successfully added."
    def search_entries(self, query: str):
        """Return list of (index, row) for entries that match query (case-insensitive) in Name/Email/Username/Notes."""
        if not query:
            return []
        q = query.strip().lower()
        matches = []
        # self.data[0] is header row; real rows start at index 1
        for idx, row in enumerate(self.data[1:], start=1):
            # row = [Name, Email, Username, Password, Notes, Creation, Modified]
            haystack = " ".join([str(row[0]), str(row[1]), str(row[2]), str(row[4])]).lower()
            if q in haystack:
                matches.append((idx, row))
        return matches

def main():
    """Start of the program, prompting user from predefined selection of options"""
    # Start of program with welcome message and starting instance in class
    print_header("Welcome to your CLI Password Manager")
    pm = PasswordManager()

    # Creates a folder to store all the files in one place
    relative_path = os.path.join(os.getcwd(), "resources")
    if not os.path.exists(relative_path):
        os.makedirs(relative_path)

    # While loop for whole instance to allow for fresh setup and adding/changing data or opening existing file and changing data
    while True:
        try:
            files = os.listdir(relative_path)
            # Request from user what they would like to do.
            welcome = input(
                "Would you like to: \n [1] Open a new file \n [2] Open an existing file \n Your choice: "
            ).strip()

            # Option to allow for creating a new file
            if welcome in acceptance:

                # While loop to keep attempting. Else normal Ctrl+C to exit
                while True:
                    try:
                        print_header(" - ")
                        print_message("m_exit_message")
                        print_header("FILE CREATION")

                        # Create new file with user inputting file name
                        filename = input(
                            "What would you like to call your new file? (Note: No need to enter file extension in the end.) \n"
                        ).strip()
                        full_path = os.path.join(relative_path, filename + ".csv")

                        # If filename already exists or incorrect naming, retry
                        if os.path.exists(full_path):
                            print_header("ERROR")
                            print_message("m_file_exists")
                            print_header("-")
                            continue
                        elif re.search(r'[<>:"/\\|?*]', filename):
                            print_header("ERROR")
                            print_message("m_invalid_char")
                            print_header("-")
                            continue
                        elif not filename:
                            print_header("ERROR")
                            print_message("Filename cannot be empty.")
                            continue

                        # Filename successful. Password requests next.
                        else:
                            master_password = password_choice(pm)
                            break
                    except ValueError:
                        print("Please enter the correct length in number")
                        continue
                    except KeyboardInterrupt:
                        user_exit(pm)
                        continue
                    except Exception as e:
                        print("Something went wrong.\n Error:", e)
                        continue

                # Should print confirmations of results
                print_header("FILENAME AND PASSWORD ACCEPTED. CREATING FILE")
                assert master_password
                result = pm.create_file(filename, master_password)
                print_header(result)
                continue

            # Second option from Welcome: opening files
            elif welcome in denied:
                if not files:
                    print_header("ERROR")
                    print_message("m_no_files")
                    print_header(" - ")
                    continue

                # Prints CSV files located in directory (if any)
                csv_files = [file for file in files if file.lower().endswith(".csv")]
                if not csv_files:
                    print_header("ERROR")
                    print("There are no CSV files. Please create one.")
                    print_header("-")
                    continue

                print_header(" - ")
                print("These are the files found in your directory:")
                for index, file in enumerate(csv_files, start=1):
                    print(f"[{index}]", file)

                # Loop for select the file
                while True:
                    try:
                        print_header(" - ")
                        choice = (int(input("Which file would you like to open? "))) - 1
                        if 0 <= choice < len(csv_files):
                            selected_file = csv_files[choice]
                            print_header(f"OPENING {selected_file}")
                            results = pm.load_file(selected_file)
                            print_header(results)
                            break
                        else:
                            print_message("m_invalid")
                            continue
                    except ValueError:
                        print_message("m_invalid")
                        continue
                # Loop to provide options after file is opened: See entries, add, update or delete from database
                while True:
                    print_header("MAIN MENU")
                    print_message("m_options")
                    choice = input("\n Your choice: ")

                    if choice == "1":
                        if len(pm.data) <= 1:
                            print_header("ERROR")
                            print_message("m_no_entries")
                            continue
                        else:
                            # Show names, then allow selecting one to view full details
                            print_database(pm)
                            sel = input("Enter the number to view full details (or press Enter to go back): ").strip()
                            if sel.isdigit():
                                idx = int(sel)
                                if 1 <= idx <= len(pm.data) - 1:
                                    header_row = pm.data[0]
                                    selected_entry = pm.data[idx]
                                    print_header("ENTRY DETAILS")
                                    for i, field in enumerate(header_row, start=1):
                                        value = ("********" if field == "Password" else selected_entry[i - 1])
                                        print(f" [{i}] {field}: {value}")
                                    print_header("space")
                                    input("Press Enter to return to Main Menu...")
                                else:
                                    print_message("m_invalid")
                            # Always return to main menu afterwards
                            continue

                    # Option 2: Adding to database
                    elif choice == "2":
                        # SEARCH entries
                        if len(pm.data) <= 1:
                            print_header("ERROR")
                            print_message("m_no_entries")
                            continue
                        print_header("SEARCH")
                        query = input("Enter a word to search (name/email/username/notes): ").strip()
                        results = pm.search_entries(query)
                        print_search_results(results)
                        input("Press Enter to return to Main Menu...")
                        continue

                    elif choice == "3":
                        # Adding data to database
                        print_header("ADDING A NEW ENTRY")
                        print(
                            "\033[1mNote: All spaces at the beginning and end will automatically be removed\033[0m"
                        )
                        print_header("space")
                        # Loop to allow for data entry
                        while True:
                            name = input("Name: ").strip()
                            if not name:
                                print("Name cannot be empty. Please enter a name. \n")
                            else:
                                break

                        email = input("Email: ").strip()
                        username = input("Username: ").strip()
                        notes = input("Notes: ").strip()
                        password = password_choice(pm)
                        # Printing confirmations to user
                        print_header("ALL DATA ACCEPTED. ADDING TO DATABASE")
                        new_result = pm.add_entry(
                            name, email, username, password, notes
                        )
                        print_header(new_result)
                        pm.save_data()
                        print_header("RETURNING TO MAIN MENU")
                        continue
                    elif choice == "4":
                        # Check if database has any entries
                        if len(pm.data) <= 1:
                            print_header("ERROR")
                            print_message("m_no_entries")
                            print_header("-")
                            continue

                        # Loop for changing single or many entries
                        while True:
                            try:
                                # Print entries in database
                                print_database(pm)

                                # User selection of row to change
                                entry = input(
                                    "Which of the entries would you like to modify? Choose number or exit to return to exit fron entry selection \n "
                                )
                                # Check user for exit or continue with int
                                if entry == "exit":
                                    break
                                else:
                                    entry = int(entry)
                                # Check if value in range of data
                                if 1 <= entry <= len(pm.data) - 1:
                                    selected_entry = pm.data[entry]
                                    print_header("SELECTED ENTRY")
                                else:
                                    print_message("m_invalid")
                                    continue

                                # Printing of values in selected row
                                header_row = pm.data[0]
                                for i, field in enumerate(header_row, start=1):
                                    print(f" [{i}] {field}: {selected_entry[i-1]}")
                                print_header("space")
                                selected_entry_value = input("Your choice: ").strip()
                                print_header("space")

                                # Check if value is digit or restart process of row selection
                                if selected_entry_value.isdigit():
                                    selected_entry_value = int(selected_entry_value) - 1
                                else:
                                    print_message("m_invalid")
                                    continue

                                # Check confirming which of the values in row to change
                                if 0 <= selected_entry_value < len(header_row):
                                    entry_confirm = input(
                                        f"You selected {header_row[selected_entry_value]}. Confirm? \n [1] Yes \n [2] No \n Your choice: "
                                    ).strip()

                                    # If password changing, run password function; else, allow user to update other values
                                    if (
                                        selected_entry_value == 3
                                        and entry_confirm in acceptance
                                    ):
                                        new_value = password_choice(pm)
                                        print_header("space")
                                        print_header("UPDATING")
                                        selected_entry[int(selected_entry_value)] = (
                                            new_value
                                        )
                                        datetime_stamp = datetime.now().strftime(
                                            "%Y-%m-%d %H:%M:%S"
                                        )
                                        selected_entry[-1] = datetime_stamp
                                        print_header("UPDATE COMPLETE")

                                    # After user confirm of thier selection, enter value to replace
                                    elif entry_confirm in acceptance:
                                        new_value = input(
                                            "Please enter your update: "
                                        ).strip()
                                        print_header("space")
                                        print_header("UPDATING")
                                        selected_entry[int(selected_entry_value)] = (
                                            new_value
                                        )
                                        datetime_stamp = datetime.now().strftime(
                                            "%Y-%m-%d %H:%M:%S"
                                        )
                                        selected_entry[-1] = datetime_stamp
                                        print_header("UPDATE COMPLETE")
                                    else:
                                        continue
                                else:
                                    print_message("m_invalid")
                                    continue

                                # Either continue to modify data or move to main menu
                                update_confirm = input(
                                    "Would you like to update more or return to Main Menu? \n [1] Update \n [2] Main Menu \n Your choice: "
                                ).strip()
                                if update_confirm == "1":
                                    continue
                                elif update_confirm == "2":
                                    pm.save_data()
                                    break
                                else:
                                    print_message("m_invalid")
                                    continue

                            # Handle input and runtime errors
                            except ValueError:
                                print_message("m_invalid")
                            except KeyboardInterrupt:
                                user_exit(pm)
                                continue
                            except Exception as e:
                                print("Something went wrong.\n Error:", e)

                    elif choice == "5":
                        # Check if database has any entries
                        if len(pm.data) <= 1:
                            print_header("ERROR")
                            print_message("m_no_entries")
                            print_header("-")
                            continue

                        # Loop for deleting single or many entries
                        while True:
                            try:
                                # Print delete warning, then entries in the database
                                print_message("m_delete_reminder")

                                # Print entries in database
                                print_database(pm)
                                delete_entry(pm)

                                # Ask whether to continue deleting or return to main menu
                                delete_end = input(
                                    "Would you like to delete more or return to Main Menu? \n [1] Delete \n [2] Main Menu \n Your choice: "
                                ).strip()
                                if delete_end == "1":
                                    continue
                                elif delete_end == "2":
                                    break
                                else:
                                    print_message("m_invalid")
                                    continue

                            # Handle input and runtime errors
                            except ValueError:
                                print_message("m_invalid")
                            except KeyboardInterrupt:
                                user_exit(pm)
                                continue
                            except Exception as e:
                                print("Something went wrong.\n Error:", e)

                    elif choice == "6":
                        print_header("ENCRYPTING DATA")
                        pm.encrypt_data()
                        print_header("EXITING PROGRAM")
                        print_header("GOODBYE")
                        sys.exit(0)

        except KeyboardInterrupt:
            user_exit(pm)
            continue
        except ValueError:
            print_message("m_invalid")
        except Exception as e:
            print("Something went wrong.\n Error:", e)


def generate_password(length):
    """Function for generating new password within the file at user request"""
    if length <= 8:
        print(
            "Password cannot be less than 8 characters long. This is the standard generation length."
        )
        lower = random.choices(string.ascii_lowercase, k=2)
        upper = random.choices(string.ascii_uppercase, k=2)
        digit = random.choices(string.digits, k=2)
        special = random.choices(string.punctuation, k=2)
        combined_values = lower + upper + digit + special
        values_list = list(combined_values)
        random.shuffle(values_list)
        new_password = "".join(values_list)

        return new_password

    elif length > 8:
        # Makes a string to choose from for extra length passwords
        all_values = "".join(sorted(set(string.printable) - set(string.whitespace)))

        # Creates 2 of each of the criteria to keep it equal
        lower = random.choices(string.ascii_lowercase, k=2)
        upper = random.choices(string.ascii_uppercase, k=2)
        digit = random.choices(string.digits, k=2)
        special = random.choices(string.punctuation, k=2)

        # Finding how many extra characters needed to include in the password
        extra = length - 8
        extra = random.choices(all_values, k=extra)

        # Combines all the new values, puts them in a list for shuffling and joining
        combined_values = lower + upper + digit + special + extra
        values_list = list(combined_values)
        random.shuffle(values_list)
        new_password = "".join(values_list)

        return new_password


def password_strength_check(password):
    """Function for checking password strength with predefined checks of 2 per character type and checking database for possible compromised password"""
    # Counters to check each of the cases in the password and listing them
    lower = sum(1 for c in password if c.islower())
    upper = sum(1 for c in password if c.isupper())
    digit = sum(1 for c in password if c.isdigit())
    special = sum(1 for c in password if c in string.punctuation)
    strength_list = [lower, upper, digit, special]

    # Calculates the strength and possible total strength
    strength = lower + upper + digit + special
    total = strength + len(password) / 2

    # Try to avoid errors in file not found
    try:
        # Open compromised list to check password if in or not in list
        with open("data/compromised_list.txt", "r", encoding="utf-8") as file:
            content = file.read().splitlines()
            if password in content:
                print_header("space")
                print(
                    "Your password was found in a 1 million list of compromised passwords.It is highly recommend to change it so something stronger. Use the below list of categories as a guide (minimum 2 of each, randomly ordered)"
                )
                strength = len(password) / 2
            elif password not in content:
                print_header("space")
                print(
                    "Your password was not found in the compromised list; yet, if it is less than 12 characters, recommend you change it to 12 or more characters in length. Use the below list of categories as a guide (minimum 2 of each, randomly ordered)"
                )
                strength += len(password) / 2

    # Error incase file not found
    except FileNotFoundError:
        print("Warning: Could not check password versus compromised list")
        pass

    # Rating system that is dynamic bases on length of password
    if strength < total * 0.3 or len(password) < 8:
        strength = 0
        rating = "Weak"
    elif strength < total * 0.6 or len(password) < 11:
        rating = "Good"
    else:
        rating = "Strong"

    if any(x < 2 for x in strength_list) and strength > 0:
        rating = "Good"

    # Rounding values to print
    strength = round(strength)
    total = round(total)

    # Printing results directly
    print(
        f"\n Password length: {len(password)} \n Lowercase: {lower} \n Uppercase: {upper} \n Numbers: {digit} \n Special: {special} \n Score: {strength} from {total} \n Rating: {rating} \n"
    )

    return rating


def delete_entry(pm: PasswordManager):
    """Function to delete an entry from within the data file (csv)"""
    try:
        data = pm.data
        # User selection of row to delete
        entry = int(input("Which of the entries would you like to delete? "))
        if 1 <= entry <= len(data) - 1:
            selected_entry = data[entry]
            print_header("SELECTED ENTRY")
            # Printing of values in selected row
            header_row = pm.data[0]
            for i, field in enumerate(header_row, start=1):
                print(f" [{i}] {field}: {selected_entry[i-1]}")
        else:
            print_message("m_invalid")
            return 1

        # Prompt again to confirm deletion of the selected entry
        print_message("m_delete_reminder")
        print_header("space")
        delete_confirm = input(
            f"Confirm delete? \n [1] Yes \n [2] No \n Your choice: "
        ).strip()

        # Confirm user selection to delete
        if delete_confirm in acceptance:
            print_header("space")
            print_header("DELETING ENTRY FROM DATABASE")
            del data[entry]
            print_header("DELETE ENTRY COMPLETE")
            return 0
        elif delete_confirm in denied:
            print_header("space")
            print_header("DATA WAS NOT DELETED")
            print_header("space")
            return 0
        else:
            print_message("m_invalid")
            return 1
    except ValueError:
        print_message("m_invalid")
        return 1
    except KeyboardInterrupt:
        user_exit(pm)
        return 1
    except Exception as e:
        print("Something went wrong.\n Error:", e)
        return 1


def print_header(message, width=80):
    """Function for printing breaker lines in program run"""
    # Function for format/printing headers throughout the code
    if message == "space":
        print("")
    elif message == "-":
        print("-" * width)
    elif message == " - ":
        print("\n" + ("-" * width) + "\n")
    else:
        dashes = dashes_calculator(message)
        print("")
        print("-" * dashes + f"   {message}   " + dashes * "-", end="\n\n")


def dashes_calculator(message):
    """Function to calculate the number of dashes in print_header for uniform look of the headings/line breakers"""
    width = 80
    message_length = len(message)
    calculation = width - message_length
    dashes = round((calculation - 6) / 2)
    return dashes


def print_message(message):
    """Predefined messages to be used within the code for shorthand adding of long print messages"""
    # Function to print messages for used throughout the code
    if message == "m_file_exists":
        print("File already exists.")
    elif message == "m_invalid_char":
        print("Filename contains invalid characters. Try again.")
    elif message == "m_long_no_space":
        print(
            "Note: All characters, numbers and symbols are accepted. However, passwords cannot start or end with spaces - they will be removed automatically."
        )
    elif message == "m_pass_empty":
        print("Password cannot be empty. Try again.")
    elif message == "m_no_files":
        print("No files found in the directory. Try creating a file first.")
    elif message == "m_invalid":
        print(
            "Invalid choice. Please choose the number of the required file/option. Restarting..."
        )
    elif message == "m_options":
        print(
            "Choose from the following options:\n"
            " [1] See all entries in the database\n"
            " [2] Search entries (by name/email/username/notes)\n"
            " [3] Add a new entry to the database\n"
            " [4] Update an existing entry\n"
            " [5] Delete an existing entry\n"
            " [6] Exit program"
        )
    elif message == "m_no_entries":
        print("No entries available. Please add some.")
    elif message == "m_fail_pass":
        print("Invalid choice. Restarting password options... ")
    elif message == "m_exit_message":
        print(
            "If you would like to exit from the program, press Ctrl+C. If a database is open, it will close it and encrypt it."
        )
    elif message == "m_delete_reminder":
        print(
            "Once data is deleted, it cannot be restored. Be careful with the your selections."
        )
    elif message == "m_delete_nothing":
        print("Entry was not deleted.")
    elif message == "m_invalid_number":
        print("Invalid input. Please choose a whole number (eg. 12, 15, 18...)")
    else:
        print(f"{message} \n")


def password_choice(pm: PasswordManager):
    """Function for creating master password"""
    # While loop to keep active the password entry
    while True:
        try:
            # Padding for CLI
            print_header("space")
            print_header("PASSWORD CREATOR")
            print_header("space")
            print_message("m_long_no_space")
            print_header(" - ")

            # Check if password for master or entries into file
            if pm.filepath is None:
                new_choice = input(
                    "Would you like to: \n [1] Enter your own master password \n [2] Generate a password \n Your choice: "
                ).strip()
            else:
                new_choice = input(
                    "Would like to: \n [1] Enter your own password \n [2] Generate a password \n Your choice:  "
                )
            # User input password
            if new_choice in acceptance:
                print_header("space")
                password = input("Password: ").strip()
                confirm = input("Confirm: ").strip()
                print_header("space")
                # Check for master password input or entries
                if not password and pm.filepath is None:
                    print_header("ERROR")
                    print(
                        "\033[1mThis is a master password and should be strong. It cannot be empty.\033[0m \n"
                    )
                    print_header("RESTARTING PASSWORD CREATOR")
                    continue
                elif not password:
                    no_password = input(
                        "No password was entered.\n [1] Agree \n [2] Redo \n Your choice: "
                    )
                    if no_password == "1" and password == confirm:
                        break
                    if no_password == "2" or password != confirm:
                        print_header("RESTARTING PASSWORD CREATOR")
                        continue
                if password != confirm:
                    print_header("ERROR")
                    print("PASSWORD MISMATCH - RESTARTING PASSWORD CREATOR")
                    continue
                # Force strength test on master password, while request if other
                if pm.filepath is None:
                    print_header("PASSWORD STRENGTH TEST")
                    check = password_strength_check(password)
                    if check != "Strong":
                        print(
                            "\033[1mThis is a master password and should be strong. It is recommended for you to change your password and either remember it or write it down somewhere safe. Use the categories above as a guide (2 of each in random order) or use the password generator option. \033[0m \n"
                        )
                else:
                    strength_check = input(
                        "Strength check your password? \n [1] Yes \n [2] No \n Your choice: "
                    ).strip()
                    if strength_check in acceptance:
                        print_header("PASSWORD STRENGTH TEST")
                        password_strength_check(password)
                    elif strength_check in denied:
                        break
                    else:
                        print_message("m_invalid")
                        continue
                password_accept = input(
                    "Would you like to: \n [1] Keep the password \n [2] Change the password \n Your choice: "
                ).strip()
                if password_accept in acceptance:
                    break
                elif password_accept in denied:
                    continue
                else:
                    print_header("ERROR")
                    print_message("m_fail_pass")
                    continue
            # Generating password option
            elif new_choice in denied:
                password_length = input(
                    "How long would you like your password to be? (Recommended: 12) \n Your choice: "
                ).strip()

                if password_length.isdigit() and pm.filepath is None:
                    password = generate_password(int(password_length))
                    print(f"The generated password is: {password} \n")
                    print(
                        "Please save this password in a safe place. If you lose this password, you will lose access to the file and all its contents."
                    )
                elif password_length.isdigit():
                    password = generate_password(int(password_length))
                    print(f"The generated password is: {password} \n")
                else:
                    print_header("ERROR")
                    print_message("m_invalid_number")
                    continue
                print_header("PASSWORD STRENGTH TEST")
                strength_check = input(
                    "Strength check your password? \n [1] Yes \n [2] No \n \n Your choice: "
                ).strip()
                if strength_check in acceptance:
                    password_strength_check(password)
                    confirm = input(
                        "Would you like to: \n [1] Keep the password \n [2] Change the password \n Your choice: "
                    ).strip()
                    if confirm in acceptance:
                        print_header("PASSWORD ACCEPTED")
                        break
                    elif confirm in denied:
                        print_header("PASSWORD CREATOR RESTART")
                        continue
                    else:
                        print_message("m_invalid")
                        continue
            else:
                print_message("m_invalid")
                continue
            break
        except ValueError:
            print_message("m_invalid")
            continue
        except KeyboardInterrupt:
            user_exit(pm)
            continue
        except Exception as e:
            print("Something went wrong.\n Error:", e)
            continue

    return password


def user_exit(pm: PasswordManager):
    """Function for safe exit from the program"""
    print_header("Process Interrupted By User")
    exit_confirm = input(
        "Are you sure you want to exit? \n [1] Yes \n [2] No \n Your choice: "
    )
    if exit_confirm == "1" or not exit_confirm:
        if pm.filepath is not None:
            save_confirm = input(
                "Would you like to save your data first? \n [1] Yes \n [2] No \n Your choice: "
            )
            if save_confirm == "1" or not save_confirm:
                if pm.filepath and pm.data:
                    pm.save_data()
                    print_header("EXITING PROGRAM")
                    print_header("GOODBYE")
                    sys.exit(0)
            elif save_confirm == "2":
                print_header("EXITING PROGRAM")
                print_header("GOODBYE")
                sys.exit(0)
        else:
            sys.exit(0)
    if exit_confirm == "2":
        return

def print_search_results(matches):
    """Pretty print search matches without revealing passwords."""
    if not matches:
        print_header("No matches found")
        return
    print_header(f"{len(matches)} match(es)")
    print(f'{"#":<4} {"Name":<24} {"Email":<28} {"Username":<20} {"Notes"}')
    print("-" * 80)
    for idx, row in matches:
        name, email, username, _password, notes = row[0], row[1], row[2], row[3], row[4]
        print(f'{idx:<4} {name[:24]:<24} {email[:28]:<28} {username[:20]:<20} {notes[:40]}')
    print_header("END OF RESULTS")

def print_database(pm: PasswordManager):
    """Function for print the database for user selection"""
    # Print entries in database
    print_header("DATA IN DATABASE")
    for index, row in enumerate(pm.data[1:], start=1):
        print(f"[{index}] {row[0]}")
    print_header("END OF DATA")
    print_header("space")


if __name__ == "__main__":
    main()
