import bcrypt
import os
import re
import string 
USER_DATA_FILE = "users.txt"
# password hashing function
def hash_password(plain_text_password):
    password_byte = plain_text_password.encode('utf-8')
    salt = bcrypt.gensalt()
    password_hashed = bcrypt.hashpw(password_byte, salt)
    password_decode = password_hashed.decode('utf-8')
    return password_decode
#password verification function
def verify_password(plain_text_password, hashed_password):
    password_byte = plain_text_password.encode('utf-8')
    hashed_password_bytes = hashed_password.encode('utf-8')
    verification = bcrypt.checkpw(password_byte, hashed_password_bytes)
    return verification 
#implementation of registration function
def register_user(username, password):
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "r") as f:
            for line in f:
                username_exist = line.strip().split(",")[0]
                if username_exist == username:
                    return False 
    hashed_password = hash_password(password)
    with open(USER_DATA_FILE, "a") as f:
        f.write(f"{username}, {hashed_password}\n")
    return True
#implementation of user existance check
def user_exists(username):
    if not os.path.exists(USER_DATA_FILE):
        return False
    with open(USER_DATA_FILE, "r") as f:
        for line in f:
            username_exist = line.strip().split(",")[0]
            if username_exist == username:
                return False 
            
#implementation of user login
def login_user(username, password):
    if not user_exists(username):
        print("User not registered\n")
        print("You will have to register first\n")
        return False
    with open(USER_DATA_FILE, "r") as f:
        for user in f:
             user_exist, user_password = user.strip().split(":")
             if user_exist == username:
                 if user_password ==password:
                     print("User found")
                     return True
                 else:
                     print("Incorrect! Please re enter the username and password correctly.")

def validate_username(username):
    if re.search (r"\s", username):
        print("Username should not contain space.")
        return False
    else:
        return True

def validate_password(password):
    lowerCase = re.search("[a-z]", password)
    upperCase = re.search("[A-Z]", password)
    digit = re.search(r"\d",password)
    character = re.search(f"[{re.escape(string.punctuation)}]",password)
    if all ([lowerCase, upperCase, digit, character]):
        return True
    else: 
        print("password should contain: LowerCase, UpperCase,Digit and Special character.\n")
        return True
    
def display_menu():
    print("\n" + "=" * 50)
    print("  MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print("  Secure Authentication System")
    print("="*50)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-"*50)

def main():
     print("\nWelcome to the Week 7 Authentication System!")
    
     while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()
        
        if choice == '1':
            # Registration flow
            print("\n--- USER REGISTRATION ---")
            username = input("Enter a username: ").strip()
            
            # Validate username
            is_valid, error_msg = validate_username(username)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue
            
            password = input("Enter a password: ").strip()
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue
            
            # Confirm password
            password_confirm = input("Confirm password: ").strip()
            if password != password_confirm:
                print("Error: Passwords do not match.")
                continue
            
            # Register the user
            register_user(username, password)
        
        elif choice == '2':
            # Login flow
            print("\n--- USER LOGIN ---")
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()
            
            # Attempt login
            if login_user(username, password):
                print("\nYou are now logged in.")
                print("(In a real application, you would now access the d")
                
                # Optional: Ask if they want to logout or exit
                input("\nPress Enter to return to main menu...")
        
        elif choice == '3':
            # Exit
            print("\nThank you for using the authentication system.")
            print("Exiting...")
            break
        
        else:
            print("\nError: Invalid option. Please select 1, 2, or 3.")
if __name__ == "__main__":
   main()

    


    






