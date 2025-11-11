import bcrypt
def hash_password (plain_text_password):
    password_bytes = plain_text_password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password
def verify_password (plain_text_password, hashed_password):
    password_bytes = plain_text_password.encode("utf-8")
    hashed_password_bytes= hashed_password.encode ("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_password_bytes)
def user_registration(UserName, Password):
    hashed_password = hash_password(Password)
    with open ("user.txt", "a") as f:
        f.write(f"{UserName}, {hashed_password}\n")
    print(f"User{UserName} registered.")
def user_login(UserName, Password):
    with open("user.txt", "r") as f:
        for line in f.readline():
            user, hash = line.strip().split(',',1)
            if user == UserName:
                return verify_password (Password, hash)
    return False




