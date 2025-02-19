import sqlite3
username='abc'
password='test'

def login_user(username,password):
    # Connect to the SQLite database
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()

    # Execute the query to check for matching username and password
    cursor.execute('''SELECT * FROM user WHERE username = ? AND password = ?''', (username, password))
    data = cursor.fetchall()

    # Close the connection
    conn.close()

    if len(data) == 1:
        return True
    
    return False

def create_user(username, password):
    # Connect to the SQLite database
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()

    # Check if the username already exists
    cursor.execute('''SELECT * FROM user WHERE username = ?''', (username,))
    if cursor.fetchone() is not None:
        conn.close()
        return False  # Username already exists

    # Insert the new username and password into the table
    cursor.execute('''INSERT INTO user (username, password) VALUES (?, ?)''', (username, password))
    conn.commit()

    # Close the connection
    conn.close()

    return True  # User successfully created

print(login_user(username, password))
print(create_user('new','new'))