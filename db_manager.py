import sqlite3
import os

# Define the directory and file path for the local SQLite database
DB_FOLDER = 'database'
DB_FILE = os.path.join(DB_FOLDER, 'url_logs.db')


def setup_database():
    """
    Creates the database folder and the necessary table if they don't already exist.
    Using context managers (the 'with' keyword) ensures the database connection
    is safely closed automatically when the block ends, preventing locked file errors.
    """
    # Create the 'database' folder if it is missing
    if not os.path.exists(DB_FOLDER):
        os.makedirs(DB_FOLDER)

    # Connect to SQLite. If 'url_logs.db' doesn't exist, SQLite creates it instantly.
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()

        # Execute SQL to create the table.
        # - AUTOINCREMENT: Automatically assigns a unique ID (1, 2, 3...) to each entry.
        # - UNIQUE: Prevents the exact same URL from being logged multiple times.
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS phishing_logs
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           url
                           TEXT
                           UNIQUE
                           NOT
                           NULL,
                           status
                           TEXT
                           NOT
                           NULL
                       )
                       ''')
        # Commit (save) the changes to the database file
        conn.commit()


def log_url(url: str, status: str) -> bool:
    """
    Saves a newly analyzed URL and its AI prediction to the database.

    Args:
        url (str): The suspicious link that was analyzed.
        status (str): The result of the analysis ('Phishing' or 'Safe').

    Returns:
        bool: True if the database updated successfully, False if an error occurred.
    """
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            # INSERT OR IGNORE: A very helpful SQLite command. If the URL is already in
            # the database (triggering the UNIQUE constraint), it silently skips the insert
            # instead of crashing the program.
            cursor.execute('''
                           INSERT
                           OR IGNORE INTO phishing_logs (url, status) 
                VALUES (?, ?)
                           ''', (url, status))
            conn.commit()
            return True

    except sqlite3.Error as e:
        # Catching specific database errors helps with debugging
        print(f"Database Error: {e}")
        return False


def check_url_in_db(url: str) -> str | None:
    """
    Acts as a caching system. Checks if a URL has already been analyzed to save
    the AI from doing redundant work.

    Args:
        url (str): The URL the user just typed into the GUI.

    Returns:
        str | None: The status ('Phishing' or 'Safe') if found, else None.
    """
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()

        # Parameterized queries (?,) are CRITICAL in cybersecurity.
        # They sanitize the user's input, preventing malicious users from typing
        # "DROP TABLE" into your URL box to delete your database (SQL Injection).
        cursor.execute('SELECT status FROM phishing_logs WHERE url = ?', (url,))
        result = cursor.fetchone()

    # If the database returns a match, grab the first column (status). Otherwise, return None.
    if result:
        return result[0]
    return None


# Auto-execute: Ensures the database is built and ready the moment this file is imported.
setup_database()