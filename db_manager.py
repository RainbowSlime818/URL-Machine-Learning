import sqlite3
import os

# Define where the database file will live
DB_FOLDER = 'database'
DB_FILE = os.path.join(DB_FOLDER, 'url_logs.db')


def setup_database():
    """Creates the database folder and table if they don't exist."""
    if not os.path.exists(DB_FOLDER):
        os.makedirs(DB_FOLDER)

    # Connect to SQLite (this automatically creates the file if it doesn't exist)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Create a table with three columns: ID, URL, and Status
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

    conn.commit()
    conn.close()


def log_url(url, status):
    """Saves a flagged URL to the database."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # INSERT OR IGNORE prevents the program from crashing if we try to log the same URL twice
        cursor.execute('''
                       INSERT
                       OR IGNORE INTO phishing_logs (url, status) 
            VALUES (?, ?)
                       ''', (url, status))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Database Error: {e}")
        return False


def check_url_in_db(url):
    """Checks if a URL has already been analyzed and flagged."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute('SELECT status FROM phishing_logs WHERE url = ?', (url,))
    result = cursor.fetchone()

    conn.close()

    if result:
        return result[0]  # Returns the status (e.g., "Phishing" or "Safe")
    return None  # Returns None if the URL isn't in the database yet


# Run setup automatically when this file is imported or run
setup_database()