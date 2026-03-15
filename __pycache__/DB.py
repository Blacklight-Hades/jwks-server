import sqlite3
import time
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def init_db(db_file: str):
    """
    Create the keys table if it doesn't already exist.
    Schema is fixed per project requirements.
    """
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def get_valid_keys_from_db(db_file: str):
    now = int(time.time())
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (now,))
    rows = cursor.fetchall()
    conn.close()

    result = []
    for kid, pem_str in rows:
        private_key = load_pem_private_key(
            pem_str.encode("utf-8") if isinstance(pem_str, str) else pem_str,
            password=None,
        )
        result.append((kid, private_key))
    return result


def get_expired_key_from_db(db_file: str):
    
    now = int(time.time())
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT kid, key FROM keys WHERE exp < ? LIMIT 1", (now,)
    )
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    kid, pem_str = row
    private_key = load_pem_private_key(
        pem_str.encode("utf-8") if isinstance(pem_str, str) else pem_str,
        password=None,
    )
    return (kid, private_key)
