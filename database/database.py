import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash


# ==================================================
# DATABASE LOCATION
# ==================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATABASE_DIR = BASE_DIR / "database"

DATABASE_FILE = DATABASE_DIR / "phishing_platform.db"


# ==================================================
# DATABASE CONNECTION
# ==================================================

def get_connection():

    DATABASE_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_FILE
    )

    connection.row_factory = sqlite3.Row

    return connection


# ==================================================
# INITIALIZE DATABASE
# ==================================================

def initialize_database():

    connection = get_connection()

    cursor = connection.cursor()

    # ----------------------------------------------
    # USERS TABLE
    # ----------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT UNIQUE NOT NULL,

            password_hash TEXT NOT NULL,

            created_at TEXT NOT NULL

        )
        """
    )

    # ----------------------------------------------
    # SCANS TABLE
    # ----------------------------------------------

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            scan_time TEXT NOT NULL,

            scan_type TEXT NOT NULL,

            target TEXT,

            risk_score INTEGER,

            risk_level TEXT,

            findings_count INTEGER,

            FOREIGN KEY(user_id)
                REFERENCES users(id)

        )
        """
    )

    connection.commit()

    connection.close()


# ==================================================
# CREATE USER
# ==================================================

def create_user(
    username,
    password
):

    connection = get_connection()

    cursor = connection.cursor()

    password_hash = generate_password_hash(
        password
    )

    try:

        cursor.execute(
            """
            INSERT INTO users
            (
                username,
                password_hash,
                created_at
            )

            VALUES (?, ?, datetime('now'))
            """,
            (
                username,
                password_hash
            )
        )

        connection.commit()

        user_id = cursor.lastrowid

        connection.close()

        return {
            "success": True,
            "id": user_id,
            "username": username
        }

    except sqlite3.IntegrityError:

        connection.close()

        return {
            "success": False,
            "error": "Username already exists."
        }


# ==================================================
# AUTHENTICATE USER
# ==================================================

def authenticate_user(
    username,
    password
):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            username,
            password_hash

        FROM users

        WHERE username = ?
        """,
        (username,)
    )

    user = cursor.fetchone()

    connection.close()

    if user is None:

        return None

    if check_password_hash(
        user["password_hash"],
        password
    ):

        return {
            "id": user["id"],
            "username": user["username"]
        }

    return None


# ==================================================
# SAVE SCAN
# ==================================================

def save_scan(
    scan_time,
    scan_type,
    target,
    risk_score,
    risk_level,
    findings_count,
    user_id=None
):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO scans
        (
            user_id,
            scan_time,
            scan_type,
            target,
            risk_score,
            risk_level,
            findings_count
        )

        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            scan_time,
            scan_type,
            target,
            risk_score,
            risk_level,
            findings_count
        )
    )

    connection.commit()

    scan_id = cursor.lastrowid

    connection.close()

    return scan_id


# ==================================================
# GET ALL SCANS
# ==================================================

def get_all_scans(
    user_id=None
):

    connection = get_connection()

    cursor = connection.cursor()

    if user_id is not None:

        cursor.execute(
            """
            SELECT
                id,
                scan_time,
                scan_type,
                target,
                risk_score,
                risk_level,
                findings_count

            FROM scans

            WHERE user_id = ?

            ORDER BY id DESC
            """,
            (user_id,)
        )

    else:

        cursor.execute(
            """
            SELECT
                id,
                scan_time,
                scan_type,
                target,
                risk_score,
                risk_level,
                findings_count

            FROM scans

            ORDER BY id DESC
            """
        )

    scans = cursor.fetchall()

    connection.close()

    return [
        dict(scan)
        for scan in scans
    ]


# ==================================================
# GET USER SCANS
# ==================================================

def get_user_scans(
    user_id
):

    return get_all_scans(
        user_id=user_id
    )


# ==================================================
# GET SCAN COUNT
# ==================================================

def get_scan_count(
    user_id=None
):

    connection = get_connection()

    cursor = connection.cursor()

    if user_id is not None:

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM scans
            WHERE user_id = ?
            """,
            (user_id,)
        )

    else:

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM scans
            """
        )

    count = cursor.fetchone()[0]

    connection.close()

    return count


# ==================================================
# CLEAR SCANS
# ==================================================

def clear_scans(
    user_id=None
):

    connection = get_connection()

    cursor = connection.cursor()

    if user_id is not None:

        cursor.execute(
            """
            DELETE FROM scans
            WHERE user_id = ?
            """,
            (user_id,)
        )

    else:

        cursor.execute(
            """
            DELETE FROM scans
            """
        )

    connection.commit()

    connection.close()


# ==================================================
# DELETE USER
# ==================================================

def delete_user(
    user_id
):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        DELETE FROM scans
        WHERE user_id = ?
        """,
        (user_id,)
    )

    cursor.execute(
        """
        DELETE FROM users
        WHERE id = ?
        """,
        (user_id,)
    )

    connection.commit()

    connection.close()


# ==================================================
# INITIALIZE WHEN MODULE LOADS
# ==================================================

initialize_database()