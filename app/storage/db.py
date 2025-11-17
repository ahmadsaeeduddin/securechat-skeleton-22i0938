# app/storage/db.py
import os
import argparse
import pymysql
import hashlib
import os

from dotenv import load_dotenv

load_dotenv()


def get_connection():
    return pymysql.connect(
        host=os.getenv("MYSQL_HOST", "127.0.0.1"),
        port=int(os.getenv("MYSQL_PORT", "3307")),
        user=os.getenv("MYSQL_USER", "scuser"),
        password=os.getenv("MYSQL_PASSWORD", "12345678"),
        database=os.getenv("MYSQL_DB", "securechat"),
        autocommit=True,
    )


def init_schema():
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                email      VARCHAR(255),
                username   VARCHAR(255) UNIQUE,
                salt       VARBINARY(16),
                pwd_hash   CHAR(64)
            )
            """
        )
    conn.close()
    print("[+] users table created/verified")


def _hash_password(salt: bytes, password: str) -> str:
    # pwd_hash = hex(SHA256(salt || password))
    h = hashlib.sha256()
    h.update(salt)
    h.update(password.encode("utf-8"))
    return h.hexdigest()


def create_user(email: str, username: str, password: str) -> bool:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            salt = os.urandom(16)  # 16-byte random salt
            pwd_hash = _hash_password(salt, password)
            cur.execute(
                """
                INSERT INTO users (email, username, salt, pwd_hash)
                VALUES (%s, %s, %s, %s)
                """,
                (email, username, salt, pwd_hash),
            )
        conn.close()
        return True
    except Exception as e:
        print(f"[DB] create_user failed: {e}")
        conn.close()
        return False


def verify_user(email: str, password: str) -> bool:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT salt, pwd_hash FROM users WHERE email = %s",
                (email,),
            )
            row = cur.fetchone()
            if not row:
                conn.close()
                return False
            salt, stored_hash = row
            candidate = _hash_password(salt, password)
            # constant-time compare
            if len(candidate) != len(stored_hash):
                conn.close()
                return False
            result = 0
            for x, y in zip(candidate, stored_hash):
                result |= ord(x) ^ ord(y)
            conn.close()
            return result == 0
    except Exception as e:
        print(f"[DB] verify_user failed: {e}")
        conn.close()
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true", help="Initialize DB schema")
    args = parser.parse_args()

    if args.init:
        init_schema()
