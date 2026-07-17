import psycopg
import os
from dotenv import load_dotenv
from urllib.parse import urlparse

load_dotenv()

def init_db():
    DATABASE_URL = os.getenv("DATABASE_URL")

    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable is not set")
    
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

    db_name = DATABASE_URL.rsplit('/', 1)[-1]
    base_url = DATABASE_URL.rsplit('/', 1)[0] + '/postgres'

    conn = psycopg.connect(base_url, autocommit=True)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT 1 FROM pg_database WHERE datname = %s",
        (db_name,)
    )

    if not cursor.fetchone():
        from psycopg import sql
        cursor.execute(
            sql.SQL("CREATE DATABASE {}")
            .format(sql.Identifier(db_name))
        )

    cursor.close()
    conn.close()
