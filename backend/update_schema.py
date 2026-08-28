import asyncio
import sys
import os

# Add backend to path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from app.db.mysql import init_db
from app.core.config import settings
import sqlite3

async def main():
    print("Creating missing tables...")
    await init_db()
    
    print("Altering existing tables if needed...")
    db_path = settings.DATABASE_URL.replace("sqlite+aiosqlite:///", "")
    if db_path:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT 0;")
            print("Added email_verified")
        except Exception as e:
            print(e)
            
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN profile_completed BOOLEAN NOT NULL DEFAULT 0;")
            print("Added profile_completed")
        except Exception as e:
            print(e)
            
        conn.commit()
        conn.close()

if __name__ == "__main__":
    asyncio.run(main())
