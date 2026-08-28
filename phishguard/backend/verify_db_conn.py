import asyncio
from app.db.mysql import AsyncSessionLocal, engine, settings
from sqlalchemy import text

async def test_db():
    print(f"Database URL configured: {settings.DATABASE_URL}")
    async with AsyncSessionLocal() as session:
        # Ping
        res = await session.execute(text("SELECT 1"))
        ping_val = res.scalar()
        print(f"Database ping test: PASS (returned {ping_val})")
        
        # Query tables
        res_tables = await session.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        tables = [r[0] for r in res_tables.fetchall() if not r[0].startswith("sqlite_")]
        print(f"Verified Tables ({len(tables)} total): {tables}")
        
        for t in tables:
            cnt = (await session.execute(text(f"SELECT count(*) FROM {t}"))).scalar()
            print(f"  [OK] {t}: {cnt} rows stored")

    print("\nOVERALL STATUS: CONNECTED PROPERLY (PASS)")

if __name__ == "__main__":
    asyncio.run(test_db())
