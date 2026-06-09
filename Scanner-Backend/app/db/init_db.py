from sqlalchemy import text
from .base import engine
from .models import Base


def init_tables():
    Base.metadata.create_all(bind=engine)

    # Ensure the tags field exists on existing subscription plans tables.
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE IF EXISTS subscription_plans ADD COLUMN IF NOT EXISTS tags JSONB"))
