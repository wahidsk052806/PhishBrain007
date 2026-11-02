"""The database URL must name the driver that is actually installed.

A bare ``postgresql://`` URL makes SQLAlchemy import psycopg2, which the
requirements do not install (they pin psycopg 3). In Compose that produced a
backend that answered scans while never persisting them, and a dashboard badge
reading only "backend degraded".
"""
from __future__ import annotations

from app.db.session import sqlalchemy_url


def test_postgres_urls_use_the_installed_psycopg3_driver():
    assert (
        sqlalchemy_url("postgresql://phishbrain:phishbrain@postgres:5432/phishbrain")
        == "postgresql+psycopg://phishbrain:phishbrain@postgres:5432/phishbrain"
    )
    # Heroku-style alias, same driver.
    assert sqlalchemy_url("postgres://u:p@db:5432/app") == "postgresql+psycopg://u:p@db:5432/app"


def test_other_urls_are_left_alone():
    assert sqlalchemy_url("sqlite:///./phishbrain.db") == "sqlite:///./phishbrain.db"
    # Already explicit: rewriting it would double the driver suffix.
    assert (
        sqlalchemy_url("postgresql+psycopg://u@db:5432/app")
        == "postgresql+psycopg://u@db:5432/app"
    )
