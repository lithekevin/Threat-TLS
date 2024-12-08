from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base

DATABASE_URL = 'sqlite:///attack_results.db'

engine = create_engine(DATABASE_URL, echo=False)

Base.metadata.create_all(engine)

SessionLocal = sessionmaker(bind=engine)
