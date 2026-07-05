from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Konfigurasi koneksi MySQL lokal. 
# Secara default, user XAMPP adalah 'root' dan password-nya kosong.
DATABASE_URL = "mysql+pymysql://root:@localhost/dsti_asm_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()