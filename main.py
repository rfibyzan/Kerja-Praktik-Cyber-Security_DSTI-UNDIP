from fastapi import FastAPI, Depends
from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.orm import Session
import pydantic
from typing import List
from database import engine, Base, get_db

# Baris ini akan otomatis membuatkan tabel di MySQL jika belum ada
Base.metadata.create_all(bind=engine)

app = FastAPI(title="DSTI Automated Attack Surface Management API")

# --- MODEL DATABASE (SQLAlchemy) ---
class DomainDB(Base):
    __tablename__ = "domains"
    id_domain = Column(Integer, primary_key=True, index=True, autoincrement=True)
    nama_domain = Column(String(255), unique=True, index=True)
    ip_address = Column(String(45))
    status_monitoring = Column(Boolean, default=True)

# --- SKEMA INPUT (Pydantic) ---
class DomainCreate(pydantic.BaseModel):
    # Nama variabel harus sama persis dengan kunci di aset_aktif_undip.json
    domain_name: str 
    ip_address: str = None

# --- ENDPOINT UNTUK MASSEA ---
# Menggunakan List[DomainCreate] karena Massea mengirim banyak data sekaligus (Array)
@app.post("/api/domains/add")
def add_new_domains(domains: List[DomainCreate], db: Session = Depends(get_db)):
    added_count = 0
    for d in domains:
        # Cek database agar tidak ada domain yang masuk dua kali
        existing = db.query(DomainDB).filter(DomainDB.nama_domain == d.domain_name).first()
        if not existing:
            new_domain = DomainDB(nama_domain=d.domain_name, ip_address=d.ip_address)
            db.add(new_domain)
            added_count += 1
    
    db.commit()
    return {"status": "success", "message": f"{added_count} domain baru berhasil disimpan ke MySQL."}