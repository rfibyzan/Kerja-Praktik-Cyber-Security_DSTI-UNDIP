import time
from celery import Celery

celery_app = Celery(
    "tasks",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)

@celery_app.task
def trigger_pentest_scan(id_domain: int, nama_domain: str): # <--- Fungsi ini yang dicari!
    print(f"[{nama_domain}] Memulai pemindaian (pentest) di background...")
    time.sleep(10)
    print(f"[{nama_domain}] Pemindaian selesai!")
    return {"status": "success", "domain": nama_domain}