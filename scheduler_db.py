import sqlite3
from datetime import datetime, timedelta, timezone
import config

class SchedulerDB:
    def __init__(self, db_path=None):
        self.db_path = db_path or config.SCHEDULER_DB_PATH
        self.init_db()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def init_db(self):
        """Membuat tabel scan_schedules jika belum ada."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_schedules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_name TEXT UNIQUE NOT NULL,
                    interval_days INTEGER DEFAULT 7,
                    last_scan_time TEXT,
                    next_scan_time TEXT NOT NULL,
                    scan_status TEXT DEFAULT 'Idle',
                    current_scan_id INTEGER,
                    error_log TEXT
                )
            """)
            conn.commit()

    def register_domains(self, domains, interval_days=7):
        """Mendaftarkan domain baru dari aset_aktif ke database scheduler."""
        now = datetime.now(timezone.utc)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for domain in domains:
                # Masukkan domain baru, abaikan jika sudah terdaftar
                cursor.execute("""
                    INSERT OR IGNORE INTO scan_schedules 
                    (domain_name, interval_days, next_scan_time)
                    VALUES (?, ?, ?)
                """, (domain, interval_days, now.isoformat()))
            conn.commit()

    def get_due_domains(self):
        """Mengambil daftar domain yang jadwal scannya sudah jatuh tempo (due)."""
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT domain_name, interval_days, current_scan_id FROM scan_schedules
                WHERE next_scan_time <= ? AND scan_status != 'Running'
            """, (now,))
            return cursor.fetchall()

    def update_scan_start(self, domain_name, scan_id):
        """Mencatat bahwa scan di Pentest-Tools API telah dimulai."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE scan_schedules
                SET scan_status = 'Running', current_scan_id = ?, error_log = NULL
                WHERE domain_name = ?
            """, (scan_id, domain_name))
            conn.commit()

    def update_scan_success(self, domain_name, interval_days):
        """Mencatat bahwa scan sukses dan menghitung jadwal scan berikutnya."""
        now = datetime.now(timezone.utc)
        next_scan = now + timedelta(days=interval_days)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE scan_schedules
                SET scan_status = 'Idle', 
                    last_scan_time = ?, 
                    next_scan_time = ?, 
                    current_scan_id = NULL
                WHERE domain_name = ?
            """, (now.isoformat(), next_scan.isoformat(), domain_name))
            conn.commit()

    def update_scan_failed(self, domain_name, error_msg):
        """Mencatat kegagalan scan untuk ditinjau oleh administrator."""
        # Jadwal di-delay 1 hari untuk retry otomatis
        retry_time = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE scan_schedules
                SET scan_status = 'Failed', 
                    next_scan_time = ?, 
                    error_log = ?
                WHERE domain_name = ?
            """, (retry_time, error_msg, domain_name))
            conn.commit()
