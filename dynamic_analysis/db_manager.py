# 파일명: db_manager.py
import sqlite3
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.create_tables()

    def create_tables(self):
        """DB 테이블 생성"""
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                apk_sha256 TEXT,
                package_name TEXT NOT NULL,
                status TEXT NOT NULL,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            )
        ''')
        # --- mobsf_scan_hash 컬럼 추가 ---
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dumped_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER,
                file_path TEXT NOT NULL UNIQUE,
                source_hook TEXT,
                mobsf_scan_hash TEXT,
                FOREIGN KEY(job_id) REFERENCES analysis_jobs(id)
            )
        ''')
        self.conn.commit()

    def create_job(self, package_name):
        """새 분석 작업을 생성하고 ID를 반환"""
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO analysis_jobs (package_name, status) VALUES (?, ?)", (package_name, 'pending'))
        self.conn.commit()
        return cursor.lastrowid

    def update_job_status(self, job_id, status):
        """작업 상태 업데이트"""
        cursor = self.conn.cursor()
        cursor.execute("UPDATE analysis_jobs SET status = ? WHERE id = ?", (status, job_id))
        if status in ['completed', 'error']:
            cursor.execute("UPDATE analysis_jobs SET completed_at = ? WHERE id = ?", (datetime.now(), job_id))
        self.conn.commit()

    def log_dumped_file(self, job_id, file_path, source_hook):
        """덤프된 파일 정보 기록"""
        cursor = self.conn.cursor()
        # 파일 경로가 중복되지 않도록 IGNORE 처리
        cursor.execute("INSERT OR IGNORE INTO dumped_files (job_id, file_path, source_hook) VALUES (?, ?, ?)",
                       (job_id, file_path, source_hook))
        self.conn.commit()

    def update_scan_hash(self, file_path, scan_hash):
        """파일 경로를 기준으로 MobSF 스캔 해시를 업데이트"""
        cursor = self.conn.cursor()
        cursor.execute("UPDATE dumped_files SET mobsf_scan_hash = ? WHERE file_path = ?", (scan_hash, file_path))
        self.conn.commit()