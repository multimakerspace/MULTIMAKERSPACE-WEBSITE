import sqlite3
import os
from werkzeug.security import generate_password_hash

def init_db():
    conn = sqlite3.connect('multimaker.db')
    cursor = conn.cursor()
    
    # Users table with is_approved column
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT DEFAULT 'student',
            is_approved BOOLEAN DEFAULT 1,  -- NEW: Approval status
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Class schedule table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS class_schedule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_name TEXT NOT NULL,
            day TEXT NOT NULL,
            time TEXT NOT NULL,
            instructor TEXT NOT NULL,
            duration TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Student achievements table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS student_achievements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            achievement TEXT NOT NULL,
            date_achieved DATE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    # Media gallery table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS media_gallery (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            category TEXT NOT NULL,
            uploaded_by INTEGER NOT NULL,
            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (uploaded_by) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    # Create class_students junction table for many-to-many relationship
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS class_students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (class_id) REFERENCES class_schedule (id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            UNIQUE(class_id, user_id)
        )
    ''')
    
    # Insert default admin user if not exists
    try:
        cursor.execute(
            'INSERT OR IGNORE INTO users (username, email, password, full_name, role, is_approved) VALUES (?, ?, ?, ?, ?, ?)',
            ('admin', 'admin@multimaker.com', generate_password_hash('admin123'), 'Administrator', 'admin', 1)
        )
        print("Default admin user created successfully")
    except sqlite3.IntegrityError:
        print("Admin user already exists")
    except Exception as e:
        print(f"Error creating admin user: {e}")
    
    conn.commit()
    conn.close()
    print("Database initialized successfully")

def get_db_connection():
    conn = sqlite3.connect('multimaker.db')
    conn.row_factory = sqlite3.Row
    return conn