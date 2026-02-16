import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pytz


# Malaysia Timezone Configuration
MALAYSIA_TZ = pytz.timezone('Asia/Kuala_Lumpur')

def get_malaysia_now():
    """Get current time in Malaysia timezone (UTC+8)."""
    return datetime.now(MALAYSIA_TZ)

def convert_to_malaysia_tz(datetime_str):
    """Convert UTC datetime string to Malaysia timezone."""
    if not datetime_str:
        return None
    
    try:
        if isinstance(datetime_str, str):
            utc_dt = datetime.fromisoformat(datetime_str.replace('Z', '+00:00'))
        else:
            utc_dt = datetime_str
        
        if utc_dt.tzinfo is None:
            utc_dt = pytz.utc.localize(utc_dt)
        
        malaysia_dt = utc_dt.astimezone(MALAYSIA_TZ)
        return malaysia_dt
    except Exception as e:
        print(f"Error converting timezone: {e}")
        return datetime_str
def add_additional_remarks_column():
    """Add additional_remarks column to attendance table if it doesn't exist."""
    try:
        conn = get_db_connection()
        
        # Check if additional_remarks column exists
        columns = conn.execute("PRAGMA table_info(attendance)").fetchall()
        column_names = [col[1] for col in columns]
        
        if 'additional_remarks' not in column_names:
            print("Adding additional_remarks column to attendance table...")
            conn.execute('ALTER TABLE attendance ADD COLUMN additional_remarks TEXT')
            conn.commit()
            print("✅ additional_remarks column added!")
        
        conn.close()
    except Exception as e:
        print(f"Error adding additional_remarks column: {e}")

# Call this function in your initialization
add_additional_remarks_column()

def get_db_connection():
    """Get a database connection with row factory."""
    conn = sqlite3.connect('multimaker.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_upcoming_class_sessions(user_id):
    """Get upcoming class sessions for a student."""
    conn = get_db_connection()
    
    try:
        sessions = conn.execute('''
            SELECT 
                cs.id as class_id,
                cs.class_name,
                cs.class_date,
                cs.time,
                cs.instructor,
                cs.duration
            FROM class_schedule cs
            JOIN class_students cst ON cs.id = cst.class_id
            WHERE cst.user_id = ?
            ORDER BY cs.class_date, cs.time
        ''', (user_id,)).fetchall()
        
        return [dict(session) for session in sessions]
    finally:
        conn.close()

def init_db():
    """Initialize the database with all required tables."""
    try:
        conn = get_db_connection()
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
                is_approved BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Class schedule table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS class_schedule (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                class_name TEXT NOT NULL,
                class_date DATE NOT NULL,
                time TEXT NOT NULL,
                instructor TEXT NOT NULL,
                duration TEXT NOT NULL,
                admin_notes TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create class_students junction table for many-to-many relationship
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS class_students (
                class_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (class_id) REFERENCES class_schedule (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                UNIQUE(class_id, user_id),
                PRIMARY KEY (class_id, user_id)
            )
        ''')
        
        # Attendance table 
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                class_id INTEGER NOT NULL,
                class_date DATE NOT NULL,
                class_name TEXT NOT NULL,
                time TEXT NOT NULL,
                can_attend INTEGER NOT NULL,
                reason TEXT,
                alternative_date DATE,
                submitted_by TEXT DEFAULT 'parent',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (class_id) REFERENCES class_schedule (id) ON DELETE CASCADE,
                UNIQUE(user_id, class_id, class_date)
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

        
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_class_students_class_id ON class_students(class_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_class_students_user_id ON class_students(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attendance_user_class ON attendance(user_id, class_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance(class_date)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_approved ON users(is_approved)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_class_schedule_date ON class_schedule(class_date)')
        
        conn.commit()
        conn.close()
        
        print("✓ Database tables created successfully")
        
        # Create admin user (after ensuring database connection is closed)
        create_admin_user()
        
    except Exception as e:
        print(f"✗ Error initializing database: {e}")
        import traceback
        traceback.print_exc()
# Add this function after your existing database initialization functions
def create_alternative_dates_table():
    """Create table for multiple alternative date proposals."""
    try:
        conn = get_db_connection()
        
        # Create table for multiple alternative dates
        conn.execute('''
            CREATE TABLE IF NOT EXISTS alternative_date_proposals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attendance_id INTEGER NOT NULL,
                alternative_date DATE NOT NULL,
                preferred_session TEXT,
                status INTEGER DEFAULT NULL,
                rejection_reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (attendance_id) REFERENCES attendance (id) ON DELETE CASCADE
            )
        ''')
        
        # Check if columns exist and add if missing
        columns = conn.execute("PRAGMA table_info(alternative_date_proposals)").fetchall()
        column_names = [col[1] for col in columns]
        
        if 'preferred_session' not in column_names:
            conn.execute('ALTER TABLE alternative_date_proposals ADD COLUMN preferred_session TEXT')
        
        if 'status' not in column_names:
            conn.execute('ALTER TABLE alternative_date_proposals ADD COLUMN status INTEGER DEFAULT NULL')
        
        if 'rejection_reason' not in column_names:
            conn.execute('ALTER TABLE alternative_date_proposals ADD COLUMN rejection_reason TEXT')
        
        conn.commit()
        conn.close()
        print("✅ Created/updated alternative_date_proposals table")
    except Exception as e:
        print(f"Error creating alternative_date_proposals table: {e}")

# Call this function in your initialization
create_alternative_dates_table()
def create_attendance_table_if_needed():
    """Create attendance table if it doesn't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if attendance table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='attendance'")
        table_exists = cursor.fetchone()
        
        if not table_exists:
            print("Creating attendance table...")
            cursor.execute('''
                CREATE TABLE attendance (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    class_id INTEGER NOT NULL,
                    class_date DATE NOT NULL,
                    class_name TEXT NOT NULL,
                    time TEXT NOT NULL,
                    can_attend INTEGER NOT NULL,
                    reason TEXT,
                    alternative_date DATE,
                    submitted_by TEXT DEFAULT 'parent',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    FOREIGN KEY (class_id) REFERENCES class_schedule (id) ON DELETE CASCADE,
                    UNIQUE(user_id, class_id, class_date)
                )
            ''')
            
            # Check if old attendance_calendar table exists and migrate data
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='attendance_calendar'")
            old_table_exists = cursor.fetchone()
            
            if old_table_exists:
                print("Migrating data from attendance_calendar to attendance table...")
                cursor.execute('''
                    INSERT OR IGNORE INTO attendance 
                    (user_id, class_id, class_date, class_name, time, can_attend, reason, submitted_by, created_at)
                    SELECT 
                        user_id, 
                        class_id, 
                        class_date, 
                        (SELECT class_name FROM class_schedule WHERE id = ac.class_id) as class_name,
                        class_time as time,
                        CASE WHEN can_attend = 1 THEN 1 ELSE 0 END as can_attend,
                        reason,
                        submitted_by,
                        submitted_at
                    FROM attendance_calendar ac
                ''')
                print("Data migration completed!")
            
            conn.commit()
            print("Attendance table created successfully!")
    except Exception as e:
        print(f"Error creating attendance table: {e}")
        conn.rollback()
    finally:
        conn.close()

def ensure_attendance_table_exists():
    conn = sqlite3.connect('multimaker.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            class_id INTEGER NOT NULL,
            class_date TEXT NOT NULL,
            class_name TEXT,
            time TEXT,
            can_attend INTEGER DEFAULT NULL,
            reason TEXT,
            alternative_date TEXT,
            submitted_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            admin_approval INTEGER,  -- NULL = not applicable, 1 = approved, 0 = rejected, 2 = pending
            rejection_reason TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(class_id) REFERENCES class_schedule(id)
        )
    ''')
    
    # Add admin_approval column if it doesn't exist
    cursor.execute("PRAGMA table_info(attendance)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'admin_approval' not in columns:
        cursor.execute('ALTER TABLE attendance ADD COLUMN admin_approval INTEGER')
        print("Added admin_approval column to attendance table")
    
    if 'rejection_reason' not in columns:
        cursor.execute('ALTER TABLE attendance ADD COLUMN rejection_reason TEXT')
        print("Added rejection_reason column to attendance table")
    
    conn.commit()
    conn.close()

# Call this function in your app initialization
ensure_attendance_table_exists()

def create_admin_user():
    """Ensure admin user exists."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if admin exists
        cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
        admin_exists = cursor.fetchone()
        
        if not admin_exists:
            hashed_password = generate_password_hash('admin123')
            cursor.execute('''
                INSERT INTO users (username, email, password, full_name, role, is_approved)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', ('admin', 'multimakerspace@gmail.com', hashed_password, 'Administrator', 'admin', 1))
            conn.commit()
            print("✓ Admin user created successfully!")
        else:
            print("✓ Admin user already exists")
            
        conn.close()
        
    except Exception as e:
        print(f"✗ Error creating admin user: {e}")
        import traceback
        traceback.print_exc()

def execute_query(query, params=()):
    """Execute a SQL query."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(query, params)
        conn.commit()
        return cursor.lastrowid
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def get_user_by_username(username):
    """Get user by username."""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    """Get user by ID."""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return user

def get_all_students():
    """Get all approved student users."""
    conn = get_db_connection()
    students = conn.execute('''
        SELECT id, username, full_name, email, created_at 
        FROM users 
        WHERE role = 'student' AND is_approved = 1
        ORDER BY full_name
    ''').fetchall()
    conn.close()
    return [dict(student) for student in students]

def get_pending_users():
    """Get all users pending approval."""
    conn = get_db_connection()
    users = conn.execute('''
        SELECT id, username, full_name, email, created_at 
        FROM users 
        WHERE is_approved = 0
        ORDER BY created_at
    ''').fetchall()
    conn.close()
    return [dict(user) for user in users]

def get_all_classes():
    """Get all classes."""
    conn = get_db_connection()
    classes = conn.execute('SELECT * FROM class_schedule ORDER BY class_date, time').fetchall()
    conn.close()
    return [dict(cls) for cls in classes]

def get_class_with_students(class_id):
    """Get a class with its enrolled students."""
    conn = get_db_connection()
    
    try:
        # Get class details
        class_info = conn.execute(
            'SELECT * FROM class_schedule WHERE id = ?',
            (class_id,)
        ).fetchone()
        
        if not class_info:
            return None
        
        # Get enrolled students
        students = conn.execute('''
            SELECT u.id, u.username, u.full_name, u.email, cs.enrolled_at
            FROM users u
            JOIN class_students cs ON u.id = cs.user_id
            WHERE cs.class_id = ?
            ORDER BY u.full_name
        ''', (class_id,)).fetchall()
        
        # Convert to dict and add students
        class_dict = dict(class_info)
        class_dict['students'] = [dict(student) for student in students]
        
        return class_dict
    finally:
        conn.close()

def assign_student_to_class(class_id, user_id):
    """Assign a student to a class."""
    try:
        execute_query(
            'INSERT OR IGNORE INTO class_students (class_id, user_id) VALUES (?, ?)',
            (class_id, user_id)
        )
        return True
    except Exception as e:
        print(f"Error assigning student to class: {e}")
        return False

def remove_student_from_class(class_id, user_id):
    """Remove a student from a class."""
    try:
        # First, remove any attendance records
        execute_query(
            'DELETE FROM attendance WHERE class_id = ? AND user_id = ?',
            (class_id, user_id)
        )
        
        # Then remove from class_students
        execute_query(
            'DELETE FROM class_students WHERE class_id = ? AND user_id = ?',
            (class_id, user_id)
        )
        
        return True
    except Exception as e:
        print(f"Error removing student from class: {e}")
        return False

def get_classes_for_student(user_id):
    """Get all classes a student is enrolled in."""
    conn = get_db_connection()
    
    try:
        classes = conn.execute('''
            SELECT cs.*, cls.enrolled_at
            FROM class_schedule cs
            JOIN class_students cls ON cs.id = cls.class_id
            WHERE cls.user_id = ?
            ORDER BY cs.class_date, cs.time
        ''', (user_id,)).fetchall()
        
        return [dict(cls) for cls in classes]
    finally:
        conn.close()

def get_student_attendance(user_id, class_id=None):
    """Get attendance records for a student."""
    conn = get_db_connection()
    
    try:
        if class_id:
            # Get attendance for specific class
            attendance = conn.execute('''
                SELECT a.*, cs.class_name, cs.class_date, cs.time, cs.instructor
                FROM attendance a
                JOIN class_schedule cs ON a.class_id = cs.id
                WHERE a.user_id = ? AND a.class_id = ?
                ORDER BY a.class_date DESC
            ''', (user_id, class_id)).fetchall()
        else:
            # Get all attendance records
            attendance = conn.execute('''
                SELECT a.*, cs.class_name, cs.class_date, cs.time, cs.instructor
                FROM attendance a
                JOIN class_schedule cs ON a.class_id = cs.id
                WHERE a.user_id = ?
                ORDER BY a.class_date DESC
            ''', (user_id,)).fetchall()
        
        return [dict(record) for record in attendance]
    finally:
        conn.close()

def add_class(class_name, class_date, time, instructor, duration):
    """Add a new class."""
    return execute_query(
        'INSERT INTO class_schedule (class_name, class_date, time, instructor, duration) VALUES (?, ?, ?, ?, ?)',
        (class_name, class_date, time, instructor, duration)
    )

def delete_class(class_id):
    """Delete a class and all related records."""
    try:
        execute_query('DELETE FROM class_schedule WHERE id = ?', (class_id,))
        return True
    except Exception as e:
        print(f"Error deleting class: {e}")
        return False

def check_user_credentials(username, password):
    """Check if username and password are correct."""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if user and check_password_hash(user['password'], password):
        return user
    return None

def update_user_approval(user_id, is_approved):
    """Update user approval status."""
    try:
        execute_query(
            'UPDATE users SET is_approved = ? WHERE id = ?',
            (is_approved, user_id)
        )
        return True
    except Exception as e:
        print(f"Error updating user approval: {e}")
        return False
def update_payments_table():
    """Update payments table with classes_remaining column."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if classes_remaining column exists
        columns = conn.execute("PRAGMA table_info(payments)").fetchall()
        column_names = [col[1] for col in columns]
        
        if 'classes_remaining' not in column_names:
            print("Adding classes_remaining column to payments table...")
            cursor.execute('ALTER TABLE payments ADD COLUMN classes_remaining INTEGER DEFAULT 0')
            conn.commit()
            print("✅ classes_remaining column added!")
            
            # Update existing records to set classes_remaining = number_of_classes
            cursor.execute('''
                UPDATE payments SET classes_remaining = number_of_classes 
                WHERE classes_remaining IS NULL OR classes_remaining = 0
            ''')
            conn.commit()
            print("✅ Existing payment records updated with classes_remaining!")
        
        # Check if receipt_number column exists
        if 'receipt_number' not in column_names:
            print("Adding receipt_number column to payments table...")
            cursor.execute('ALTER TABLE payments ADD COLUMN receipt_number TEXT UNIQUE')
            conn.commit()
            print("✅ receipt_number column added!")
            
    except Exception as e:
        print(f"Error updating payments table: {e}")
    finally:
        conn.close()

# Call this function after create_payment_table()
update_payments_table()

# Updated add_payment function with classes_remaining and receipt_number
def add_payment(user_id, class_type, number_of_classes, payment_date, 
                payment_month, payment_year, payment_method, amount_paid, 
                recorded_by, notes='', class_date=''):
    """Add a new payment record."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # Generate a simple receipt number
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        receipt_number = f"RCPT-{timestamp}-{user_id}"
        
        # Check which columns exist
        columns = conn.execute("PRAGMA table_info(payments)").fetchall()
        column_names = [col[1] for col in columns]
        
        has_classes_remaining = 'classes_remaining' in column_names
        has_receipt_number = 'receipt_number' in column_names
        has_class_date = 'class_date' in column_names
        
        # Build dynamic insert
        insert_cols = ['user_id', 'class_type', 'number_of_classes', 'payment_date',
                       'payment_month', 'payment_year', 'payment_method', 'amount_paid',
                       'notes', 'recorded_by']
        insert_vals = [user_id, class_type, number_of_classes, payment_date,
                       payment_month, payment_year, payment_method, amount_paid,
                       notes, recorded_by]
        
        if has_classes_remaining:
            insert_cols.append('classes_remaining')
            insert_vals.append(number_of_classes)
        
        if has_receipt_number:
            insert_cols.append('receipt_number')
            insert_vals.append(receipt_number)
        
        if has_class_date:
            insert_cols.append('class_date')
            insert_vals.append(class_date if class_date else None)
        
        placeholders = ', '.join(['?'] * len(insert_cols))
        col_names = ', '.join(insert_cols)
        
        cursor.execute(f'''
            INSERT INTO payments ({col_names})
            VALUES ({placeholders})
        ''', insert_vals)
        
        payment_id = cursor.lastrowid
        conn.commit()
        return payment_id
    except Exception as e:
        conn.rollback()
        print(f"Error in add_payment: {e}")
        import traceback
        traceback.print_exc()
        raise e
    finally:
        conn.close()

def update_payment(payment_id, user_id, class_type, number_of_classes, payment_date,
                   payment_month, payment_year, payment_method, amount_paid,
                   notes='', class_date=''):
    """Update an existing payment record."""
    conn = get_db_connection()
    try:
        # Check which columns exist
        columns = conn.execute("PRAGMA table_info(payments)").fetchall()
        column_names = [col[1] for col in columns]
        
        # Build dynamic update
        update_cols = [
            'user_id = ?', 'class_type = ?', 'number_of_classes = ?',
            'payment_date = ?', 'payment_month = ?', 'payment_year = ?',
            'payment_method = ?', 'amount_paid = ?', 'notes = ?'
        ]
        update_vals = [
            user_id, class_type, number_of_classes,
            payment_date, payment_month, payment_year,
            payment_method, amount_paid, notes
        ]
        
        if 'classes_remaining' in column_names:
            update_cols.append('classes_remaining = ?')
            update_vals.append(number_of_classes)
        
        if 'class_date' in column_names:
            update_cols.append('class_date = ?')
            update_vals.append(class_date if class_date else None)
        
        update_vals.append(payment_id)
        set_clause = ', '.join(update_cols)
        
        conn.execute(f'''
            UPDATE payments SET {set_clause} WHERE id = ?
        ''', update_vals)
        
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        print(f"Error in update_payment: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        conn.close()

def add_classes_remaining_column():
    """Add classes_remaining column to payments table if it doesn't exist."""
    conn = get_db_connection()
    try:
        # Check if column exists
        columns = conn.execute("PRAGMA table_info(payments)").fetchall()
        column_names = [col[1] for col in columns]
        
        if 'classes_remaining' not in column_names:
            print("Adding classes_remaining column to payments table...")
            conn.execute('ALTER TABLE payments ADD COLUMN classes_remaining INTEGER DEFAULT 0')
            conn.commit()
            print("✅ classes_remaining column added!")
            
        if 'receipt_number' not in column_names:
            print("Adding receipt_number column to payments table...")
            conn.execute('ALTER TABLE payments ADD COLUMN receipt_number TEXT')
            conn.commit()
            print("✅ receipt_number column added!")
        
        if 'class_date' not in column_names:
            print("Adding class_date column to payments table...")
            conn.execute('ALTER TABLE payments ADD COLUMN class_date DATE')
            conn.commit()
            print("✅ class_date column added!")
            
    except Exception as e:
        print(f"Error updating payments table: {e}")
    finally:
        conn.close()

# Call this function after create_payment_table()
add_classes_remaining_column()

def get_student_payment_summary(user_id):
    """Get enhanced payment summary for a student with dynamic classes_remaining."""
    conn = get_db_connection()
    try:
        from datetime import date
        today = date.today().isoformat()
        
        summary = conn.execute('''
            SELECT 
                COUNT(*) as total_payments,
                COALESCE(SUM(number_of_classes), 0) as total_classes_purchased,
                COALESCE(SUM(amount_paid), 0) as total_amount,
                MAX(payment_date) as last_payment_date,
                GROUP_CONCAT(DISTINCT payment_method) as payment_methods
            FROM payments
            WHERE user_id = ?
        ''', (user_id,)).fetchone()
        
        # Count attended classes dynamically (past dates only)
        total_attended = 0
        try:
            attended = conn.execute('''
                SELECT COUNT(*) as total_attended
                FROM attendance
                WHERE user_id = ? AND can_attend = 1 AND class_date <= ?
            ''', (user_id, today)).fetchone()
            
            if attended is not None:
                total_attended = attended['total_attended'] or 0
        except Exception as e:
            print(f"Note: Could not query attendance for user {user_id}: {e}")
            total_attended = 0
        
        result = dict(summary) if summary is not None else {}
        total_purchased = result.get('total_classes_purchased', 0) or 0
        total_remaining = max(0, total_purchased - total_attended)
        
        return {
            'total_payments': result.get('total_payments', 0) or 0,
            'total_classes_purchased': total_purchased,
            'total_classes_remaining': total_remaining,
            'total_amount': result.get('total_amount', 0) or 0,
            'last_payment_date': result.get('last_payment_date', 'Never'),
            'payment_methods': result.get('payment_methods', 'N/A')
        }
    finally:
        conn.close()

def get_recent_payments(limit=10):
    """Get recent payments for admin dashboard."""
    conn = get_db_connection()
    try:
        payments = conn.execute('''
            SELECT 
                p.*,
                u.full_name as student_name,
                u.username,
                adm.full_name as recorded_by_name
            FROM payments p
            JOIN users u ON p.user_id = u.id
            JOIN users adm ON p.recorded_by = adm.id
            ORDER BY p.created_at DESC
            LIMIT ?
        ''', (limit,)).fetchall()
        return [dict(payment) for payment in payments]
    finally:
        conn.close()

def get_user_count():
    """Get total number of users."""
    conn = get_db_connection()
    count = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
    conn.close()
    return count

def get_class_count():
    """Get total number of classes."""
    conn = get_db_connection()
    count = conn.execute('SELECT COUNT(*) as count FROM class_schedule').fetchone()['count']
    conn.close()
    return count
def create_payment_table():
    """Create payment table for payment management."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Create simple payment table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                class_type TEXT NOT NULL,
                number_of_classes INTEGER NOT NULL,
                payment_date DATE NOT NULL,
                payment_month TEXT NOT NULL,
                payment_year INTEGER NOT NULL,
                payment_method TEXT NOT NULL,
                amount_paid DECIMAL(10,2) NOT NULL,
                notes TEXT,
                recorded_by INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (recorded_by) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        print("✅ Payment table created successfully!")
        
    except Exception as e:
        print(f"Error creating payment table: {e}")
        conn.rollback()
    finally:
        conn.close()

def get_all_payments():
    """Get all payment records with student details and dynamic classes_remaining."""
    conn = get_db_connection()
    try:
        from datetime import date
        from collections import defaultdict
        today = date.today().isoformat()
        
        # Check which columns exist
        columns = conn.execute("PRAGMA table_info(payments)").fetchall()
        column_names = [col[1] for col in columns]
        
        # Build query dynamically based on available columns
        select_cols = ['p.id', 'p.user_id', 'p.class_type', 'p.number_of_classes', 
                       'p.payment_date', 'p.payment_month', 'p.payment_year', 
                       'p.payment_method', 'p.amount_paid', 'p.notes', 
                       'p.recorded_by', 'p.created_at',
                       'u.full_name as student_name', 'u.username', 'u.email',
                       'adm.full_name as recorded_by_name']
        
        # Add optional columns if they exist
        if 'classes_remaining' in column_names:
            select_cols.append('p.classes_remaining')
        if 'receipt_number' in column_names:
            select_cols.append('p.receipt_number')
        if 'class_date' in column_names:
            select_cols.append('p.class_date')
        
        select_clause = ', '.join(select_cols)
        
        query = f'''
            SELECT {select_clause}
            FROM payments p
            JOIN users u ON p.user_id = u.id
            JOIN users adm ON p.recorded_by = adm.id
            ORDER BY p.payment_date ASC, p.id ASC
        '''
        
        payments = conn.execute(query).fetchall()
        payments = [dict(payment) for payment in payments]
        
        # Group payments by user_id for FIFO calculation
        user_payments = defaultdict(list)
        for p in payments:
            user_payments[p['user_id']].append(p)
        
        # Get attended class counts per student (past dates only)
        attended_map = {}
        try:
            attended_counts = conn.execute('''
                SELECT user_id, COUNT(*) as total_attended
                FROM attendance
                WHERE can_attend = 1 AND class_date <= ?
                GROUP BY user_id
            ''', (today,)).fetchall()
            
            for row in attended_counts:
                if row is not None and row['user_id'] is not None:
                    attended_map[row['user_id']] = row['total_attended'] or 0
        except Exception as e:
            print(f"Note: Could not query attendance counts: {e}")
            attended_map = {}
        
        # Calculate classes_remaining using FIFO per student
        for uid, user_pays in user_payments.items():
            remaining_to_deduct = attended_map.get(uid, 0)
            # Already sorted ASC by payment_date
            for payment in user_pays:
                purchased = payment.get('number_of_classes', 0) or 0
                if remaining_to_deduct >= purchased:
                    payment['classes_remaining'] = 0
                    remaining_to_deduct -= purchased
                else:
                    payment['classes_remaining'] = purchased - remaining_to_deduct
                    remaining_to_deduct = 0
        
        # Re-sort by payment_date DESC for display
        payments.sort(key=lambda x: (x.get('payment_date', ''), x.get('created_at', '')), reverse=True)
        
        return payments
    except Exception as e:
        print(f"Error in get_all_payments: {e}")
        import traceback
        traceback.print_exc()
        return []
    finally:
        conn.close()
def admin_reset_password(user_id, new_password):
    """Admin resets a user's password and flags them to change it on next login."""
    try:
        conn = get_db_connection()
        hashed_password = generate_password_hash(new_password)
        conn.execute(
            'UPDATE users SET password = ?, must_change_password = 1 WHERE id = ?',
            (hashed_password, user_id)
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error resetting password: {e}")
        return False
def change_user_password(user_id, new_password):
    """Student sets a new password and clears the must_change flag."""
    try:
        conn = get_db_connection()
        hashed = generate_password_hash(new_password)
        conn.execute(
            'UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?',
            (hashed, user_id)
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error changing password: {e}")
        return False
    
def submit_password_reset_request(username_or_email, message=''):
    """Student submits a password reset request."""
    try:
        conn = get_db_connection()
        
        # Check if user exists by username OR email
        user = conn.execute(
            'SELECT id, username, full_name, email FROM users WHERE username = ? OR email = ?',
            (username_or_email, username_or_email)
        ).fetchone()
        
        if not user:
            conn.close()
            return False, "No account found with that username or email."
        
        # Check if there's already a pending request
        existing = conn.execute(
            "SELECT id FROM password_reset_requests WHERE username_or_email = ? AND status = 'pending'",
            (username_or_email,)
        ).fetchone()
        
        if existing:
            conn.close()
            return False, "You already have a pending reset request. Please wait for admin to process it."
        
        conn.execute(
            'INSERT INTO password_reset_requests (username_or_email, message) VALUES (?, ?)',
            (username_or_email, message)
        )
        conn.commit()
        conn.close()
        return True, "Password reset request submitted! Admin will reset your password soon."
    except Exception as e:
        print(f"Error submitting reset request: {e}")
        return False, "Something went wrong. Please try again."


def get_pending_reset_requests():
    """Get all pending password reset requests with user info."""
    conn = get_db_connection()
    requests = conn.execute('''
        SELECT 
            pr.id as request_id,
            pr.username_or_email,
            pr.message,
            pr.created_at,
            u.id as user_id,
            u.username,
            u.full_name,
            u.email
        FROM password_reset_requests pr
        LEFT JOIN users u ON u.username = pr.username_or_email OR u.email = pr.username_or_email
        WHERE pr.status = 'pending'
        ORDER BY pr.created_at DESC
    ''').fetchall()
    conn.close()
    return [dict(r) for r in requests]


def mark_reset_request_handled(request_id):
    """Mark a password reset request as handled."""
    try:
        conn = get_db_connection()
        conn.execute(
            "UPDATE password_reset_requests SET status = 'done', handled_at = CURRENT_TIMESTAMP WHERE id = ?",
            (request_id,)
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error marking request as handled: {e}")
        return False


def dismiss_reset_request(request_id):
    """Dismiss/reject a password reset request."""
    try:
        conn = get_db_connection()
        conn.execute(
            "UPDATE password_reset_requests SET status = 'dismissed', handled_at = CURRENT_TIMESTAMP WHERE id = ?",
            (request_id,)
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error dismissing request: {e}")
        return False
    
def create_password_reset_requests_table():
    """Create password reset requests table."""
    try:
        conn = get_db_connection()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username_or_email TEXT NOT NULL,
                message TEXT,
                status TEXT DEFAULT 'pending',
                handled_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
        print("✅ password_reset_requests table ready")
    except Exception as e:
        print(f"Error creating password_reset_requests table: {e}")

# Call it during initialization
create_password_reset_requests_table()
def add_must_change_password_column():
    """Add must_change_password column to users table if it doesn't exist."""
    try:
        conn = get_db_connection()
        columns = conn.execute("PRAGMA table_info(users)").fetchall()
        column_names = [col[1] for col in columns]
        
        if 'must_change_password' not in column_names:
            print("Adding must_change_password column to users table...")
            conn.execute('ALTER TABLE users ADD COLUMN must_change_password BOOLEAN DEFAULT 0')
            conn.commit()
            print("✅ must_change_password column added!")
        
        conn.close()
    except Exception as e:
        print(f"Error adding must_change_password column: {e}")

# Call during initialization
add_must_change_password_column()
def fix_payments_table():
    """Add missing columns to payments table."""
    conn = get_db_connection()
    try:
        # Check existing columns
        columns = conn.execute("PRAGMA table_info(payments)").fetchall()
        column_names = [col[1] for col in columns]
        
        print(f"Current payments table columns: {column_names}")
        
        # Add missing columns
        if 'classes_remaining' not in column_names:
            print("Adding classes_remaining column...")
            conn.execute('ALTER TABLE payments ADD COLUMN classes_remaining INTEGER DEFAULT 0')
            print("✅ classes_remaining column added")
            
        if 'receipt_number' not in column_names:
            print("Adding receipt_number column...")
            conn.execute('ALTER TABLE payments ADD COLUMN receipt_number TEXT')
            print("✅ receipt_number column added")
        
        conn.commit()
        print("✅ Payments table updated successfully")
        
    except Exception as e:
        print(f"Error fixing payments table: {e}")
    finally:
        conn.close()

# Call this function after create_payment_table()
fix_payments_table()

def get_payments_by_student(user_id):
    """Get payment records for a specific student with dynamically calculated classes_remaining."""
    conn = get_db_connection()
    try:
        payments = conn.execute('''
            SELECT 
                p.*,
                adm.full_name as recorded_by_name
            FROM payments p
            JOIN users adm ON p.recorded_by = adm.id
            WHERE p.user_id = ?
            ORDER BY p.payment_date ASC, p.id ASC
        ''', (user_id,)).fetchall()
        payments = [dict(payment) for payment in payments]
        
        # Calculate classes_remaining dynamically using attendance records
        payments = _calculate_classes_remaining(conn, user_id, payments)
        
        # Re-sort by payment_date DESC for display
        payments.sort(key=lambda x: (x.get('payment_date', ''), x.get('id', 0)), reverse=True)
        
        return payments
    finally:
        conn.close()


def _calculate_classes_remaining(conn, user_id, payments):
    """
    Calculate classes_remaining for each payment dynamically based on attendance.
    Uses FIFO: oldest payment gets deducted first.
    Counts attendance records where the student attended (can_attend = 1) 
    and the class_date has already passed (class_date <= today).
    """
    from datetime import date
    today = date.today().isoformat()
    
    total_attended = 0
    try:
        # Get total attended classes for this student (past dates only, confirmed attendance)
        attended = conn.execute('''
            SELECT COUNT(*) as total_attended
            FROM attendance
            WHERE user_id = ? AND can_attend = 1 AND class_date <= ?
        ''', (user_id, today)).fetchone()
        
        if attended is not None:
            total_attended = attended['total_attended'] or 0
    except Exception as e:
        print(f"Note: Could not query attendance for user {user_id}: {e}")
        total_attended = 0
    
    # Sort payments by date ASC (oldest first) for FIFO deduction
    sorted_payments = sorted(payments, key=lambda x: (x.get('payment_date', ''), x.get('id', 0)))
    
    remaining_to_deduct = total_attended
    
    for payment in sorted_payments:
        purchased = payment.get('number_of_classes', 0) or 0
        if remaining_to_deduct >= purchased:
            payment['classes_remaining'] = 0
            remaining_to_deduct -= purchased
        else:
            payment['classes_remaining'] = purchased - remaining_to_deduct
            remaining_to_deduct = 0
    
    return sorted_payments


def delete_payment(payment_id):
    """Delete a payment record."""
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM payments WHERE id = ?', (payment_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error deleting payment: {e}")
        return False
    finally:
        conn.close()



def migrate_attendance_table():
    """Migrate from attendance_calendar to attendance table if needed."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if attendance_calendar table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='attendance_calendar'")
        old_table_exists = cursor.fetchone()
        
        if old_table_exists:
            print("Migrating data from attendance_calendar to attendance table...")
            
            # Check if attendance table exists, create it if not
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='attendance'")
            new_table_exists = cursor.fetchone()
            
            if not new_table_exists:
                # Create the new attendance table
                cursor.execute('''
                    CREATE TABLE attendance (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        class_id INTEGER NOT NULL,
                        class_date DATE NOT NULL,
                        class_name TEXT NOT NULL,
                        time TEXT NOT NULL,
                        can_attend INTEGER NOT NULL,
                        reason TEXT,
                        alternative_date DATE,
                        submitted_by TEXT DEFAULT 'parent',
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                        FOREIGN KEY (class_id) REFERENCES class_schedule (id) ON DELETE CASCADE,
                        UNIQUE(user_id, class_id, class_date)
                    )
                ''')
            
            # Migrate data from old table to new table
            cursor.execute('''
                INSERT OR IGNORE INTO attendance 
                (user_id, class_id, class_date, class_name, time, can_attend, reason, submitted_by, created_at)
                SELECT 
                    user_id, 
                    class_id, 
                    class_date, 
                    (SELECT class_name FROM class_schedule WHERE id = ac.class_id) as class_name,
                    class_time as time,
                    CASE WHEN can_attend = 1 THEN 1 ELSE 0 END as can_attend,
                    reason,
                    submitted_by,
                    submitted_at
                FROM attendance_calendar ac
            ''')
            
            print("Data migration completed successfully!")
        
        conn.commit()
        
    except Exception as e:
        print(f"Migration error: {e}")
        conn.rollback()
    finally:
        conn.close()
