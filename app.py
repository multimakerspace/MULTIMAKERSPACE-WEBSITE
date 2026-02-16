from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g
from database import init_db, get_db_connection
from database import change_user_password
from database import check_user_credentials
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from database import add_payment as db_add_payment
import inspect
from datetime import datetime
import pytz 
from datetime import datetime, timedelta
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect, validate_csrf
from wtforms import ValidationError
from functools import wraps
from database import (
    submit_password_reset_request,
    get_pending_reset_requests,
    mark_reset_request_handled,
    dismiss_reset_request,
    admin_reset_password  # from the previous feature
)
from database import (
    get_all_students, get_all_classes, get_class_with_students,
    assign_student_to_class, remove_student_from_class,
    get_pending_users, get_classes_for_student, get_student_attendance,
    get_upcoming_class_sessions, add_class, delete_class as delete_class_db,
    get_user_by_username, get_user_by_id, execute_query, create_attendance_table_if_needed
)
from database import (
    create_payment_table, get_all_payments, add_payment as db_add_payment_func, 
    delete_payment as db_delete_payment, update_payment as db_update_payment,
    get_payments_by_student, get_student_payment_summary
)


from database import migrate_attendance_table
# Add this function to your app.py
def add_preferred_session_column():
    """Add missing columns to attendance table if they don't exist."""
    try:
        conn = get_db_connection()
        
        # Check which columns exist
        columns = conn.execute("PRAGMA table_info(attendance)").fetchall()
        column_names = [col[1] for col in columns]
        
        # Add preferred_session column if missing
        if 'preferred_session' not in column_names:
            print("Adding preferred_session column to attendance table...")
            conn.execute('ALTER TABLE attendance ADD COLUMN preferred_session TEXT')
            conn.commit()
            print("✅ preferred_session column added!")
        
        # Add admin_approval column if missing ✅ NEW
        # Add admin_approval column if missing ✅ NEW
        if 'admin_approval' not in column_names:
            print("Adding admin_approval column to attendance table...")
        # CRITICAL: Default to NULL to represent "pending" status
            conn.execute('ALTER TABLE attendance ADD COLUMN admin_approval INTEGER DEFAULT NULL')
            conn.commit()
            print("✅ admin_approval column added with NULL default for pending status!")
        
        # Add rejection_reason column if missing ✅ NEW
        if 'rejection_reason' not in column_names:
            print("Adding rejection_reason column to attendance table...")
            conn.execute('ALTER TABLE attendance ADD COLUMN rejection_reason TEXT')
            conn.commit()
            print("✅ rejection_reason column added!")
        
        # Add additional_remarks column if missing ✅ NEW
        if 'additional_remarks' not in column_names:
            print("Adding additional_remarks column to attendance table...")
            conn.execute('ALTER TABLE attendance ADD COLUMN additional_remarks TEXT')
            conn.commit()
            print("✅ additional_remarks column added!")
        
        conn.close()
    except Exception as e:
        print(f"Error adding columns to attendance table: {e}")

# Call this function in your initialization
init_db()
migrate_attendance_table()
add_preferred_session_column()


app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-this-in-production'
import sqlite3

create_payment_table()






# Custom decorators for authentication
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function
create_payment_table()
@app.route('/change-password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if not new_password or len(new_password) < 4:
        flash('New password must be at least 4 characters.', 'danger')
        return redirect(url_for('student_dashboard'))
    
    if new_password != confirm_password:
        flash('Passwords do not match.', 'danger')
        return redirect(url_for('student_dashboard'))
    
    if change_user_password(session['user_id'], new_password):
        session['must_change_password'] = 0  # Clear the flag in session
        flash('Password changed successfully!', 'success')
    else:
        flash('Failed to change password. Please try again.', 'danger')
    
    return redirect(url_for('student_dashboard'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email', '').strip()
        message = request.form.get('message', '').strip()
        
        if not username_or_email:
            flash('Please enter your username or email.', 'danger')
            return redirect(url_for('forgot_password'))
        
        success, msg = submit_password_reset_request(username_or_email, message)
        flash(msg, 'success' if success else 'danger')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')
@app.route('/admin/handle_reset_request/<int:request_id>', methods=['POST'])
def handle_reset_request(request_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Admin access required.', 'danger')
        return redirect(url_for('login'))
    
    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password')
    
    if not user_id or not new_password or len(new_password) < 4:
        flash('Password must be at least 4 characters.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    if admin_reset_password(int(user_id), new_password):
        mark_reset_request_handled(request_id)
        user = get_user_by_id(int(user_id))
        flash(f'Password reset for {user["full_name"]}! New password: {new_password} — Please inform the student.', 'success')
    else:
        flash('Failed to reset password.', 'danger')
    
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/dismiss_reset_request/<int:request_id>', methods=['POST'])
def dismiss_reset_request_route(request_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Admin access required.', 'danger')
        return redirect(url_for('login'))
    
    dismiss_reset_request(request_id)
    flash('Reset request dismissed.', 'info')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/payments')
@admin_required
def admin_payments():
    """Payment management dashboard."""
    current_user = get_current_user()
    
    # Get filter parameters
    student_filter = request.args.get('student', '')
    month_filter = request.args.get('month', '')
    year_filter = request.args.get('year', '')
    method_filter = request.args.get('method', '')
    
    conn = get_db_connection()
    
    # Get all payments
    payments = get_all_payments()
    
    # Apply filters to payments
    if student_filter:
        payments = [p for p in payments if student_filter.lower() in p['student_name'].lower()]
    if month_filter:
        payments = [p for p in payments if p['payment_month'] == month_filter]
    if year_filter:
        payments = [p for p in payments if str(p['payment_year']) == year_filter]
    if method_filter:
        payments = [p for p in payments if p['payment_method'] == method_filter]
    
    # FIX: Get ALL approved students for dropdown, not just those with payments
    students = conn.execute('''
        SELECT id, full_name, username, email 
        FROM users 
        WHERE role = 'student' AND is_approved = 1
        ORDER BY full_name
    ''').fetchall()
    students_list = [dict(s) for s in students]
    
    # Get available years for filter from payments table
    years = conn.execute('''
        SELECT DISTINCT payment_year 
        FROM payments 
        ORDER BY payment_year DESC
    ''').fetchall()
    years_list = [y['payment_year'] for y in years] if years else []
    
    conn.close()
    
    # Calculate statistics
    total_revenue = sum(p['amount_paid'] for p in payments) if payments else 0
    total_transactions = len(payments)
    total_classes = sum(p['number_of_classes'] for p in payments) if payments else 0
    
    # Months for dropdown
    months = ['January', 'February', 'March', 'April', 'May', 'June',
              'July', 'August', 'September', 'October', 'November', 'December']
    
    # Payment methods
    payment_methods = ['Cash', 'Online Transfer', 'Credit Card', 'Debit Card', 'Cheque', 'Other']
    
    return render_template('admin_payments.html',
                         user=current_user,
                         payments=payments,
                         students=students_list,  # Now contains ALL approved students
                         years=years_list,
                         months=months,
                         payment_methods=payment_methods,
                         total_revenue=total_revenue,
                         total_transactions=total_transactions,
                         total_classes=total_classes,
                         student_filter=student_filter,
                         month_filter=month_filter,
                         year_filter=year_filter,
                         method_filter=method_filter,
                         current_year=datetime.now().year,
                         current_month=datetime.now().strftime('%B'))

@app.route('/admin/payments/add', methods=['POST'])
@admin_required
def add_payment():
    """Add a new payment record."""
    current_user = get_current_user()

    try:
        
        print(f"Function signature: {inspect.signature(db_add_payment)}")
        print(f"Function module: {db_add_payment.__module__}")
        print(f"Function file: {inspect.getfile(db_add_payment)}")
   
        # Get form data
        user_id = request.form.get('user_id')
        class_type = request.form.get('class_type')
        number_of_classes = request.form.get('number_of_classes')
        class_date = request.form.get('class_date', '')
        payment_date = request.form.get('payment_date')
        payment_month = request.form.get('payment_month')
        payment_year = request.form.get('payment_year')
        payment_method = request.form.get('payment_method')
        amount_paid = request.form.get('amount_paid')
        notes = request.form.get('notes', '')
        
        # Validate required fields
        if not all([user_id, class_type, number_of_classes, payment_date, 
                   payment_month, payment_year, payment_method, amount_paid]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('admin_payments'))
        
        # Convert types
        try:
            user_id = int(user_id)
            number_of_classes = int(number_of_classes)
            payment_year = int(payment_year)
            amount_paid = float(amount_paid)
        except ValueError as e:
            flash(f'Invalid data format: {str(e)}', 'danger')
            return redirect(url_for('admin_payments'))
        
        # Add payment record - USING KEYWORD ARGUMENTS for clarity
        payment_id = db_add_payment(
            user_id,                    # position 1
            class_type,                # position 2
            number_of_classes,         # position 3
            payment_date,             # position 4
            payment_month,            # position 5
            payment_year,             # position 6
            payment_method,           # position 7
            amount_paid,             # position 8
            current_user['id'],      # position 9 (recorded_by)
            notes,                   # position 10 (notes)
            class_date               # position 11 (class_date)
        )
        
        flash(f'✅ Payment recorded successfully!', 'success')
        
    except TypeError as e:
        print(f"TypeError adding payment: {e}")
        import traceback
        traceback.print_exc()
        flash(f'❌ Error: Function parameter mismatch - {str(e)}', 'danger')
    except Exception as e:
        print(f"Error adding payment: {e}")
        import traceback
        traceback.print_exc()
        flash(f'❌ Error adding payment: {str(e)}', 'danger')
    
    return redirect(url_for('admin_payments'))

@app.route('/admin/payments/edit/<int:payment_id>', methods=['POST'])
@admin_required
def edit_payment(payment_id):
    """Edit an existing payment record."""
    try:
        # CSRF validation
        csrf_token = request.form.get('csrf_token')
        try:
            validate_csrf(csrf_token)
        except Exception:
            flash('Invalid CSRF token', 'danger')
            return redirect(url_for('admin_payments'))
        
        # Get form data
        user_id = request.form.get('user_id')
        class_type = request.form.get('class_type')
        number_of_classes = request.form.get('number_of_classes')
        class_date = request.form.get('class_date', '')
        payment_date = request.form.get('payment_date')
        payment_month = request.form.get('payment_month')
        payment_year = request.form.get('payment_year')
        payment_method = request.form.get('payment_method')
        amount_paid = request.form.get('amount_paid')
        notes = request.form.get('notes', '')
        
        # Validate required fields
        if not all([user_id, class_type, number_of_classes, payment_date, 
                   payment_month, payment_year, payment_method, amount_paid]):
            flash('All required fields must be filled.', 'danger')
            return redirect(url_for('admin_payments'))
        
        # Convert types
        try:
            user_id = int(user_id)
            number_of_classes = int(number_of_classes)
            payment_year = int(payment_year)
            amount_paid = float(amount_paid)
        except ValueError as e:
            flash(f'Invalid data format: {str(e)}', 'danger')
            return redirect(url_for('admin_payments'))
        
        # Update payment record
        success = db_update_payment(
            payment_id, user_id, class_type, number_of_classes,
            payment_date, payment_month, payment_year, payment_method,
            amount_paid, notes, class_date
        )
        
        if success:
            flash('✅ Payment record updated successfully!', 'success')
        else:
            flash('❌ Error updating payment record.', 'danger')
        
    except Exception as e:
        print(f"Error editing payment: {e}")
        import traceback
        traceback.print_exc()
        flash(f'❌ Error: {str(e)}', 'danger')
    
    return redirect(url_for('admin_payments'))

@app.route('/admin/payments/delete/<int:payment_id>', methods=['POST'])
@admin_required
def delete_payment(payment_id):
    """Delete a payment record."""
    try:
        # CSRF validation
        csrf_token = request.form.get('csrf_token')
        try:
            validate_csrf(csrf_token)
        except Exception:
            flash('Invalid CSRF token', 'danger')
            return redirect(url_for('admin_payments'))
        
        success = db_delete_payment(payment_id)
        
        if success:
            flash('✅ Payment record deleted successfully!', 'success')
        else:
            flash('❌ Error deleting payment record.', 'danger')
            
    except Exception as e:
        print(f"Error deleting payment: {e}")
        flash(f'❌ Error: {str(e)}', 'danger')
    
    return redirect(url_for('admin_payments'))

@app.route('/admin/payments/student/<int:student_id>')
@admin_required
def student_payment_history(student_id):
    """View payment history for a specific student."""
    current_user = get_current_user()
    
    # Get student details
    conn = get_db_connection()
    student = conn.execute(
        'SELECT id, full_name, username, email FROM users WHERE id = ?',
        (student_id,)
    ).fetchone()
    
    if not student:
        flash('Student not found.', 'danger')
        return redirect(url_for('admin_payments'))
    
    # Get payment history
    payments = get_payments_by_student(student_id)
    
    # Get payment summary
    summary = get_student_payment_summary(student_id)
    
    conn.close()
    
    return render_template('student_payment_history.html',
                         user=current_user,
                         student=dict(student),
                         payments=payments,
                         summary=summary)
                         
def fix_alternative_proposals_table():
    """Add missing columns to alternative_proposals table."""
    try:
        conn = get_db_connection()
        
        # Check if table exists
        table_exists = conn.execute('''
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='alternative_proposals'
        ''').fetchone()
        
        if table_exists:
            # Get existing columns
            columns = conn.execute("PRAGMA table_info(alternative_proposals)").fetchall()
            column_names = [col[1] for col in columns]
            
            print("Alternative proposals table columns:", column_names)
            
            # Add missing columns
            if 'rejection_reason' not in column_names:
                print("Adding rejection_reason column to alternative_proposals...")
                conn.execute('ALTER TABLE alternative_proposals ADD COLUMN rejection_reason TEXT')
                print("✅ Added rejection_reason column")
            
            if 'status' not in column_names:
                print("Adding status column to alternative_proposals...")
                conn.execute('ALTER TABLE alternative_proposals ADD COLUMN status TEXT DEFAULT "pending"')
                print("✅ Added status column")
            
            conn.commit()
        else:
            # Create table with all columns
            print("Creating alternative_proposals table with all columns...")
            conn.execute('''
                CREATE TABLE IF NOT EXISTS alternative_proposals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    attendance_id INTEGER NOT NULL,
                    proposed_date DATE NOT NULL,
                    preferred_session TEXT,
                    reason TEXT,
                    additional_remarks TEXT,
                    status TEXT DEFAULT 'pending',
                    rejection_reason TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (attendance_id) REFERENCES attendance (id) ON DELETE CASCADE
                )
            ''')
            conn.commit()
            print("✅ Created alternative_proposals table with all columns")
        
        conn.close()
        print("✅ Alternative proposals table fix completed")
        
    except Exception as e:
        print(f"Error fixing alternative_proposals table: {e}")

# Call this function during app initialization
fix_alternative_proposals_table()
def fix_pending_approvals():
    """
    Fix approval status for existing records.
    Sets admin_approval to NULL for alternative date proposals that should be pending.
    """
    try:
        conn = get_db_connection()
        
        print("\n" + "="*60)
        print("MIGRATION: Fixing pending approval statuses...")
        print("="*60)
        
        # Check current state
        pending_count = conn.execute('''
            SELECT COUNT(*) as count FROM attendance 
            WHERE can_attend = 2 AND admin_approval IS NULL
        ''').fetchone()['count']
        
        approved_count = conn.execute('''
            SELECT COUNT(*) as count FROM attendance 
            WHERE can_attend = 2 AND admin_approval = 1
        ''').fetchone()['count']
        
        rejected_count = conn.execute('''
            SELECT COUNT(*) as count FROM attendance 
            WHERE can_attend = 2 AND admin_approval = 0
        ''').fetchone()['count']
        
        print(f"Current state:")
        print(f"  - Pending: {pending_count}")
        print(f"  - Approved: {approved_count}")
        print(f"  - Rejected: {rejected_count}")
        
        # Set admin_approval to NULL for records that need it
        # (This handles any records that might have been incorrectly marked)
        result = conn.execute('''
            UPDATE attendance 
            SET admin_approval = NULL 
            WHERE can_attend = 2 
                AND admin_approval IS NOT NULL
                AND updated_at IS NULL
        ''')
        
        if result.rowcount > 0:
            print(f"\n✅ Fixed {result.rowcount} records!")
        else:
            print(f"\n✅ No fixes needed - all records are correct!")
        
        conn.commit()
        conn.close()
        
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"ℹ️  Migration note: {e}")
        print("(This is normal if the table structure is correct)")

fix_pending_approvals()
# Helper function to get current user info
def get_current_user():
    """Get current user information from session."""
    if 'user_id' in session:
        conn = get_db_connection()
        try:
            user_data = conn.execute(
                'SELECT * FROM users WHERE id = ?', (session['user_id'],)
            ).fetchone()
            
            if user_data:
                return {
                    'id': user_data['id'],
                    'username': user_data['username'],
                    'full_name': user_data['full_name'],
                    'email': user_data['email'],
                    'role': user_data['role'],
                    'is_admin': user_data['role'] == 'admin'
                }
        except Exception as e:
            print(f"Error getting current user: {e}")
        finally:
            conn.close()
    return None
@app.template_filter('format_date_short')
def format_date_short(date_str):
    """Format date to short format (e.g., Mon, Jan 15)"""
    try:
        from datetime import datetime
        date_obj = datetime.strptime(date_str, '%Y-%m-%d')
        return date_obj.strftime('%a, %b %d')
    except:
        return date_str
@app.context_processor
def utility_processor():
    return {
        'now': datetime.now,
        'current_year': datetime.now().year,
        'current_month': datetime.now().strftime('%B'),
        'current_date': datetime.now().strftime('%Y-%m-%d')
    }

@app.context_processor
def inject_user():
    """Make current_user available in all templates."""
    user = get_current_user()
    return {'user': user, 'current_user': user}  
# Malaysia Timezone Configuration
MALAYSIA_TZ = pytz.timezone('Asia/Kuala_Lumpur')

def convert_to_malaysia_tz(datetime_str):
    """Convert UTC datetime string to Malaysia timezone (UTC+8)."""
    if not datetime_str:
        return None
    
    try:
        # Parse the datetime string as UTC
        if isinstance(datetime_str, str):
            utc_dt = datetime.fromisoformat(datetime_str.replace('Z', '+00:00'))
        else:
            utc_dt = datetime_str
        
        # If naive datetime (no timezone info), assume it's UTC
        if utc_dt.tzinfo is None:
            utc_dt = pytz.utc.localize(utc_dt)
        
        # Convert to Malaysia timezone
        malaysia_dt = utc_dt.astimezone(MALAYSIA_TZ)
        return malaysia_dt
    except Exception as e:
        print(f"Error converting timezone: {e}")
        return datetime_str

def format_malaysia_time(datetime_str, format_str="%Y-%m-%d %H:%M:%S"):
    """Format datetime string to Malaysia timezone with custom format."""
    try:
        malaysia_dt = convert_to_malaysia_tz(datetime_str)
        if malaysia_dt:
            return malaysia_dt.strftime(format_str)
        return datetime_str
    except Exception as e:
        print(f"Error formatting time: {e}")
        return datetime_str
# Add this function to app.py to create the alternative_proposals table

def create_alternative_proposals_table():
    """Create a separate table for multiple alternative date proposals."""
    try:
        conn = get_db_connection()
        
        # Create table for multiple alternative date proposals
        conn.execute('''
            CREATE TABLE IF NOT EXISTS alternative_proposals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attendance_id INTEGER NOT NULL,
                proposed_date DATE NOT NULL,
                preferred_session TEXT,
                reason TEXT,
                additional_remarks TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (attendance_id) REFERENCES attendance (id) ON DELETE CASCADE
            )
        ''')
        conn.commit()
        
        # Check if we need to migrate existing data
        existing_records = conn.execute('''
            SELECT id, alternative_date, preferred_session, reason, additional_remarks 
            FROM attendance 
            WHERE can_attend = 2 AND alternative_date IS NOT NULL
        ''').fetchall()
        
        migrated_count = 0
        for record in existing_records:
            # Check if already migrated
            exists = conn.execute('''
                SELECT id FROM alternative_proposals 
                WHERE attendance_id = ? AND proposed_date = ?
            ''', (record['id'], record['alternative_date'])).fetchone()
            
            if not exists and record['alternative_date']:
                conn.execute('''
                    INSERT INTO alternative_proposals 
                    (attendance_id, proposed_date, preferred_session, reason, additional_remarks, status)
                    VALUES (?, ?, ?, ?, ?, 'pending')
                ''', (record['id'], record['alternative_date'], 
                      record['preferred_session'], record['reason'], 
                      record['additional_remarks']))
                migrated_count += 1
        
        if migrated_count > 0:
            conn.commit()
            print(f"✅ Migrated {migrated_count} existing alternative date proposals")
        
        conn.close()
        print("✅ Alternative proposals table ready")
        
    except Exception as e:
        print(f"Error creating alternative proposals table: {e}")

# Call this during app initialization
create_alternative_proposals_table()

# Add Jinja filter for Malaysia timezone formatting
@app.template_filter('malaysia_time')
def malaysia_time_filter(datetime_str):
    """Jinja filter to format datetime in Malaysia timezone (HH:MM format)."""
    return format_malaysia_time(datetime_str, "%Y-%m-%d %H:%M")

@app.template_filter('malaysia_time_full')
def malaysia_time_full_filter(datetime_str):
    """Jinja filter to format datetime in Malaysia timezone (full format)."""
    return format_malaysia_time(datetime_str, "%Y-%m-%d %H:%M:%S")

# Enable CSRF protection globally
csrf = CSRFProtect(app)

# Set CSRF time limit (default is 3600s = 1 hour, set to None for no expiry tied to session)
app.config['WTF_CSRF_TIME_LIMIT'] = None  # Token valid for entire session lifetime

# Media configuration
UPLOAD_FOLDER = 'static/media'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Initialize database
init_db()

@app.route('/debug-auth')
def debug_auth():
    current_user = get_current_user()
    return {
        'is_authenticated': current_user is not None,
        'user_id': current_user['id'] if current_user else None,
        'username': current_user['username'] if current_user else None,
        'session': dict(session)
    }

# CSRF Error Handler
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('Security token invalid or expired. Please refresh the page and try again.', 'error')
    return redirect(request.referrer or url_for('index'))

# Custom error handlers
@app.errorhandler(403)
def forbidden_error(e):
    flash('Access forbidden. Please login with appropriate permissions.', 'error')
    return redirect(url_for('login'))

@app.errorhandler(404)
def not_found_error(e):
    flash('Page not found.', 'error')
    return redirect(url_for('index'))

@app.errorhandler(500)
def internal_error(e):
    flash('An internal error occurred. Please try again later.', 'error')
    return redirect(url_for('index'))

@app.route('/')
def index():
    return render_template('index.html')




# --- API: Get Services ---
@app.route('/api/services')
def api_services():
    """Return services data as JSON for AJAX loading."""
    services = [
        {
            'title': 'STEM CLASS',
            'icon': 'fas fa-robot fa-2x',
            'items': ['3D PRINTING', 'MICROBIT CLASS'],
            'color': '#ea580c',
            'color_end': '#f97316',
            'bg_color': 'rgba(234,88,12,0.1)',
            'modal_id': 'stemModal'
        },
        {
            'title': 'TRAINING',
            'icon': 'fas fa-gem fa-2x',
            'items': ['LASER ENGRAVING'],
            'color': '#f97316',
            'color_end': '#fb923c',
            'bg_color': 'rgba(249,115,22,0.1)',
            'modal_id': 'trainingModal'
        },
        {
            'title': 'CUSTOMIZED PROJECT',
            'icon': 'fas fa-tools fa-2x',
            'items': ['EVENT SHOWCASE', 'UPCYCLE', 'PROJECT CONSULTATION'],
            'color': '#c2410c',
            'color_end': '#ea580c',
            'bg_color': 'rgba(194,65,12,0.1)',
            'modal_id': 'projectModal'
        }
    ]
    return jsonify({'services': services})


# --- API: Get Collaborations ---
@app.route('/api/collaborations')
def api_collaborations():
    """Return collaboration partners data as JSON."""
    collaborations = [
        {
            'name': 'NADI',
            'description': 'Teluk Air Tawar',
            'logo': url_for('static', filename='images/NADI.jpeg')
        },
        {
            'name': 'Yayasan Restu',
            'description': 'Strategic Partner',
            'logo': url_for('static', filename='images/yayasan restu.png')
        },
        {
            'name': 'Cytron',
            'description': 'Official Training Partner',
            'logo': url_for('static', filename='images/cytron.png')
        }
    ]
    return jsonify({'collaborations': collaborations})


# --- API: Homepage Stats ---
@app.route('/api/homepage-stats')
def api_homepage_stats():
    """Return live homepage statistics from the database."""
    try:
        conn = get_db_connection()
        student_count = conn.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'student' AND is_approved = 1"
        ).fetchone()[0]
        class_count = conn.execute(
            "SELECT COUNT(*) FROM class_schedule"
        ).fetchone()[0]
        conn.close()
        
        return jsonify({'stats': {
            'students_trained': max(student_count, 150),
            'services': 3,
            'partners': 3,
            'years': 5
        }})
    except Exception as e:
        print(f"Error fetching homepage stats: {e}")
        return jsonify({'stats': {
            'students_trained': 150, 'services': 3, 'partners': 3, 'years': 5
        }})


# --- API: Check Username Availability ---
@app.route('/api/check-username')
def api_check_username():
    """Check if a username is available for registration."""
    username = request.args.get('username', '').strip()
    
    if not username or len(username) < 3:
        return jsonify({'available': False, 'error': 'Username too short'})
    
    try:
        conn = get_db_connection()
        existing = conn.execute(
            'SELECT id FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        return jsonify({'available': existing is None})
    except Exception as e:
        print(f"Error checking username: {e}")
        return jsonify({'available': True})
    
@app.route('/stem-q')
def stem_q():
    return render_template('stem_q.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

# Simple form for testing
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = check_user_credentials(username, password)
        
        if user:
            if not user['is_approved']:
                flash('Your account is pending approval.', 'warning')
                return redirect(url_for('login'))
            
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']
            # ADD THIS LINE ▼
            session['must_change_password'] = user['must_change_password'] if 'must_change_password' in user.keys() else 0
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@csrf.exempt
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        full_name = request.form['full_name']
        
        conn = get_db_connection()
        try:
            hashed_password = generate_password_hash(password)
            # New users are not approved by default
            conn.execute(
                'INSERT INTO users (username, email, password, full_name, role, is_approved) VALUES (?, ?, ?, ?, ?, ?)',
                (username, email, hashed_password, full_name, 'student', 0)
            )
            conn.commit()
            flash('Registration successful! Please wait for admin approval before logging in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists')
        finally:
            conn.close()
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def student_dashboard():
    current_user = get_current_user()  # Get current user info
    
    conn = get_db_connection()
    
    # Get class schedule
    classes = conn.execute('''
        SELECT cs.* 
        FROM class_schedule cs
        JOIN class_students cst ON cs.id = cst.class_id
        WHERE cst.user_id = ?
        ORDER BY cs.class_date, cs.time
    ''', (current_user['id'],)).fetchall()
    
    # Get achievements
    achievements = conn.execute(
        'SELECT * FROM student_achievements WHERE user_id = ? ORDER BY date_achieved DESC',
        (current_user['id'],)
    ).fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', 
                         classes=classes, 
                         achievements=achievements,
                         user=current_user)  # Pass user to template
@app.route('/update_attendance', methods=['POST'])
@login_required
def update_attendance():
    current_user = get_current_user()
    
    # Check if user is None
    if not current_user:
        flash('Please log in to update attendance.', 'warning')
        return redirect(url_for('login'))
    
    try:
        print("\n=== UPDATE ATTENDANCE REQUEST ===")
        print(f"User: {current_user['id']} - {current_user['username']}")
        
        # Get form data with proper defaults
        class_id = request.form.get('class_id')
        class_date = request.form.get('class_date')
        can_attend = request.form.get('can_attend')
        reason = request.form.get('reason', '')
        alternative_date = request.form.get('alternative_date', None)
        submitted_by = request.form.get('submitted_by', 'parent')
        
        print(f"Form data: class_id={class_id}, class_date={class_date}, can_attend={can_attend}")
        print(f"alternative_date={alternative_date}, reason={reason}")
        
        # Validate inputs
        if not class_id or not class_date or can_attend is None:
            error_msg = f'Missing required fields: class_id={class_id}, class_date={class_date}, can_attend={can_attend}'
            print(f"Validation error: {error_msg}")
            flash('Missing required fields', 'danger')
            return redirect(url_for('student_calendar'))
        
        # Convert can_attend to integer
        try:
            can_attend = int(can_attend)
        except ValueError:
            error_msg = f'Invalid attendance value: {can_attend}'
            print(f"Validation error: {error_msg}")
            flash('Invalid attendance value', 'danger')
            return redirect(url_for('student_calendar'))
        
        # Connect to database
        conn = get_db_connection()
        
        # Check if class exists
        class_info = conn.execute('''
            SELECT class_name, time, instructor 
            FROM class_schedule 
            WHERE id = ?
        ''', (class_id,)).fetchone()
        
        if not class_info:
            error_msg = f'Class not found with ID: {class_id}'
            print(f"Validation error: {error_msg}")
            conn.close()
            flash('Class not found', 'danger')
            return redirect(url_for('student_calendar'))
        
        print(f"Class found: {dict(class_info)}")
        
        # Check if alternative date is provided when can_attend is 2
        if can_attend == 2 and not alternative_date:
            error_msg = 'Alternative date is required when proposing an alternative'
            print(f"Validation error: {error_msg}")
            conn.close()
            flash(error_msg, 'danger')
            return redirect(url_for('student_calendar'))
        
        # Check if reason is provided when not attending or proposing alternative
        if can_attend in [0, 2] and not reason.strip():
            error_msg = 'Reason is required when not attending or proposing alternative'
            print(f"Validation error: {error_msg}")
            conn.close()
            flash(error_msg, 'danger')
            return redirect(url_for('student_calendar'))
        
        # Check if an attendance record already exists for this user and class date
        existing_record = conn.execute('''
            SELECT id FROM attendance 
            WHERE user_id = ? AND class_id = ? AND class_date = ?
        ''', (current_user['id'], class_id, class_date)).fetchone()
        
        if existing_record:
            print(f"Updating existing record ID: {existing_record['id']}")
            # Update existing record
            conn.execute('''
                UPDATE attendance 
                SET can_attend = ?, 
                    reason = ?, 
                    alternative_date = ?,
                    submitted_by = ?,
                    updated_at = datetime('now')
                WHERE id = ?
            ''', (can_attend, reason.strip(), alternative_date, submitted_by, existing_record['id']))
            operation = "UPDATE"
        else:
            print("Creating new attendance record")
            # Insert new record
            conn.execute('''
                INSERT INTO attendance 
                (user_id, class_id, class_date, class_name, time, 
                 can_attend, reason, alternative_date, submitted_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ''', (current_user['id'], class_id, class_date, 
                  class_info['class_name'], class_info['time'],
                  can_attend, reason.strip(), alternative_date, submitted_by))
            operation = "INSERT"
        
        # Commit the transaction
        conn.commit()
        
        # Verify the operation
        saved_record = conn.execute('''
            SELECT * FROM attendance 
            WHERE user_id = ? AND class_id = ? AND class_date = ?
        ''', (current_user['id'], class_id, class_date)).fetchone()
        
        if saved_record:
            print(f"Successfully {operation} attendance record: {dict(saved_record)}")
        else:
            print(f"WARNING: Record not found after {operation}")
        
        conn.close()
        
        flash('Attendance updated successfully!', 'success')
        
    except Exception as e:
        print(f"Error updating attendance: {e}")
        import traceback
        traceback.print_exc()
        flash('An error occurred while updating attendance', 'danger')
    
    return redirect(url_for('student_calendar'))
@app.route('/update-class-students/<int:class_id>', methods=['POST'])
@admin_required
def update_class_students(class_id):
    """Update students for a specific class."""
    # Validate CSRF token
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf(csrf_token):
        flash('Invalid CSRF token', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Get the list of student IDs from the form
    student_ids = request.form.getlist('student_ids[]')  # If using checkboxes
    
    # Update the class with the new students
    # Your logic here to update the database
    
    flash('Class students updated successfully', 'success')
    return redirect(url_for('admin_dashboard'))


# Add this to app.py - Enhanced admin dashboard with payment statistics
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    current_user = get_current_user()
    
    conn = get_db_connection()
    
    # Get ALL users
    all_users = conn.execute('''
        SELECT id, username, full_name, email, role, is_approved, created_at 
        FROM users 
        ORDER BY is_approved DESC, created_at DESC
    ''').fetchall()
    
    users_list = []
    for user in all_users:
        user_dict = dict(user)
        if 'is_approved' in user_dict:
            try:
                user_dict['is_approved'] = int(user_dict['is_approved']) if user_dict['is_approved'] is not None else 0
            except (ValueError, TypeError):
                user_dict['is_approved'] = 0
        users_list.append(user_dict)
    
    # Get pending users
    pending_users = [user for user in users_list if user.get('is_approved') == 0]
    
    # Get classes with students
    classes_data = get_all_classes()
    classes_with_students = []
    
    for cls in classes_data:
        cls_dict = dict(cls) if cls else {}
        if 'duration' in cls_dict and cls_dict['duration']:
            try:
                cls_dict['duration'] = float(cls_dict['duration'])
            except (ValueError, TypeError):
                cls_dict['duration'] = 1.0
        else:
            cls_dict['duration'] = 1.0
        
        class_details = get_class_with_students(cls['id']) if cls else None
        if class_details:
            cls_dict['students'] = class_details.get('students', [])
        else:
            cls_dict['students'] = []
            
        classes_with_students.append(cls_dict)
    
    # Get all approved students
    all_students = get_all_students()
    
    # Get achievements
    achievements = conn.execute('''
        SELECT sa.id, sa.user_id, sa.achievement, sa.date_achieved, u.full_name, u.username
        FROM student_achievements sa
        JOIN users u ON sa.user_id = u.id
        ORDER BY sa.date_achieved DESC
    ''').fetchall()
    achievements_list = [dict(achievement) for achievement in achievements]
    
    # ===== PAYMENT STATISTICS FOR DASHBOARD =====
    # Get recent payments (last 5)
    recent_payments = conn.execute('''
        SELECT 
            p.*,
            u.full_name as student_name,
            u.username,
            adm.full_name as recorded_by_name
        FROM payments p
        JOIN users u ON p.user_id = u.id
        JOIN users adm ON p.recorded_by = adm.id
        ORDER BY p.created_at DESC
        LIMIT 5
    ''').fetchall()
    recent_payments_list = [dict(payment) for payment in recent_payments]
    
    # Get total revenue
    total_revenue_result = conn.execute('''
        SELECT SUM(amount_paid) as total FROM payments
    ''').fetchone()
    total_revenue = total_revenue_result['total'] or 0 if total_revenue_result else 0
    
    # Get total payments count
    total_payments_result = conn.execute('''
        SELECT COUNT(*) as count FROM payments
    ''').fetchone()
    total_payments = total_payments_result['count'] or 0 if total_payments_result else 0
    
    # Get total classes sold
    total_classes_result = conn.execute('''
        SELECT SUM(number_of_classes) as total FROM payments
    ''').fetchone()
    total_classes_sold = total_classes_result['total'] or 0 if total_classes_result else 0
    
    # Get this month's revenue
    current_month = datetime.now().strftime('%B')
    current_year = datetime.now().year
    monthly_revenue_result = conn.execute('''
        SELECT SUM(amount_paid) as total 
        FROM payments 
        WHERE payment_month = ? AND payment_year = ?
    ''', (current_month, current_year)).fetchone()
    monthly_revenue = monthly_revenue_result['total'] or 0 if monthly_revenue_result else 0
    
    # Get top paying students
    top_students = conn.execute('''
        SELECT 
            u.id,
            u.full_name,
            u.username,
            SUM(p.amount_paid) as total_paid,
            COUNT(p.id) as payment_count,
            SUM(p.number_of_classes) as total_classes
        FROM payments p
        JOIN users u ON p.user_id = u.id
        GROUP BY u.id
        ORDER BY total_paid DESC
        LIMIT 3
    ''').fetchall()
    top_students_list = [dict(student) for student in top_students]
    
    conn.close()
    reset_requests = get_pending_reset_requests() 
    return render_template('admin_dashboard.html',
                         user=current_user,
                         users=users_list,
                         pending_users=pending_users,
                         classes=classes_with_students,
                         all_students=all_students,
                         achievements=achievements_list,
                         # Payment data for dashboard
                         recent_payments=recent_payments_list,
                         total_revenue=total_revenue,
                         total_payments=total_payments,
                         total_classes_sold=total_classes_sold,
                         monthly_revenue=monthly_revenue,
                         top_students=top_students_list,
                         current_month=current_month,
                         current_year=current_year,reset_requests=reset_requests)

# Add student payment view route
@app.route('/student/payments')
@login_required
def student_payments():
    """Student view their own payment history."""
    current_user = get_current_user()
    
    # Get student's payment history
    payments = get_payments_by_student(current_user['id'])
    
    # Get payment summary
    summary = get_student_payment_summary(current_user['id'])
    
    # Get remaining classes
    remaining_classes = summary.get('total_classes_remaining', 0)
    
    return render_template('student_payments.html',
                         user=current_user,
                         payments=payments,
                         summary=summary,
                         remaining_classes=remaining_classes)

@app.route('/assign-students/<int:class_id>', methods=['POST'])
@admin_required
def assign_students_to_class(class_id):
    """Assign selected students to a class."""
    current_user = get_current_user()
    
    # Validate CSRF
    form = FlaskForm()
    if not form.validate_on_submit():
        flash('Invalid CSRF token', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    student_ids = request.form.getlist('student_ids')
    added_count = 0
    
    for student_id in student_ids:
        if assign_student_to_class(class_id, student_id):
            added_count += 1
    
    if added_count > 0:
        flash(f'Successfully added {added_count} student(s) to the class', 'success')
    else:
        flash('No students were added', 'info')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/remove-student/<int:class_id>/<int:student_id>', methods=['POST'])
@admin_required
def remove_student_from_class_route(class_id, student_id):  # Note the new name
    """Remove a student from a class."""
    try:
        # Get current user info
        current_user = get_current_user()
        
        if not current_user:
            flash('Please log in to perform this action.', 'warning')
            return redirect(url_for('login'))
        
        # Debug info
        print(f"Attempting to remove student {student_id} from class {class_id}")
        print(f"Current user: {current_user['username']} (role: {current_user['role']})")
        
        # Call the database function (from imports)
        success = remove_student_from_class(class_id, student_id)
        
        if success:
            flash('Student removed from class successfully', 'success')
        else:
            flash('Error removing student from class', 'danger')
        
    except Exception as e:
        print(f"Error removing student from class: {e}")
        import traceback
        traceback.print_exc()
        flash('An error occurred while removing the student.', 'danger')
    
    return redirect(url_for('admin_dashboard'))

# MEDIA ROUTES
@app.route('/media')
def media_gallery():
    category = request.args.get('category', 'all')
    
    conn = get_db_connection()
    
    if category == 'all':
        media = conn.execute('''
            SELECT mg.*, u.username 
            FROM media_gallery mg 
            JOIN users u ON mg.uploaded_by = u.id 
            WHERE mg.is_active = 1 
            ORDER BY mg.uploaded_at DESC
        ''').fetchall()
    else:
        media = conn.execute('''
            SELECT mg.*, u.username 
            FROM media_gallery mg 
            JOIN users u ON mg.uploaded_by = u.id 
            WHERE mg.category = ? AND mg.is_active = 1 
            ORDER BY mg.uploaded_at DESC
        ''', (category,)).fetchall()
    
    # Get distinct categories for filter
    categories = conn.execute('''
        SELECT DISTINCT category FROM media_gallery WHERE is_active = 1 ORDER BY category
    ''').fetchall()
    
    conn.close()
    
    return render_template('media.html', 
                         media=media, 
                         categories=categories, 
                         current_category=category)

@app.route('/admin/media')
@admin_required
def admin_media():
    category = request.args.get('category', 'all')
    conn = get_db_connection()
    
    if category == 'all':
        media = conn.execute('''
            SELECT mg.*, u.username 
            FROM media_gallery mg 
            JOIN users u ON mg.uploaded_by = u.id 
            ORDER BY mg.uploaded_at DESC
        ''').fetchall()
    else:
        media = conn.execute('''
            SELECT mg.*, u.username 
            FROM media_gallery mg 
            JOIN users u ON mg.uploaded_by = u.id 
            WHERE mg.category = ? 
            ORDER BY mg.uploaded_at DESC
        ''', (category,)).fetchall()
    
    categories = conn.execute('SELECT DISTINCT category FROM media_gallery ORDER BY category').fetchall()
    conn.close()
    
    return render_template('admin_media.html', 
                         media=media, 
                         categories=categories, 
                         current_category=category)

@app.route('/admin/upload-media', methods=['POST'])
@admin_required
def upload_media():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('admin_media'))
    
    file = request.files['file']
    title = request.form.get('title', '')
    description = request.form.get('description', '')
    category = request.form.get('category', 'general')
    
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('admin_media'))
    
    if file and allowed_file(file.filename):
        # Check file size
        file.seek(0, os.SEEK_END)
        file_length = file.tell()
        file.seek(0)
        
        if file_length > MAX_FILE_SIZE:
            flash('File size too large. Maximum 16MB allowed.')
            return redirect(url_for('admin_media'))
        
        # Secure filename and make unique
        filename = secure_filename(file.filename)
        base, ext = os.path.splitext(filename)
        timestamp = str(int(datetime.now().timestamp()))
        unique_filename = f"{base}_{timestamp}{ext}"
        
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        file.save(file_path)
        
        # Save to database
        current_user = get_current_user()
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO media_gallery (filename, title, description, category, uploaded_by) VALUES (?, ?, ?, ?, ?)',
            (unique_filename, title, description, category, current_user['id'])
        )
        conn.commit()
        conn.close()
        
        flash('Media uploaded successfully!', 'success')
    else:
        flash('Invalid file type. Allowed: PNG, JPG, JPEG, GIF, WEBP')
    
    return redirect(url_for('admin_media'))

@app.route('/admin/delete-media/<int:media_id>', methods=['POST'])
@admin_required
def delete_media(media_id):
    conn = get_db_connection()
    
    # Get filename before deleting
    media = conn.execute('SELECT filename FROM media_gallery WHERE id = ?', (media_id,)).fetchone()
    
    if media:
        # Delete file from filesystem
        file_path = os.path.join(UPLOAD_FOLDER, media['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete from database
        conn.execute('DELETE FROM media_gallery WHERE id = ?', (media_id,))
        conn.commit()
        flash('Media deleted successfully!', 'success')
    else:
        flash('Media not found', 'error')
    
    conn.close()
    return redirect(url_for('admin_media'))
@app.route('/admin/edit-media/<int:media_id>', methods=['POST'])
@admin_required
def edit_media(media_id):
    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    category = request.form.get('category', 'general').strip()

    if not title:
        flash('Title is required.', 'error')
        return redirect(url_for('admin_media'))

    # Validate category
    allowed_categories = ['events', 'classes', 'projects', 'students', 'facilities', 'general']
    if category not in allowed_categories:
        category = 'general'

    conn = get_db_connection()
    media = conn.execute('SELECT id FROM media_gallery WHERE id = ?', (media_id,)).fetchone()

    if media:
        conn.execute(
            'UPDATE media_gallery SET title = ?, description = ?, category = ? WHERE id = ?',
            (title, description, category, media_id)
        )
        conn.commit()
        flash('Media updated successfully!', 'success')
    else:
        flash('Media not found.', 'error')

    conn.close()
    return redirect(url_for('admin_media'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

# Student achievement route (for students to add their own - if needed)
@app.route('/add_achievement', methods=['POST'])
@login_required
def add_achievement():
    achievement = request.form['achievement']
    current_user = get_current_user()
    
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO student_achievements (user_id, achievement, date_achieved) VALUES (?, ?, DATE("now"))',
        (current_user['id'], achievement)
    )
    conn.commit()
    conn.close()
    
    flash('Achievement added successfully!')
    return redirect(url_for('student_dashboard'))

# Admin achievement management routes
@app.route('/add_achievement_admin', methods=['POST'])
@admin_required
def add_achievement_admin():
    try:
        user_id = request.form['user_id']
        achievement = request.form['achievement']
        date_achieved = request.form['date_achieved']
        
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO student_achievements (user_id, achievement, date_achieved) VALUES (?, ?, ?)',
            (user_id, achievement, date_achieved)
        )
        conn.commit()
        conn.close()
        
        flash('Achievement added successfully!')
    except Exception as e:
        flash(f'Error adding achievement: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))
@app.route('/edit_achievement_admin/<int:achievement_id>', methods=['POST'])
@admin_required
def edit_achievement_admin(achievement_id):
    """Edit an existing achievement (admin only)"""
    try:
        achievement = request.form.get('achievement', '').strip()
        date_achieved = request.form.get('date_achieved', '').strip()
        user_id = request.form.get('user_id')
        
        if not achievement or not date_achieved:
            flash('Achievement description and date are required.', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        conn = get_db_connection()
        
        # Verify achievement exists
        existing = conn.execute(
            'SELECT id FROM student_achievements WHERE id = ?',
            (achievement_id,)
        ).fetchone()
        
        if not existing:
            flash('Achievement not found.', 'danger')
            conn.close()
            return redirect(url_for('admin_dashboard'))
        
        # Update the achievement
        conn.execute('''
            UPDATE student_achievements 
            SET achievement = ?, date_achieved = ?
            WHERE id = ?
        ''', (achievement, date_achieved, achievement_id))
        
        conn.commit()
        conn.close()
        
        flash('Achievement updated successfully!', 'success')
        
    except Exception as e:
        print(f"Error updating achievement: {e}")
        flash(f'Error updating achievement: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))
@app.route('/add-alternative-date', methods=['POST'])
@login_required
def add_alternative_date():
    """Add a new alternative date proposal to an existing attendance record."""
    current_user = get_current_user()
    
    try:
        attendance_id = request.form.get('attendance_id')
        alternative_date = request.form.get('alternative_date')
        preferred_session = request.form.get('preferred_session', '')
        reason = request.form.get('reason', '')
        
        print(f"\n=== ADD ALTERNATIVE DATE REQUEST ===")
        print(f"Attendance ID: {attendance_id}, Date: {alternative_date}")
        
        if not attendance_id or not alternative_date:
            flash('Missing required fields', 'danger')
            return redirect(url_for('student_calendar'))
        
        conn = get_db_connection()
        
        # Verify the attendance record belongs to the current user
        attendance = conn.execute('''
            SELECT a.*, cs.class_name 
            FROM attendance a
            JOIN class_schedule cs ON a.class_id = cs.id
            WHERE a.id = ? AND a.user_id = ?
        ''', (attendance_id, current_user['id'])).fetchone()
        
        if not attendance:
            flash('Attendance record not found', 'danger')
            conn.close()
            return redirect(url_for('student_calendar'))
        
        # Check if this date is already proposed
        existing = conn.execute('''
            SELECT id FROM alternative_date_proposals 
            WHERE attendance_id = ? AND alternative_date = ?
        ''', (attendance_id, alternative_date)).fetchone()
        
        if existing:
            flash('This date has already been proposed', 'warning')
            conn.close()
            return redirect(url_for('student_calendar'))
        
        # Insert new alternative date proposal
        conn.execute('''
            INSERT INTO alternative_date_proposals 
            (attendance_id, alternative_date, preferred_session, status)
            VALUES (?, ?, ?, NULL)
        ''', (attendance_id, alternative_date, preferred_session))
        
        # Update the main attendance record to indicate alternative is proposed
        # and preserve the original reason
        conn.execute('''
            UPDATE attendance 
            SET can_attend = 2,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (attendance_id,))
        
        conn.commit()
        conn.close()
        
        flash('Alternative date added successfully!', 'success')
        
    except Exception as e:
        print(f"Error adding alternative date: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Error adding alternative date: {str(e)}', 'danger')
    
    return redirect(url_for('student_calendar'))


@app.route('/delete-alternative-date/<int:proposal_id>', methods=['POST'])
@login_required
def delete_alternative_date(proposal_id):
    """Delete an alternative date proposal."""
    current_user = get_current_user()
    
    try:
        conn = get_db_connection()
        
        # Get the proposal and verify ownership
        proposal = conn.execute('''
            SELECT adp.*, a.user_id 
            FROM alternative_date_proposals adp
            JOIN attendance a ON adp.attendance_id = a.id
            WHERE adp.id = ?
        ''', (proposal_id,)).fetchone()
        
        if not proposal:
            flash('Proposal not found', 'danger')
            conn.close()
            return redirect(url_for('student_calendar'))
        
        if proposal['user_id'] != current_user['id']:
            flash('Unauthorized to delete this proposal', 'danger')
            conn.close()
            return redirect(url_for('student_calendar'))
        
        # Delete the proposal
        conn.execute('DELETE FROM alternative_date_proposals WHERE id = ?', (proposal_id,))
        
        # Check if there are any remaining alternative proposals for this attendance
        remaining = conn.execute('''
            SELECT COUNT(*) as count FROM alternative_date_proposals 
            WHERE attendance_id = ?
        ''', (proposal['attendance_id'],)).fetchone()
        
        # If no more proposals, update attendance status back to no response
        if remaining['count'] == 0:
            conn.execute('''
                UPDATE attendance 
                SET can_attend = 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (proposal['attendance_id'],))
        
        conn.commit()
        conn.close()
        
        flash('Alternative date removed successfully', 'success')
        
    except Exception as e:
        print(f"Error deleting alternative date: {e}")
        flash(f'Error deleting alternative date: {str(e)}', 'danger')
    
    return redirect(url_for('student_calendar'))


@app.route('/admin/alternative-dates/<int:proposal_id>/approve', methods=['POST'])
@admin_required
def approve_alternative_date_proposal(proposal_id):
    """Approve a specific alternative date proposal."""
    try:
        csrf_token = request.form.get('csrf_token')
        try:
            validate_csrf(csrf_token)
        except Exception:
            flash('Invalid CSRF token', 'danger')
            return redirect(url_for('admin_attendance'))
        
        conn = get_db_connection()
        
        # Get the proposal details
        proposal = conn.execute('''
            SELECT adp.*, a.user_id, a.class_id, a.class_date, 
                   u.full_name as student_name, u.email,
                   cs.class_name
            FROM alternative_date_proposals adp
            JOIN attendance a ON adp.attendance_id = a.id
            JOIN users u ON a.user_id = u.id
            JOIN class_schedule cs ON a.class_id = cs.id
            WHERE adp.id = ?
        ''', (proposal_id,)).fetchone()
        
        if not proposal:
            flash('Proposal not found', 'danger')
            conn.close()
            return redirect(url_for('admin_attendance'))
        
        # Update this proposal to approved
        conn.execute('''
            UPDATE alternative_date_proposals 
            SET status = 1,
                rejection_reason = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (proposal_id,))
        
        # Update the main attendance record
        conn.execute('''
            UPDATE attendance 
            SET admin_approval = 1,
                alternative_date = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (proposal['alternative_date'], proposal['attendance_id']))
        
        # Reject all other proposals for this attendance
        conn.execute('''
            UPDATE alternative_date_proposals 
            SET status = 0,
                rejection_reason = 'Another date was approved',
                updated_at = CURRENT_TIMESTAMP
            WHERE attendance_id = ? AND id != ?
        ''', (proposal['attendance_id'], proposal_id))
        
        conn.commit()
        conn.close()
        
        flash(f'✅ Alternative date approved for {proposal["student_name"]}!', 'success')
        
    except Exception as e:
        print(f"Error approving alternative date: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Error approving alternative date: {str(e)}', 'danger')
    
    return redirect(url_for('admin_attendance'))


@app.route('/admin/alternative-dates/<int:proposal_id>/reject', methods=['POST'])
@admin_required
def reject_alternative_date_proposal(proposal_id):
    """Reject a specific alternative date proposal."""
    try:
        csrf_token = request.form.get('csrf_token')
        rejection_reason = request.form.get('rejection_reason', '').strip()
        
        try:
            validate_csrf(csrf_token)
        except Exception:
            flash('Invalid CSRF token', 'danger')
            return redirect(url_for('admin_attendance'))
        
        conn = get_db_connection()
        
        # Get the proposal details
        proposal = conn.execute('''
            SELECT adp.*, a.user_id, u.full_name as student_name
            FROM alternative_date_proposals adp
            JOIN attendance a ON adp.attendance_id = a.id
            JOIN users u ON a.user_id = u.id
            WHERE adp.id = ?
        ''', (proposal_id,)).fetchone()
        
        if not proposal:
            flash('Proposal not found', 'danger')
            conn.close()
            return redirect(url_for('admin_attendance'))
        
        # Reject this specific proposal
        conn.execute('''
            UPDATE alternative_date_proposals 
            SET status = 0,
                rejection_reason = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (rejection_reason, proposal_id))
        
        # Check if all proposals are rejected
        remaining_pending = conn.execute('''
            SELECT COUNT(*) as count FROM alternative_date_proposals 
            WHERE attendance_id = ? AND (status IS NULL OR status = 2)
        ''', (proposal['attendance_id'],)).fetchone()
        
        if remaining_pending['count'] == 0:
            # No pending proposals, update attendance status
            conn.execute('''
                UPDATE attendance 
                SET admin_approval = 0,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (proposal['attendance_id'],))
        
        conn.commit()
        conn.close()
        
        flash(f'❌ Alternative date rejected for {proposal["student_name"]}', 'warning')
        
    except Exception as e:
        print(f"Error rejecting alternative date: {e}")
        flash(f'Error rejecting alternative date: {str(e)}', 'danger')
    
    return redirect(url_for('admin_attendance'))
    
@app.route('/admin/class/<int:class_id>/edit-details', methods=['POST'])
@admin_required
def edit_class_details(class_id):
    """Edit class details with DATE instead of DAY OF WEEK"""
    class_name = request.form.get('class_name', '').strip()
    class_date = request.form.get('class_date')  #now 'class_date'
    time = request.form.get('time')
    instructor = request.form.get('instructor', '').strip()
    duration = request.form.get('duration')  # Now in HOURS instead of minutes
    
    # Validate input
    if not all([class_name, class_date, time, instructor, duration]):
        flash('All fields are required.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    try:
        # Validate duration is a number
        duration = float(duration)
        if duration < 0.5 or duration > 8:
            flash('Duration must be between 0.5 and 8 hours.', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        conn = get_db_connection()
        
        # Check if class exists
        existing = conn.execute(
            'SELECT id FROM class_schedule WHERE id = ?',
            (class_id,)
        ).fetchone()
        
        if not existing:
            flash('Class not found.', 'danger')
            conn.close()
            return redirect(url_for('admin_dashboard'))
        
        # Update with class_date
        conn.execute('''
            UPDATE class_schedule 
            SET class_name = ?, class_date = ?, time = ?, instructor = ?, duration = ?
            WHERE id = ?
        ''', (class_name, class_date, time, instructor, duration, class_id))
        
        conn.commit()
        conn.close()
        
        flash('Class details updated successfully!', 'success')
    except ValueError:
        flash('Duration must be a valid number.', 'danger')
    except Exception as e:
        print(f"Error updating class: {e}")
        flash(f'Error updating class: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))
@app.route('/delete_achievement/<int:achievement_id>', methods=['POST'])
@admin_required
def delete_achievement(achievement_id):
    try:
        conn = get_db_connection()
        conn.execute('DELETE FROM student_achievements WHERE id = ?', (achievement_id,))
        conn.commit()
        conn.close()
        flash('Achievement deleted successfully!')
    except Exception as e:
        flash(f'Error deleting achievement: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add-class', methods=['POST'])
@admin_required
def add_class_route():
    """Add a new class with DATE instead of DAY OF WEEK"""
    class_name = request.form.get('class_name', '').strip()
    class_date = request.form.get('class_date')  # CHANGED: was 'day', now 'class_date'
    time = request.form.get('time')
    instructor = request.form.get('instructor', '').strip()
    duration = request.form.get('duration')  # Now in HOURS instead of minutes
    
    # Validate input
    if not all([class_name, class_date, time, instructor, duration]):
        flash('All fields are required.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    try:
        # Validate duration is a number
        duration = float(duration)
        if duration < 0.5 or duration > 8:
            flash('Duration must be between 0.5 and 8 hours.', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        conn = get_db_connection()
        
        # Insert with class_date instead of day
        conn.execute('''
            INSERT INTO class_schedule 
            (class_name, class_date, time, instructor, duration)
            VALUES (?, ?, ?, ?, ?)
        ''', (class_name, class_date, time, instructor, duration))
        
        conn.commit()
        conn.close()
        
        flash(f'Class "{class_name}" added successfully!', 'success')
    except ValueError:
        flash('Duration must be a valid number.', 'danger')
    except Exception as e:
        print(f"Error adding class: {e}")
        flash(f'Error adding class: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/edit_class/<int:class_id>', methods=['POST'])
@admin_required
def edit_class(class_id):
    student_ids = request.form.getlist('student_ids')
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Update student associations
        # First, remove existing associations
        cursor.execute('DELETE FROM class_students WHERE class_id = ?', (class_id,))
        
        # Then add new associations
        for student_id in student_ids:
            if student_id:  # Only if student_id is not empty
                cursor.execute(
                    'INSERT INTO class_students (class_id, user_id) VALUES (?, ?)',
                    (class_id, student_id)
                )
        
        conn.commit()
        conn.close()
        flash('Class students updated successfully!', 'success')
    except Exception as e:
        conn.rollback()
        conn.close()
        flash(f'Error updating class students: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_class/<int:class_id>', methods=['POST'])
@admin_required
def delete_class(class_id):
    try:
        conn = get_db_connection()
        
        # 1. Delete alternative_date_proposals linked to attendance records of this class
        conn.execute('''
            DELETE FROM alternative_date_proposals 
            WHERE attendance_id IN (
                SELECT id FROM attendance WHERE class_id = ?
            )
        ''', (class_id,))
        
        # 2. Delete attendance records for this class
        conn.execute('DELETE FROM attendance WHERE class_id = ?', (class_id,))
        
        # 3. Delete class_students enrollments for this class
        conn.execute('DELETE FROM class_students WHERE class_id = ?', (class_id,))
        
        conn.commit()
        conn.close()
        
        # 4. Delete the class schedule itself
        delete_class_db(class_id)
        
        flash('Class and all related attendance history deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting class: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))
    

@app.route('/admin/add-user', methods=['POST'])
@admin_required
def add_user():
    try:
        # Get form data with validation
        username = request.form.get('username', '').strip()
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip()
        
        # Validate required fields
        if not all([username, full_name, email, password, role]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        # Validate email format
        if '@' not in email:
            flash('Please enter a valid email address.', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        # Validate password length
        if len(password) < 4:
            flash('Password must be at least 4 characters long.', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        # Validate role
        if role not in ['student', 'admin']:
            flash('Invalid role selected.', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        conn = get_db_connection()
        
        # Check if username or email already exists
        existing_user = conn.execute(
            'SELECT * FROM users WHERE username = ? OR email = ?', 
            (username, email)
        ).fetchone()
        
        if existing_user:
            flash('Username or email already exists.', 'danger')
            conn.close()
            return redirect(url_for('admin_dashboard'))
        
        # Create new user - automatically approved when added by admin
        hashed_password = generate_password_hash(password)
        conn.execute(
            'INSERT INTO users (username, full_name, email, password, role, is_approved) VALUES (?, ?, ?, ?, ?, ?)',
            (username, full_name, email, hashed_password, role, 1)  # is_approved = 1
        )
        conn.commit()
        conn.close()
        
        flash(f'User "{username}" created successfully!', 'success')
        
    except Exception as e:
        print(f"Error creating user: {e}")
        flash(f'Error creating user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    current_user = get_current_user()
    
    # Prevent self-deletion
    if user_id == current_user['id']:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    
    try:
        # Delete user's achievements first
        conn.execute('DELETE FROM student_achievements WHERE user_id = ?', (user_id,))
        # Delete user's class enrollments
        conn.execute('DELETE FROM class_students WHERE user_id = ?', (user_id,))
        # Delete user
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        flash('User deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('admin_dashboard'))

# ATTENDANCE CALENDAR ROUTES

@app.route('/calendar')
@login_required
def student_calendar():
    print("\n" + "="*60)
    print("🔵 CALENDAR ROUTE ACCESSED")
    print("="*60)
    
    current_user = get_current_user()
    
    if not current_user:
        print("❌ User not authenticated")
        flash('Please log in to access the calendar.', 'warning')
        return redirect(url_for('login'))
    
    print(f"✅ User authenticated: {current_user.get('username', 'unknown')}")
    
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        print("✅ Database connection established")
        
        # --- 1. Get all classes ---
        try:
            classes = conn.execute('''
                SELECT 
                    cs.id,
                    cs.class_name,
                    cs.class_date,
                    cs.time,
                    cs.duration,
                    cs.instructor,
                    cs.admin_notes
                FROM class_schedule cs
                ORDER BY cs.class_date, cs.time
            ''').fetchall()
            print(f"✅ Retrieved {len(classes) if classes else 0} classes")
        except Exception as e:
            print(f"❌ Error fetching classes: {e}")
            classes = []
        
        # --- 2. Get attendance history for this user ---
        try:
            attendance_history = conn.execute('''
                SELECT 
                    a.id,
                    a.user_id,
                    a.class_id,
                    a.class_date,
                    a.can_attend,
                    a.reason,
                    a.alternative_date,
                    a.submitted_by,
                    a.created_at,
                    a.updated_at,
                    a.preferred_session,
                    a.additional_remarks,
                    a.admin_approval,
                    a.rejection_reason,
                    cs.class_name,
                    cs.time,
                    cs.duration
                FROM attendance a
                LEFT JOIN class_schedule cs ON a.class_id = cs.id
                WHERE a.user_id = ?
                ORDER BY a.class_date DESC
                LIMIT 100
            ''', (current_user['id'],)).fetchall()
            print(f"✅ Retrieved {len(attendance_history) if attendance_history else 0} attendance records")
        except Exception as e:
            print(f"❌ Error fetching attendance: {e}")
            attendance_history = []
        
        # --- 3. NEW: Get all class IDs this user is enrolled in ---
        try:
            user_classes = conn.execute('''
                SELECT class_id FROM class_students WHERE user_id = ?
            ''', (current_user['id'],)).fetchall()
            user_class_ids = [row['class_id'] for row in user_classes]
            print(f"✅ User is enrolled in {len(user_class_ids)} classes")
        except Exception as e:
            print(f"⚠️ Could not fetch enrolled classes: {e}")
            user_class_ids = []
        
        # --- 4. Get alternative proposals (optional) ---
        proposals_map = {}
        try:
            all_proposals = conn.execute('''
                SELECT 
                    attendance_id,
                    proposed_date,
                    status,
                    rejection_reason,
                    preferred_session
                FROM alternative_proposals
                WHERE attendance_id IN (SELECT id FROM attendance WHERE user_id = ?)
                ORDER BY proposed_date
            ''', (current_user['id'],)).fetchall()
            
            for proposal in (all_proposals or []):
                if proposal:
                    att_id = proposal['attendance_id']
                    if att_id not in proposals_map:
                        proposals_map[att_id] = []
                    proposals_map[att_id].append({
                        'date': str(proposal['proposed_date']),
                        'status': str(proposal['status'] or 'pending'),
                        'rejection_reason': str(proposal['rejection_reason'] or '') if proposal['rejection_reason'] else '',
                        'session': str(proposal['preferred_session'] or 'morning') if proposal['preferred_session'] else 'morning'
                    })
            print(f"✅ Retrieved proposals for {len(proposals_map)} attendance records")
        except Exception as e:
            print(f"⚠️ Error loading alternative proposals: {e}")
        
        # --- 5. Convert to dictionaries for easy use in template ---
        classes_list = []
        for cls in (classes or []):
            try:
                cls_dict = dict(cls) if cls else {}
                cls_dict['id'] = int(cls_dict.get('id', 0)) if cls_dict.get('id') else 0
                cls_dict['class_name'] = str(cls_dict.get('class_name', ''))
                cls_dict['class_date'] = str(cls_dict.get('class_date', ''))
                cls_dict['time'] = str(cls_dict.get('time', ''))
                cls_dict['duration'] = cls_dict.get('duration', '1')
                # Convert duration to numeric for template use
                try:
                    cls_dict['duration'] = int(float(str(cls_dict['duration']))) if cls_dict['duration'] else 1
                except (ValueError, TypeError):
                    cls_dict['duration'] = 1
                cls_dict['instructor'] = str(cls_dict.get('instructor', 'TBD'))
                cls_dict['admin_notes'] = str(cls_dict.get('admin_notes', '') or '')
                # Provide defaults for fields that templates/JS may reference
                cls_dict['location'] = str(cls_dict.get('location', 'TBD'))
                cls_dict['description'] = str(cls_dict.get('description', '') or '')
                cls_dict['max_students'] = 0
                cls_dict['instructor_id'] = 0
                cls_dict['is_active'] = True
                classes_list.append(cls_dict)
            except Exception as e:
                print(f"⚠️ Error processing class: {e}")
                continue
        
        attendance_list = []
        for record in (attendance_history or []):
            if record:
                try:
                    record_dict = dict(record)
                    record_dict['id'] = int(record_dict.get('id', 0)) if record_dict.get('id') else 0
                    record_dict['user_id'] = int(record_dict.get('user_id', 0)) if record_dict.get('user_id') else 0
                    record_dict['class_id'] = int(record_dict.get('class_id', 0)) if record_dict.get('class_id') else 0
                    record_dict['can_attend'] = int(record_dict.get('can_attend', 0)) if record_dict.get('can_attend') is not None else 0
                    record_dict['admin_approval'] = int(record_dict.get('admin_approval', 0)) if record_dict.get('admin_approval') is not None else None
                    
                    record_dict['class_date'] = str(record_dict.get('class_date', ''))
                    record_dict['class_name'] = str(record_dict.get('class_name', ''))
                    record_dict['time'] = str(record_dict.get('time', ''))
                    # Handle duration which may be stored as text
                    try:
                        record_dict['duration'] = int(float(str(record_dict.get('duration', '1')))) if record_dict.get('duration') else 1
                    except (ValueError, TypeError):
                        record_dict['duration'] = 1
                    record_dict['location'] = str(record_dict.get('location', ''))
                    record_dict['reason'] = str(record_dict.get('reason', '') or '')
                    record_dict['alternative_date'] = str(record_dict.get('alternative_date', '') or '')
                    record_dict['submitted_by'] = str(record_dict.get('submitted_by', ''))
                    record_dict['created_at'] = str(record_dict.get('created_at', ''))
                    record_dict['updated_at'] = str(record_dict.get('updated_at', '') or '')
                    record_dict['preferred_session'] = str(record_dict.get('preferred_session', '') or '')
                    record_dict['additional_remarks'] = str(record_dict.get('additional_remarks', '') or '')
                    record_dict['rejection_reason'] = str(record_dict.get('rejection_reason', '') or '')
                    
                    att_id = record_dict['id']
                    if att_id in proposals_map:
                        record_dict['proposals'] = proposals_map[att_id]
                        record_dict['proposals_count'] = len(proposals_map[att_id])
                    else:
                        record_dict['proposals'] = []
                        record_dict['proposals_count'] = 0
                    
                    attendance_list.append(record_dict)
                except Exception as e:
                    print(f"⚠️ Error processing attendance record: {e}")
                    continue
        
        conn.close()
        print("✅ Database connection closed")
        
        today = datetime.now().date()
        today_str = today.strftime('%Y-%m-%d')
        
        # --- CRITICAL: pass user_class_ids to the template ---
        return render_template('calendar.html',
                             classes=classes_list,
                             attendance_history=attendance_list,
                             user=current_user,
                             today=today_str,
                             user_class_ids=user_class_ids)   # <-- NEW
        
    except Exception as e:
        print(f"❌ CRITICAL ERROR in student_calendar: {e}")
        import traceback
        traceback.print_exc()
        flash('An error occurred while loading the calendar. Please try again.', 'danger')
        return redirect(url_for('student_dashboard'))


# Helper functions to create tables if they don't exist
def create_class_students_table_if_needed():
    """Create the class_students table if it doesn't exist."""
    try:
        conn = get_db_connection()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS class_students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                class_id INTEGER NOT NULL,
                enrolled_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (class_id) REFERENCES class_schedule (id),
                UNIQUE(user_id, class_id)
            )
        ''')
        conn.commit()
        conn.close()
        print("Created class_students table")
    except Exception as e:
        print(f"Error creating class_students table: {e}")
def create_class_schedule_table_if_needed():
    """Create or update class_schedule table."""
    try:
        conn = get_db_connection()
        
        # Check if table exists
        table_exists = conn.execute('''
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='class_schedule'
        ''').fetchone()
        
        if table_exists:
            # Check if duration column exists
            columns = conn.execute('PRAGMA table_info(class_schedule)').fetchall()
            column_names = [col[1] for col in columns]
            
            if 'duration' not in column_names:
                # Add the duration column
                conn.execute('ALTER TABLE class_schedule ADD COLUMN duration DECIMAL(3,1) DEFAULT 1.0')
                conn.commit()
                print("Added duration column to class_schedule table")
        else:
            # Create new table with duration
            conn.execute('''
                CREATE TABLE IF NOT EXISTS class_schedule (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    class_name TEXT NOT NULL,
                    class_date DATE NOT NULL,
                    
                    time TEXT NOT NULL,
                    duration DECIMAL(3,1) DEFAULT 1.0,
                    instructor TEXT,
                    level TEXT,
                    location TEXT,
                    capacity INTEGER,
                    class_type TEXT,
                    admin_notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            print("Created class_schedule table with duration column")
        
        conn.close()
    except Exception as e:
        print(f"Error creating/updating class_schedule table: {e}")

def create_attendance_table_if_needed():
    """Create the attendance table if it doesn't exist."""
    try:
        conn = get_db_connection()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                class_id INTEGER NOT NULL,
                class_date DATE NOT NULL,
                class_name TEXT,
                time TEXT,
                can_attend INTEGER DEFAULT 1,
                reason TEXT,
                alternative_date DATE,
                preferred_session TEXT,
                additional_remarks TEXT,
                admin_approval INTEGER DEFAULT NULL,
                submitted_by TEXT DEFAULT 'parent',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (class_id) REFERENCES class_schedule (id),
                UNIQUE(user_id, class_id, class_date)
            )
        ''')
        conn.commit()
        conn.close()
        print("Created attendance table")
    except Exception as e:
        print(f"Error creating attendance table: {e}")

def fix_missing_columns():
    """Check and add missing columns to existing tables."""
    try:
        conn = get_db_connection()
        
        # Check attendance table columns
        columns = conn.execute("PRAGMA table_info(attendance)").fetchall()
        column_names = [col[1] for col in columns]
        print(f"Existing attendance columns: {column_names}")
        
        # Add missing columns if they don't exist
        missing_columns = ['additional_remarks', 'preferred_session', 'rejection_reason']
        
        for column in missing_columns:
            if column not in column_names:
                print(f"Adding missing column: {column}")
                if column in ['additional_remarks', 'rejection_reason']:
                    conn.execute(f'ALTER TABLE attendance ADD COLUMN {column} TEXT')
                elif column == 'preferred_session':
                    conn.execute(f'ALTER TABLE attendance ADD COLUMN {column} TEXT')
        
        conn.commit()
        conn.close()
        print("✅ Fixed missing columns in attendance table")
    except Exception as e:
        print(f"Error fixing columns: {e}")

fix_missing_columns()

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



@app.route('/browse-classes')
@login_required
def browse_classes():
    """Browse all classes and see who's enrolled in each."""
    current_user = get_current_user()
    
    if not current_user:
        flash('Please log in to browse classes.', 'warning')
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        
        # First, check what columns exist in class_schedule
        print("=" * 50)
        print("DEBUG: Checking class_schedule table structure...")
        print("=" * 50)
        
        cursor = conn.execute("PRAGMA table_info(class_schedule)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        print(f"Found columns: {column_names}")
        
        # Build dynamic SELECT based on available columns
        select_parts = [
            'cs.id',
            'cs.class_name',
            'cs.class_date',
            'cs.time',
            'cs.instructor'
        ]
        
        # Only add optional columns if they exist
        optional_columns = ['duration', 'level', 'capacity', 'location', 'class_type']
        for col in optional_columns:
            if col in column_names:
                select_parts.append(f'cs.{col}')
                print(f"  ✅ Column '{col}' found - including in query")
            else:
                print(f"  ❌ Column '{col}' NOT found - skipping")
        
        select_clause = ', '.join(select_parts)
        select_clause += ', COUNT(DISTINCT cst.user_id) as enrolled_count'
        
        print(f"\nBuilding query with: {select_parts}")
        
        # Now run the query
        query = f'''
            SELECT DISTINCT {select_clause}
            FROM class_schedule cs
            LEFT JOIN class_students cst ON cs.id = cst.class_id
            GROUP BY cs.id
            ORDER BY cs.class_date, cs.time
        '''
        
        print(f"\nExecuting query...")
        all_classes = conn.execute(query).fetchall()
        print(f"✅ Query successful! Found {len(all_classes)} classes")
        
        # Convert to list of dictionaries
        classes_list = []
        for cls in all_classes:
            if cls:
                cls_dict = dict(cls)
                classes_list.append(cls_dict)
        
        print(f"✅ Converted to list: {len(classes_list)} classes ready")
        
        # Get user's enrolled classes
        user_classes = conn.execute('''
            SELECT class_id
            FROM class_students
            WHERE user_id = ?
        ''', (current_user['id'],)).fetchall()
        
        user_class_ids = [c['class_id'] for c in user_classes]
        print(f"✅ User enrolled in {len(user_class_ids)} classes")
        
        conn.close()
        
        print("=" * 50)
        print("✅ SUCCESS: browse_classes completed!")
        print("=" * 50)
        
        return render_template('browse_classes.html',
                             classes=classes_list,
                             user=current_user,
                             user_class_ids=user_class_ids)
        
    except Exception as e:
        print("=" * 50)
        print("❌ ERROR IN BROWSE_CLASSES:")
        print("=" * 50)
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Message: {str(e)}")
        print("=" * 50)
        
        import traceback
        traceback.print_exc()
        
        flash(f'An error occurred: {str(e)}', 'danger')
        return redirect(url_for('student_dashboard'))


@app.route('/class-details/<int:class_id>')
@login_required
def class_details(class_id):
    current_user = get_current_user()
    
    try:
        conn = get_db_connection()
        
        # Get class information
        class_info = conn.execute('''
            SELECT * FROM class_schedule 
            WHERE id = ?
        ''', (class_id,)).fetchone()
        
        if not class_info:
            flash('Class not found.', 'danger')
            return redirect(url_for('browse_classes'))
        
        # Convert to dictionary
        class_info_dict = dict(class_info)
        
        # Check if user is enrolled in this class
        is_enrolled = conn.execute('''
            SELECT 1 FROM class_students 
            WHERE user_id = ? AND class_id = ?
        ''', (current_user['id'], class_id)).fetchone() is not None
        
        # Get enrolled students for this class
        students = conn.execute('''
            SELECT u.id, u.username, u.full_name, 
                   cst.enrolled_date as enrolled_date
            FROM users u
            JOIN class_students cst ON u.id = cst.user_id
            WHERE cst.class_id = ?
            ORDER BY u.full_name
        ''', (class_id,)).fetchall()
        
        # Convert to list of dictionaries
        students_list = [dict(student) for student in students]
        
        # Get attendance statistics for the entire class (if enrolled)
        stats = None
        if is_enrolled:
            stats_record = conn.execute('''
                SELECT 
                    COUNT(CASE WHEN a.can_attend = 1 THEN 1 END) as attending,
                    COUNT(CASE WHEN a.can_attend = 0 THEN 1 END) as not_attending,
                    COUNT(CASE WHEN a.can_attend = 2 THEN 1 END) as alternative,
                    COUNT(CASE WHEN a.can_attend IS NULL THEN 1 END) as no_response
                FROM attendance a
                WHERE a.class_id = ?
            ''', (class_id,)).fetchone()
            
            if stats_record:
                stats = dict(stats_record)
            else:
                # Provide default zeros if no records exist
                stats = {
                    'attending': 0,
                    'not_attending': 0,
                    'alternative': 0,
                    'no_response': 0
                }
        conn.close()
        
        # Get list of class IDs user is enrolled in (for the browse page context)
        # This is needed if you want to show which classes the user is enrolled in
        conn = get_db_connection()
        user_classes = conn.execute('''
            SELECT class_id FROM class_students 
            WHERE user_id = ?
        ''', (current_user['id'],)).fetchall()
        user_class_ids = [row['class_id'] for row in user_classes]
        conn.close()
        
        return render_template('class_details.html',
                             class_info=class_info_dict,
                             is_enrolled=is_enrolled,
                             students=students_list,
                             stats=stats,
                             user=current_user,
                             user_class_ids=user_class_ids)
    
    except sqlite3.OperationalError as e:
        print(f"Database error in class_details: {e}")
        
        # Check if the error is about missing enrolled_date column
        if "no such column: cst.enrolled_date" in str(e):
            # Create the column or use a fallback query
            return render_class_details_without_enrolled_date(class_id, current_user)
        elif "no such table" in str(e):
            # Handle missing table
            flash('Database tables are not properly set up.', 'danger')
            return redirect(url_for('student_dashboard'))
        else:
            flash('Database error occurred.', 'danger')
            return redirect(url_for('browse_classes'))
    
    except Exception as e:
        print(f"Error in class_details: {e}")
        import traceback
        traceback.print_exc()
        flash('An error occurred while loading class details.', 'danger')
        return redirect(url_for('browse_classes'))


def render_class_details_without_enrolled_date(class_id, current_user):
    """Fallback function for when enrolled_date column doesn't exist"""
    try:
        conn = get_db_connection()
        
        # Get class information
        class_info = conn.execute('''
            SELECT * FROM class_schedule 
            WHERE id = ?
        ''', (class_id,)).fetchone()
        
        if not class_info:
            flash('Class not found.', 'danger')
            return redirect(url_for('browse_classes'))
        
        class_info_dict = dict(class_info)
        
        # Check if user is enrolled in this class
        is_enrolled = conn.execute('''
            SELECT 1 FROM class_students 
            WHERE user_id = ? AND class_id = ?
        ''', (current_user['id'], class_id)).fetchone() is not None
        
        # Get enrolled students WITHOUT enrolled_date (using current timestamp as fallback)
        students = conn.execute('''
            SELECT u.id, u.username, u.full_name,
                   datetime('now') as enrolled_date  -- Fallback to current time
            FROM users u
            JOIN class_students cst ON u.id = cst.user_id
            WHERE cst.class_id = ?
            ORDER BY u.full_name
        ''', (class_id,)).fetchall()
        
        students_list = [dict(student) for student in students]
        
        # Get attendance statistics
        stats = None
        if is_enrolled:
            stats = conn.execute('''
                SELECT 
                    COUNT(CASE WHEN can_attend = 1 THEN 1 END) as attending,
                    COUNT(CASE WHEN can_attend = 0 THEN 1 END) as not_attending,
                    COUNT(CASE WHEN can_attend = 2 THEN 1 END) as alternative,
                    COUNT(CASE WHEN can_attend IS NULL THEN 1 END) as no_response
                FROM attendance
                WHERE user_id = ? AND class_id = ?
            ''', (current_user['id'], class_id)).fetchone()
            
            if stats:
                stats = dict(stats)
        
        conn.close()
        
        # Get user's class IDs
        conn = get_db_connection()
        user_classes = conn.execute('''
            SELECT class_id FROM class_students 
            WHERE user_id = ?
        ''', (current_user['id'],)).fetchall()
        user_class_ids = [row['class_id'] for row in user_classes]
        conn.close()
        
        return render_template('class_details.html',
                             class_info=class_info_dict,
                             is_enrolled=is_enrolled,
                             students=students_list,
                             stats=stats,
                             user=current_user,
                             user_class_ids=user_class_ids)
    
    except Exception as e:
        print(f"Error in fallback function: {e}")
        flash('An error occurred while loading class details.', 'danger')
        return redirect(url_for('browse_classes'))

@app.route('/enroll/<int:class_id>', methods=['GET', 'POST'])
@login_required
def enroll_in_class(class_id):
    """Enroll a student in a class."""
    current_user = get_current_user()
    
    if not current_user:
        flash('Please log in to enroll in a class.', 'warning')
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        
        # Get class information
        class_info = conn.execute('''
            SELECT * FROM class_schedule WHERE id = ?
        ''', (class_id,)).fetchone()
        
        if not class_info:
            conn.close()
            flash('Class not found.', 'danger')
            return redirect(url_for('student_calendar'))
        
        class_dict = dict(class_info)
        
        # Check if already enrolled
        already_enrolled = conn.execute('''
            SELECT 1 FROM class_students 
            WHERE user_id = ? AND class_id = ?
        ''', (current_user['id'], class_id)).fetchone()
        
        if already_enrolled:
            conn.close()
            flash(f'You are already enrolled in {class_dict["class_name"]}.', 'info')
            return redirect(url_for('student_calendar'))
        
        # Get enrolled student count
        enrolled_count = conn.execute('''
            SELECT COUNT(*) as count FROM class_students WHERE class_id = ?
        ''', (class_id,)).fetchone()['count']
        
        # Get list of students already enrolled (to show classmates)
        classmates = conn.execute('''
            SELECT u.full_name, u.username
            FROM users u
            JOIN class_students cst ON u.id = cst.user_id
            WHERE cst.class_id = ?
            ORDER BY u.full_name
        ''', (class_id,)).fetchall()
        classmates_list = [dict(c) for c in classmates]
        
        if request.method == 'POST':
            # Perform enrollment
            try:
                conn.execute('''
                    INSERT INTO class_students (class_id, user_id)
                    VALUES (?, ?)
                ''', (class_id, current_user['id']))
                conn.commit()
                conn.close()
                
                flash(f'Successfully enrolled in {class_dict["class_name"]}! 🎉', 'success')
                return redirect(url_for('student_calendar'))
                
            except sqlite3.IntegrityError:
                conn.close()
                flash(f'You are already enrolled in {class_dict["class_name"]}.', 'info')
                return redirect(url_for('student_calendar'))
        
        conn.close()
        
        # GET request - show confirmation page
        return render_template('enroll_class.html',
                             class_info=class_dict,
                             enrolled_count=enrolled_count,
                             classmates=classmates_list,
                             user=current_user)
    
    except Exception as e:
        print(f"Error in enroll_in_class: {e}")
        import traceback
        traceback.print_exc()
        flash('An error occurred while processing your enrollment.', 'danger')
        return redirect(url_for('student_calendar'))


@app.route('/api/class-members/<int:class_id>')
@login_required
def api_class_members(class_id):
    """API endpoint to get class members (JSON)."""
    current_user = get_current_user()
    
    if not current_user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        conn = get_db_connection()
        
        students = conn.execute('''
            SELECT 
                u.id,
                u.full_name,
                u.username
            FROM class_students cst
            JOIN users u ON cst.user_id = u.id
            WHERE cst.class_id = ?
            ORDER BY u.full_name
        ''', (class_id,)).fetchall()
        
        conn.close()
        
        return jsonify({
            'class_id': class_id,
            'members': [dict(s) for s in students],
            'total': len(students)
        })
        
    except Exception as e:
        print(f"Error in api_class_members: {e}")
        return jsonify({'error': 'Server error'}), 500

# Get or create attendance record
@app.route('/get-or-create-attendance/<int:class_id>/<date_str>', methods=['GET'])
@login_required
def get_or_create_attendance(class_id, date_str):
    """Get existing attendance record or create a new one"""
    current_user = get_current_user()
    
    try:
        conn = get_db_connection()
        
        # Try to get existing record
        record = conn.execute('''
            SELECT id FROM attendance 
            WHERE user_id = ? AND class_id = ? AND class_date = ?
        ''', (current_user['id'], class_id, date_str)).fetchone()
        
        if record:
            conn.close()
            return jsonify({'id': record['id'], 'status': 'existing'})
        
        # Get class details
        class_info = conn.execute('''
            SELECT class_name, time FROM class_schedule WHERE id = ?
        ''', (class_id,)).fetchone()
        
        if not class_info:
            conn.close()
            return jsonify({'error': 'Class not found'}), 404
        
        # Create new record with default values
        conn.execute('''
            INSERT INTO attendance 
            (user_id, class_id, class_date, class_name, time, can_attend, submitted_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (current_user['id'], class_id, date_str, class_info['class_name'], 
              class_info['time'], 1, 'parent'))
        
        conn.commit()
        
        # Get the newly created record ID
        new_record = conn.execute('''
            SELECT id FROM attendance 
            WHERE user_id = ? AND class_id = ? AND class_date = ?
        ''', (current_user['id'], class_id, date_str)).fetchone()
        
        conn.close()
        
        if new_record:
            return jsonify({'id': new_record['id'], 'status': 'created'})
        else:
            return jsonify({'error': 'Failed to create record'}), 500
    
    except Exception as e:
        print(f"Error in get_or_create_attendance: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    
@app.route('/edit_attendance/<int:attendance_id>', methods=['POST'])
@login_required
def edit_attendance(attendance_id):
    """Update attendance record with multiple alternative date proposals"""
    current_user = get_current_user()
    
    print(f"\n=== EDIT ATTENDANCE REQUEST ===")
    print(f"Attendance ID: {attendance_id}")
    print(f"User: {current_user['username']} (ID: {current_user['id']})")
    
    try:
        # Get form data
        can_attend = int(request.form.get('can_attend', 1))
        reason = request.form.get('reason', '').strip()
        submitted_by = request.form.get('submitted_by', 'parent')
        preferred_session = request.form.get('preferred_session', '')
        additional_remarks = request.form.get('additional_remarks', '').strip()
        
        # Get multiple alternative dates from JSON
        alternative_dates_json = request.form.get('alternative_dates_json', '[]')
        
        print(f"Can attend: {can_attend}")
        print(f"Reason: {reason}")
        print(f"Alternative dates JSON: {alternative_dates_json}")
        
        conn = get_db_connection()
        
        # Verify the attendance record belongs to the current user
        record = conn.execute('''
            SELECT user_id, class_id, class_date 
            FROM attendance 
            WHERE id = ?
        ''', (attendance_id,)).fetchone()
        
        if not record:
            print(f"ERROR: Record {attendance_id} not found")
            conn.close()
            flash('Attendance record not found', 'error')
            return redirect(url_for('student_calendar'))
        
        if record['user_id'] != current_user['id']:
            print(f"ERROR: User mismatch. Record user: {record['user_id']}, Current user: {current_user['id']}")
            conn.close()
            flash('Unauthorized to edit this record', 'error')
            return redirect(url_for('student_calendar'))
        
        # Update main attendance record
        # Reset admin_approval and rejection_reason when student edits,
        # so admin must re-approve any changes to alternative dates
        conn.execute('''
            UPDATE attendance 
            SET can_attend = ?,
                reason = ?,
                submitted_by = ?,
                preferred_session = ?,
                additional_remarks = ?,
                admin_approval = CASE WHEN ? = 2 THEN NULL ELSE admin_approval END,
                rejection_reason = CASE WHEN ? = 2 THEN NULL ELSE rejection_reason END,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (can_attend, reason, submitted_by, preferred_session, 
              additional_remarks, can_attend, can_attend, attendance_id))
        
        # Handle alternative date proposals
        if can_attend == 2:
            import json
            try:
                alternative_dates_raw = json.loads(alternative_dates_json)
                print(f"Processing {len(alternative_dates_raw)} alternative dates")
                
                # Normalize: support both [{date, session}] and ["date"] formats
                alternative_entries = []
                for item in alternative_dates_raw:
                    if isinstance(item, dict):
                        alternative_entries.append({
                            'date': item.get('date', ''),
                            'session': item.get('session', preferred_session or 'morning')
                        })
                    elif isinstance(item, str):
                        alternative_entries.append({
                            'date': item,
                            'session': preferred_session or 'morning'
                        })
                
                alternative_dates = [e['date'] for e in alternative_entries]
                session_map = {e['date']: e['session'] for e in alternative_entries}
                
                # Get existing proposals
                existing_proposals = conn.execute('''
                    SELECT proposed_date FROM alternative_proposals 
                    WHERE attendance_id = ?
                ''', (attendance_id,)).fetchall()
                
                existing_dates = [p['proposed_date'] for p in existing_proposals]
                
                # Add new proposals with per-date session
                for entry in alternative_entries:
                    if entry['date'] not in existing_dates:
                        conn.execute('''
                            INSERT INTO alternative_proposals 
                            (attendance_id, proposed_date, preferred_session, reason, additional_remarks, status)
                            VALUES (?, ?, ?, ?, ?, 'pending')
                        ''', (attendance_id, entry['date'], entry['session'], reason, additional_remarks))
                        print(f"Added proposal for date: {entry['date']} with session: {entry['session']}")
                    else:
                        # Update session for existing proposals and reset status to pending
                        conn.execute('''
                            UPDATE alternative_proposals 
                            SET preferred_session = ?,
                                status = 'pending',
                                rejection_reason = NULL
                            WHERE attendance_id = ? AND proposed_date = ?
                        ''', (entry['session'], attendance_id, entry['date']))
                        print(f"Updated session for date: {entry['date']} to: {entry['session']} (reset to pending)")
                
                # Remove proposals that were deselected
                for existing_date in existing_dates:
                    if existing_date not in alternative_dates:
                        conn.execute('''
                            DELETE FROM alternative_proposals 
                            WHERE attendance_id = ? AND proposed_date = ?
                        ''', (attendance_id, existing_date))
                        print(f"Removed proposal for date: {existing_date}")
                
                # Clear the old alternative_date field
                conn.execute('''
                    UPDATE attendance SET alternative_date = NULL WHERE id = ?
                ''', (attendance_id,))
                
            except json.JSONDecodeError as e:
                print(f"Error parsing alternative dates JSON: {e}")
        else:
            # Not proposing alternative - clear any existing proposals
            conn.execute('''
                DELETE FROM alternative_proposals WHERE attendance_id = ?
            ''', (attendance_id,))
            
            # Clear alternative date field
            conn.execute('''
                UPDATE attendance SET alternative_date = NULL WHERE id = ?
            ''', (attendance_id,))
        
        conn.commit()
        
        # Verify update
        updated = conn.execute('''
            SELECT * FROM attendance WHERE id = ?
        ''', (attendance_id,)).fetchone()
        
        if updated:
            print(f"✅ Successfully updated attendance record {attendance_id}")
        
        conn.close()
        
        # Only flash for non-AJAX requests (AJAX handles its own UI feedback)
        if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
            flash('Attendance updated successfully!', 'success')
        
    except Exception as e:
        print(f"❌ Error updating attendance: {e}")
        import traceback
        traceback.print_exc()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': f'Error updating attendance: {str(e)}'}), 500
        flash(f'Error updating attendance: {str(e)}', 'error')
    
    # Check if this is an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True, 'message': 'Attendance updated successfully'})
    
    return redirect(url_for('student_calendar'))
# Add these routes to app.py

@app.route('/admin/select-alternative-date', methods=['POST'])
@admin_required
def admin_select_alternative_date():
    """Admin selects one alternative date from multiple proposals"""
    try:
        csrf_token = request.form.get('csrf_token')
        validate_csrf(csrf_token)
        
        proposal_id = request.form.get('proposal_id')
        attendance_id = request.form.get('attendance_id')
        selected_date = request.form.get('selected_date')
        
        conn = get_db_connection()
        
        # Check what columns exist in alternative_proposals
        columns = conn.execute("PRAGMA table_info(alternative_proposals)").fetchall()
        column_names = [col[1] for col in columns]
        
        # Get proposal details
        proposal = conn.execute('''
            SELECT ap.*, a.user_id, a.class_id, u.full_name, u.email, cs.class_name
            FROM alternative_proposals ap
            JOIN attendance a ON ap.attendance_id = a.id
            JOIN users u ON a.user_id = u.id
            JOIN class_schedule cs ON a.class_id = cs.id
            WHERE ap.id = ?
        ''', (proposal_id,)).fetchone()
        
        if not proposal:
            flash('Proposal not found', 'danger')
            conn.close()
            return redirect(url_for('admin_attendance'))
        
        # Mark this proposal as selected
        conn.execute('''
            UPDATE alternative_proposals 
            SET status = 'selected', updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (proposal_id,))
        
        # Mark all other proposals for this attendance as rejected
        if 'rejection_reason' in column_names:
            conn.execute('''
                UPDATE alternative_proposals 
                SET status = 'rejected', 
                    rejection_reason = 'Another date was selected',
                    updated_at = CURRENT_TIMESTAMP
                WHERE attendance_id = ? AND id != ?
            ''', (attendance_id, proposal_id))
        else:
            conn.execute('''
                UPDATE alternative_proposals 
                SET status = 'rejected', 
                    updated_at = CURRENT_TIMESTAMP
                WHERE attendance_id = ? AND id != ?
            ''', (attendance_id, proposal_id))
        
       
       # Update attendance record with selected date and its preferred session
        selected_session = proposal['preferred_session'] if proposal['preferred_session'] else None
        conn.execute('''
            UPDATE attendance 
            SET alternative_date = ?,
                admin_approval = 1,
                preferred_session = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (selected_date, selected_session, attendance_id))
        
        conn.commit()
        conn.close()
        
        flash(f'✅ Selected {selected_date} as the new class date for {proposal["full_name"]}!', 'success')
        
    except Exception as e:
        print(f"Error selecting alternative date: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Error selecting alternative date: {str(e)}', 'danger')
    
    return redirect(url_for('admin_attendance'))

@app.route('/admin/reject-proposal/<int:proposal_id>', methods=['POST'])
@admin_required
def admin_reject_proposal(proposal_id):
    """Reject a specific alternative date proposal"""
    try:
        csrf_token = request.form.get('csrf_token')
        validate_csrf(csrf_token)
        
        rejection_reason = request.form.get('rejection_reason', '').strip()
        
        conn = get_db_connection()
        
        # First check if rejection_reason column exists
        columns = conn.execute("PRAGMA table_info(alternative_proposals)").fetchall()
        column_names = [col[1] for col in columns]
        
        # Get proposal details
        proposal = conn.execute('''
            SELECT ap.*, a.user_id
            FROM alternative_proposals ap
            JOIN attendance a ON ap.attendance_id = a.id
            WHERE ap.id = ?
        ''', (proposal_id,)).fetchone()
        
        if not proposal:
            flash('Proposal not found', 'danger')
            conn.close()
            return redirect(url_for('admin_attendance'))
        
        # Check if we can update rejection_reason
        if 'rejection_reason' in column_names:
            # Column exists - update with rejection reason
            conn.execute('''
                UPDATE alternative_proposals 
                SET status = 'rejected',
                    rejection_reason = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (rejection_reason, proposal_id))
        else:
            # Column doesn't exist - just update status
            conn.execute('''
                UPDATE alternative_proposals 
                SET status = 'rejected',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (proposal_id,))
        
        # Check if there are still any pending proposals for this attendance
        pending = conn.execute('''
            SELECT COUNT(*) as count FROM alternative_proposals 
            WHERE attendance_id = ? AND status = 'pending'
        ''', (proposal['attendance_id'],)).fetchone()
        
        if pending['count'] == 0:
            # No pending proposals left, update attendance status
            conn.execute('''
                UPDATE attendance 
                SET admin_approval = 0,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (proposal['attendance_id'],))
        
        conn.commit()
        conn.close()
        
        flash('✅ Proposal rejected successfully', 'success')
        
    except Exception as e:
        print(f"Error rejecting proposal: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Error rejecting proposal: {str(e)}', 'danger')
    
    return redirect(url_for('admin_attendance'))
@app.route('/admin/attendance')
@admin_required
def admin_attendance():
    """Display attendance records with multiple alternative date proposals"""
    date_filter = request.args.get('date', '')
    class_filter = request.args.get('class_id', '')
    status_filter = request.args.get('status', '')
    
    try:
        conn = get_db_connection()
        
        # Get all attendance records with student and class info
        query = '''
            SELECT 
                a.id,
                a.user_id,
                a.class_id,
                a.class_date,
                a.can_attend,
                a.reason,
                a.alternative_date,
                a.preferred_session,
                a.additional_remarks,
                a.submitted_by,
                a.created_at,
                a.admin_approval,
                a.rejection_reason,
                u.full_name as student_name,
                u.username,
                cs.class_name,
                cs.time
            FROM attendance a
            JOIN users u ON a.user_id = u.id
            JOIN class_schedule cs ON a.class_id = cs.id
            WHERE 1=1
        '''
        
        params = []
        
        if date_filter:
            query += ' AND a.class_date = ?'
            params.append(date_filter)
        
        if class_filter:
            query += ' AND a.class_id = ?'
            params.append(class_filter)
        
        if status_filter == 'attending':
            query += ' AND a.can_attend = 1'
        elif status_filter == 'not_attending':
            query += ' AND a.can_attend = 0'
        elif status_filter == 'alternative':
            query += ' AND a.can_attend = 2'
        
        query += ' ORDER BY a.class_date DESC, a.created_at DESC'
        
        attendance_records = conn.execute(query, params).fetchall()
        attendance_list = [dict(r) for r in attendance_records]
        
        # Attach proposal rejection reasons to attendance records that have alternatives
        for record in attendance_list:
            if record.get('can_attend') == 2:
                try:
                    proposals = conn.execute('''
                        SELECT proposed_date, status, rejection_reason
                        FROM alternative_proposals
                        WHERE attendance_id = ?
                        ORDER BY proposed_date
                    ''', (record['id'],)).fetchall()
                    record['proposals'] = [dict(p) for p in proposals]
                except Exception:
                    record['proposals'] = []
            else:
                record['proposals'] = []
        
        # Get pending alternative proposals (grouped by attendance)
        pending_query = '''
            SELECT 
                a.id,
                a.user_id,
                a.class_id,
                a.class_date,
                a.reason,
                a.additional_remarks,
                a.submitted_by,
                a.created_at,
                u.full_name as student_name,
                u.username,
                cs.class_name,
                cs.time
            FROM attendance a
            JOIN users u ON a.user_id = u.id
            JOIN class_schedule cs ON a.class_id = cs.id
            WHERE a.can_attend = 2 
            AND EXISTS (
                SELECT 1 FROM alternative_proposals ap 
                WHERE ap.attendance_id = a.id AND ap.status = 'pending'
            )
            ORDER BY a.created_at ASC
        '''
        
        pending_records = conn.execute(pending_query).fetchall()
        pending_list = []
        
        for record in pending_records:
            record_dict = dict(record)
            
            # Get all proposals for this attendance
            proposals = conn.execute('''
                SELECT * FROM alternative_proposals 
                WHERE attendance_id = ? 
                ORDER BY proposed_date ASC
            ''', (record_dict['id'],)).fetchall()
            
            record_dict['proposals'] = [dict(p) for p in proposals]
            pending_list.append(record_dict)
        
        # Get classes for filter
        classes = conn.execute('SELECT id, class_name FROM class_schedule ORDER BY class_name').fetchall()
        
        # Calculate statistics
        total_records = len(attendance_list)
        attending = sum(1 for r in attendance_list if r['can_attend'] == 1)
        not_attending = sum(1 for r in attendance_list if r['can_attend'] == 0)
        alternative = sum(1 for r in attendance_list if r['can_attend'] == 2)
        
        conn.close()
        
        return render_template('admin_attendance.html',
                             attendance_records=attendance_list,
                             pending_alternatives=pending_list,
                             classes=classes,
                             total_records=total_records,
                             attending=attending,
                             not_attending=not_attending,
                             alternative=alternative,
                             date_filter=date_filter,
                             class_filter=class_filter,
                             status_filter=status_filter)
    
    except Exception as e:
        print(f"Error loading attendance records: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Error loading attendance records: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))
    
@app.template_filter('escapejs')
def escapejs_filter(s):
    """Escape string for use in JavaScript"""
    if s is None:
        return ''
    import json
    return json.dumps(str(s))[1:-1]  # Remove outer quotes
@app.route('/admin/edit-attendance/<int:attendance_id>', methods=['POST'])
@admin_required
def edit_attendance_admin(attendance_id):
    """Edit any attendance record (admin only) - Enhanced version"""
    print(f"\n=== ADMIN EDIT ATTENDANCE REQUEST ===")
    print(f"Attendance ID: {attendance_id}")
    print(f"Form data: {request.form}")
    
    try:
        # CSRF validation
        csrf_token = request.form.get('csrf_token')
        try:
            validate_csrf(csrf_token)
        except Exception:
            print("CSRF validation failed")
            flash('Invalid CSRF token', 'danger')
            return redirect(url_for('admin_attendance'))
        
        # Get form data with defaults
        can_attend = request.form.get('can_attend', '1')
        reason = request.form.get('reason', '')
        alternative_date = request.form.get('alternative_date', '')
        preferred_session = request.form.get('preferred_session', '')
        additional_remarks = request.form.get('additional_remarks', '')
        admin_approval = request.form.get('admin_approval')
        rejection_reason = request.form.get('rejection_reason', '')
        submitted_by = request.form.get('submitted_by', 'parent')
        
        print(f"can_attend: {can_attend}")
        print(f"admin_approval: {admin_approval}")
        
        # Validate can_attend
        try:
            can_attend = int(can_attend)
        except ValueError:
            flash('Invalid attendance status', 'danger')
            return redirect(url_for('admin_attendance'))
        
        # Connect to database
        conn = get_db_connection()
        
        # Get current record for logging
        current_record = conn.execute(
            'SELECT * FROM attendance WHERE id = ?',
            (attendance_id,)
        ).fetchone()
        
        if not current_record:
            flash('Attendance record not found', 'danger')
            conn.close()
            return redirect(url_for('admin_attendance'))
        
        print(f"Current record: {dict(current_record)}")
        
        # Handle admin approval for alternative dates
        if can_attend == 2:
            # Convert admin_approval to integer or None
            if admin_approval == '' or admin_approval is None:
                admin_approval_val = None
            else:
                try:
                    admin_approval_val = int(admin_approval)
                except (ValueError, TypeError):
                    admin_approval_val = None
            
            # If alternative date is empty, set to None
            if not alternative_date or alternative_date.strip() == '':
                alternative_date = None
            
            # Clear rejection reason if not rejecting
            if admin_approval_val != 0:
                rejection_reason = ''
                # Also clear rejection reasons and reset proposal statuses in alternative_proposals table
                if admin_approval_val == 1:
                    # Approved - clear rejection reasons from all proposals
                    conn.execute('''
                        UPDATE alternative_proposals 
                        SET rejection_reason = NULL
                        WHERE attendance_id = ? AND rejection_reason IS NOT NULL
                    ''', (attendance_id,))
                elif admin_approval_val is None:
                    # Pending - reset all proposals back to pending
                    conn.execute('''
                        UPDATE alternative_proposals 
                        SET status = 'pending', rejection_reason = NULL
                        WHERE attendance_id = ?
                    ''', (attendance_id,))
            
            # Update with all fields including admin approval
            conn.execute('''
                UPDATE attendance 
                SET can_attend = ?,
                    reason = ?,
                    alternative_date = ?,
                    preferred_session = ?,
                    additional_remarks = ?,
                    admin_approval = ?,
                    rejection_reason = ?,
                    submitted_by = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (can_attend, reason.strip(), alternative_date, 
                  preferred_session.strip() if preferred_session else None,
                  additional_remarks.strip() if additional_remarks else None,
                  admin_approval_val, rejection_reason.strip() if rejection_reason else None,
                  submitted_by, attendance_id))
            
            # Sync rejection_reason to alternative_proposals so calendar view stays consistent
            if admin_approval_val == 0 and rejection_reason and rejection_reason.strip():
                # Update all proposals for this attendance to rejected with the same reason
                conn.execute('''
                    UPDATE alternative_proposals 
                    SET status = 'rejected',
                        rejection_reason = ?
                    WHERE attendance_id = ?
                ''', (rejection_reason.strip(), attendance_id))
        else:
            # Not an alternative date proposal - clear approval fields
            conn.execute('''
                UPDATE attendance 
                SET can_attend = ?,
                    reason = ?,
                    alternative_date = NULL,
                    preferred_session = NULL,
                    additional_remarks = ?,
                    admin_approval = NULL,
                    rejection_reason = NULL,
                    submitted_by = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (can_attend, reason.strip(), 
                  additional_remarks.strip() if additional_remarks else None,
                  submitted_by, attendance_id))
        
        # Commit changes
        conn.commit()
        
        # Verify the update
        updated_record = conn.execute(
            'SELECT * FROM attendance WHERE id = ?',
            (attendance_id,)
        ).fetchone()
        
        print(f"Updated record: {dict(updated_record)}")
        
        # Get student name for flash message
        student_info = conn.execute('''
            SELECT u.full_name 
            FROM attendance a
            JOIN users u ON a.user_id = u.id
            WHERE a.id = ?
        ''', (attendance_id,)).fetchone()
        
        conn.close()
        
        student_name = student_info['full_name'] if student_info else 'Unknown'
        flash(f'✅ Attendance record updated for {student_name}!', 'success')
        
    except Exception as e:
        print(f"Error updating attendance: {e}")
        import traceback
        traceback.print_exc()
        flash(f'❌ Error updating attendance: {str(e)}', 'danger')
    
    # Check if this is an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True, 'message': 'Attendance updated successfully'})
    
    return redirect(url_for('admin_attendance'))

def check_attendance_table_structure():
    """Check and fix attendance table structure if needed"""
    conn = get_db_connection()
    try:
        # Get table info
        table_info = conn.execute("PRAGMA table_info(attendance)").fetchall()
        print("=== ATTENDANCE TABLE STRUCTURE ===")
        for column in table_info:
            print(f"Column: {column[1]}, Type: {column[2]}, Nullable: {column[3]}")
        
        # Check which columns exist ✅ NEW APPROACH
        column_names = [col[1] for col in table_info]
        columns_to_add = []
        
        if 'admin_approval' not in column_names:
            columns_to_add.append('admin_approval INTEGER')
            print("Missing: admin_approval column")
        
        if 'rejection_reason' not in column_names:
            columns_to_add.append('rejection_reason TEXT')
            print("Missing: rejection_reason column")
        
        if 'preferred_session' not in column_names:
            columns_to_add.append('preferred_session TEXT')
            print("Missing: preferred_session column")
        
        if 'additional_remarks' not in column_names:
            columns_to_add.append('additional_remarks TEXT')
            print("Missing: additional_remarks column")
        
        if columns_to_add:
            print(f"Adding {len(columns_to_add)} missing columns to attendance table...")
            for column_def in columns_to_add:
                try:
                    column_name = column_def.split()[0]
                    conn.execute(f'ALTER TABLE attendance ADD COLUMN {column_def}')
                    print(f"✅ Added: {column_name}")
                except Exception as e:
                    print(f"⚠️ Could not add {column_name}: {e}")
            
            conn.commit()
            print("All missing columns added successfully!")
        else:
            print("✅ All required columns present!")
        
    except Exception as e:
        print(f"Error checking table structure: {e}")
    finally:
        conn.close()

# Call this function after init_db()
init_db()
check_attendance_table_structure()  # Add this line

@app.route('/admin/delete-attendance/<int:attendance_id>', methods=['POST'])
@admin_required
def delete_attendance(attendance_id):
    try:
        conn = get_db_connection()
        conn.execute('DELETE FROM attendance WHERE id = ?', (attendance_id,))
        conn.commit()
        conn.close()
        
        flash('Attendance record deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting attendance: {str(e)}', 'error')
    
    return redirect(url_for('admin_attendance'))

@app.route('/admin/class/<int:class_id>/notes', methods=['POST'])
@admin_required
def add_class_notes(class_id):
    """Add or update admin notes for a class"""
    admin_notes = request.form.get('admin_notes', '').strip()
    
    try:
        conn = get_db_connection()
        
        # Verify the class exists
        existing_class = conn.execute(
            'SELECT id FROM class_schedule WHERE id = ?',
            (class_id,)
        ).fetchone()
        
        if not existing_class:
            flash('Class not found.', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        # Update the class with notes
        conn.execute(
            'UPDATE class_schedule SET admin_notes = ? WHERE id = ?',
            (admin_notes, class_id)
        )
        conn.commit()
        conn.close()
        
        flash('Admin notes updated successfully!', 'success')
    except Exception as e:
        flash(f'Error updating notes: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))


# Route to approve alternative date proposed by student/parent
@app.route('/admin/attendance/<int:attendance_id>/approve', methods=['POST'])
@admin_required
def approve_alternative_date(attendance_id):
    """Approve an alternative date proposed by a student/parent"""
    print(f"\n=== APPROVE ALTERNATIVE DATE ===")
    print(f"Attendance ID: {attendance_id}")
    
    try:
        # ✅ CSRF validation ✅ FIXED
        csrf_token = request.form.get('csrf_token')
        if not csrf_token:
            flash('Invalid request. Missing CSRF token.', 'danger')
            return redirect(url_for('admin_attendance'))

        try:
            validate_csrf(csrf_token)  # Proper validation
            print("CSRF validation passed")
        except CSRFError as e:
            flash('Invalid CSRF token. Please try again.', 'danger')
            return redirect(url_for('admin_attendance'))
        
        conn = get_db_connection()
        
        
        # Get the attendance record with student info
        record = conn.execute('''
            SELECT a.*, u.email, u.full_name
            FROM attendance a
            JOIN users u ON a.user_id = u.id
            WHERE a.id = ?
        ''', (attendance_id,)).fetchone()
        
        if not record:
            flash('Attendance record not found.', 'danger')
            conn.close()
            return redirect(url_for('admin_attendance'))
        
        print(f"Record found: {dict(record)}")
        
        # Verify this is an alternative date proposal
        if record['can_attend'] != 2:
            flash('This is not an alternative date proposal.', 'warning')
            conn.close()
            return redirect(url_for('admin_attendance'))
        
        # Update approval status to 1 (approved)
        conn.execute('''
            UPDATE attendance 
            SET admin_approval = 1, 
                updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (attendance_id,))
        
        conn.commit()
        
        # Get updated record for verification
        updated_record = conn.execute('''
            SELECT * FROM attendance WHERE id = ?
        ''', (attendance_id,)).fetchone()
        
        print(f"Updated record: {dict(updated_record)}")
        
        # TODO: Add email notification here
        # Example: send_approval_email(record['email'], record['full_name'], record['alternative_date'])
        
        student_name = record['full_name']
        alternative_date = record['alternative_date']
        
        conn.close()
        
        flash(f'✅ Alternative date ({alternative_date}) approved for {student_name}!', 'success')
        
    except Exception as e:
        print(f"Error approving alternative date: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Error approving alternative date: {str(e)}', 'danger')
    
    return redirect(url_for('admin_attendance'))

# Route to reject alternative date with optional reason

@app.route('/admin/attendance/<int:attendance_id>/reject', methods=['POST'])
@admin_required
def reject_alternative_date(attendance_id):
    """Reject an alternative date proposed by a student/parent"""
    print(f"\n=== REJECT ALTERNATIVE DATE ===")
    print(f"Attendance ID: {attendance_id}")
    
    rejection_reason = request.form.get('rejection_reason', '').strip()
    print(f"Rejection reason: {rejection_reason}")
    
    try:
        # ✅ CSRF validation
        csrf_token = request.form.get('csrf_token')
        if not csrf_token:
            flash('Invalid request. Missing CSRF token.', 'danger')
            return redirect(url_for('admin_attendance'))

        try:
            validate_csrf(csrf_token)  # Proper validation
            print("CSRF validation passed")
        except CSRFError as e:
            flash('Invalid CSRF token. Please try again.', 'danger')
            return redirect(url_for('admin_attendance'))  # MOVE THIS INSIDE THE EXCEPT BLOCK
            
        conn = get_db_connection()
        
        # Get the attendance record with student info
        record = conn.execute('''
            SELECT a.*, u.email, u.full_name
            FROM attendance a
            JOIN users u ON a.user_id = u.id
            WHERE a.id = ?
        ''', (attendance_id,)).fetchone()
        
        if not record:
            flash('Attendance record not found.', 'danger')
            conn.close()
            return redirect(url_for('admin_attendance'))
        
        print(f"Record found: {dict(record)}")
        
        # Verify this is an alternative date proposal
        if record['can_attend'] != 2:
            flash('This is not an alternative date proposal.', 'warning')
            conn.close()
            return redirect(url_for('admin_attendance'))
        
        # Update approval status to 0 (rejected)
        conn.execute('''
            UPDATE attendance 
            SET admin_approval = 0, 
                rejection_reason = ?, 
                updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (rejection_reason, attendance_id))
        
        # Sync rejection_reason to alternative_proposals so calendar view stays consistent
        if rejection_reason:
            conn.execute('''
                UPDATE alternative_proposals 
                SET status = 'rejected',
                    rejection_reason = ?
                WHERE attendance_id = ?
            ''', (rejection_reason, attendance_id))
        
        conn.commit()
        
        # Get updated record for verification
        updated_record = conn.execute('''
            SELECT * FROM attendance WHERE id = ?
        ''', (attendance_id,)).fetchone()
        
        print(f"Updated record: {dict(updated_record)}")
        
        # TODO: Add email notification here
        # Example: send_rejection_email(record['email'], record['full_name'], rejection_reason)
        
        student_name = record['full_name']
        
        conn.close()
        
        if rejection_reason:
            flash(f'❌ Alternative date rejected for {student_name}. Reason: {rejection_reason}', 'warning')
        else:
            flash(f'❌ Alternative date rejected for {student_name}.', 'warning')
        
    except Exception as e:
        print(f"Error rejecting alternative date: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Error rejecting alternative date: {str(e)}', 'danger')
    
    return redirect(url_for('admin_attendance'))
# Debug routes
@app.route('/test-data')
def test_data():
    """Test if data exists in database"""
    conn = get_db_connection()
    
    users_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    classes_count = conn.execute('SELECT COUNT(*) FROM class_schedule').fetchone()[0]
    achievements_count = conn.execute('SELECT COUNT(*) FROM student_achievements').fetchone()[0]
    class_students_count = conn.execute('SELECT COUNT(*) FROM class_students').fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'users_count': users_count,
        'classes_count': classes_count,
        'achievements_count': achievements_count,
        'class_students_count': class_students_count,
        'database_file': 'multimaker.db'
    })

@app.route('/admin/approve-user/<int:user_id>', methods=['POST'])
@admin_required
def approve_user(user_id):
    conn = get_db_connection()
    conn.execute(
        'UPDATE users SET is_approved = 1 WHERE id = ?',
        (user_id,)
    )
    conn.commit()
    conn.close()
    
    flash('User approved successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject-user/<int:user_id>', methods=['POST'])
@admin_required
def reject_user(user_id):
    current_user = get_current_user()
    
    # Prevent self-rejection
    if user_id == current_user['id']:
        flash('You cannot reject your own account.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    
    # Delete user's achievements first
    conn.execute('DELETE FROM student_achievements WHERE user_id = ?', (user_id,))
    # Delete user's class enrollments
    conn.execute('DELETE FROM class_students WHERE user_id = ?', (user_id,))
    # Delete the user
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    
    conn.commit()
    conn.close()
    
    flash('User rejected and deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/test-admin')
def test_admin():
    """Test if admin user exists"""
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone()
    conn.close()
    
    if admin:
        return jsonify({
            'admin_exists': True,
            'admin_data': dict(admin)
        })
    else:
        return jsonify({'admin_exists': False})

from database import admin_reset_password  # add to your imports

@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
def reset_user_password(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Admin access required.', 'danger')
        return redirect(url_for('login'))
    
    new_password = request.form.get('new_password')
    
    if not new_password or len(new_password) < 4:
        flash('Password must be at least 4 characters.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    user = get_user_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    if admin_reset_password(user_id, new_password):
        flash(f'Password reset successful for {user["full_name"]}. New password: {new_password}', 'success')
    else:
        flash('Failed to reset password.', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.before_request
def initialize_database():
    """Initialize database tables before each request."""
    try:
        
        create_attendance_table_if_needed()
    except Exception as e:
        print(f"Database initialization error (non-critical): {e}")

if __name__ == '__main__':
    app.run(debug=True)
