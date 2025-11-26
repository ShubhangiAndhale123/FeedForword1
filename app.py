import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# --- Flask App Setup ---
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # IMPORTANT: Change this for production
DATABASE = 'database.db'

# --- Database Functions ---
def get_db():
    """Connects to the specific database."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # This allows accessing columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Creates the necessary tables if they don't exist."""
    with app.app_context():
        db = get_db()
        # Updated Users table with 'vehicle' for Volunteers
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                location TEXT,
                license TEXT,
                vehicle TEXT  -- NEW: Vehicle info for Volunteers
            )
        """)
        # NEW TABLE: Donations
        db.execute("""
            CREATE TABLE IF NOT EXISTS donations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider_id INTEGER NOT NULL,
                food_type TEXT NOT NULL,
                quantity TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                pickup_location TEXT NOT NULL,
                notes TEXT,
                status TEXT NOT NULL, -- e.g., 'Pending', 'Claimed', 'Completed'
                volunteer_id INTEGER,
                FOREIGN KEY (provider_id) REFERENCES users(id),
                FOREIGN KEY (volunteer_id) REFERENCES users(id)
            )
        """)
        db.commit()

# --- Role-Based Access Control Decorator ---
def role_required(role):
    """Decorator to restrict access to a route based on user role."""
    def decorator(f):
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if session.get('role') != role:
                # Redirect if user tries to access a dashboard for a different role
                return redirect(url_for('index', error="Access Denied"))
            return f(*args, **kwargs)
        # Fix for Flask endpoint name collision
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

# --- Utility: Redirection based on Role ---
def get_dashboard_url(role):
    """Returns the correct dashboard URL based on the user's role."""
    if role == 'admin':
        return url_for('dashboard_admin')
    elif role == 'provider':
        return url_for('dashboard_provider')
    elif role == 'volunteer':
        return url_for('dashboard_volunteer')
    else:
        return url_for('index')

# --- PUBLIC ROUTES ---

@app.route('/')
def index():
    # Retrieve success message from registration, if present
    success_message = request.args.get('success_message')
    return render_template('index.html', success_message=success_message)

@app.route('/about-contact.html')
def about_contact():
    return render_template('about-contact.html')

# --- AUTHENTICATION ROUTES ---

@app.route('/register.html', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # 1. Get form data
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        location = request.form.get('location')  # Provider field
        license = request.form.get('license')    # Provider field
        vehicle = request.form.get('vehicle')    # Volunteer field (optional)
        
        # 2. Hash the password for secure storage
        password_hash = generate_password_hash(password)
        
        db = get_db()
        try:
            # 3. Insert new user into the database
            db.execute(
                "INSERT INTO users (name, email, password_hash, role, location, license, vehicle) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (name, email, password_hash, role, location, license, vehicle)
            )
            db.commit()
            
            # 4. Registration successful, redirect to INDEX (Home Page)
            # Pass a success message to the index route
            return redirect(url_for('index', success_message="Registration successful! Please log in."))
            
        except sqlite3.IntegrityError:
            return render_template('register.html', error="This email is already registered. Please login.")
            
        except Exception as e:
            return render_template('register.html', error=f"An error occurred: {e}")
            
    return render_template('register.html')

@app.route('/login.html', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_username = request.form['email']
        password = request.form['password']

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ?", (email_or_username,)
        ).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            # Successful login
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['name'] = user['name']

            # Redirect to the appropriate dashboard
            return redirect(get_dashboard_url(user['role']))
        else:
            return render_template('login.html', error="Invalid email or password.")

    return render_template('login.html')

@app.route('/logout')
def logout():
    # Remove user information from the session
    session.clear()
    return redirect(url_for('index'))

# --- DASHBOARD & APPLICATION ROUTES ---

# 1. Provider Dashboard Logic
@app.route('/dashboard-provider.html', methods=['GET', 'POST'])
@role_required('provider')
def dashboard_provider():
    db = get_db()
    provider_id = session['user_id']
    
    if request.method == 'POST':
        # Handle new donation submission
        food_type = request.form['foodType']
        quantity = request.form['quantity']
        expires_at = request.form['expiresAt']
        pickup_location = request.form['pickupLocation']
        notes = request.form['notes']
        
        db.execute(
            """INSERT INTO donations 
               (provider_id, food_type, quantity, expires_at, pickup_location, notes, status) 
               VALUES (?, ?, ?, ?, ?, ?, 'Pending')""",
            (provider_id, food_type, quantity, expires_at, pickup_location, notes)
        )
        db.commit()
        return redirect(url_for('dashboard_provider'))
        
    # Handle GET request: Display recent posts
    recent_donations = db.execute(
        "SELECT * FROM donations WHERE provider_id = ? ORDER BY id DESC", (provider_id,)
    ).fetchall()
    
    return render_template('dashboard-provider.html', donations=recent_donations, user=session)

# 2. Admin Dashboard Logic
# @app.route('/dashboard-admin.html')
# @role_required('admin')
# def dashboard_admin():
#     db = get_db()
    
#     donations = db.execute("""
#         SELECT 
#             d.*, 
#             p.name AS provider_name, 
#             p.location AS provider_location,
#             v.name AS volunteer_name
#         FROM donations d
#         JOIN users p ON d.provider_id = p.id
#         LEFT JOIN users v ON d.volunteer_id = v.id
#         WHERE d.status IN ('Pending', 'Claimed')
#         ORDER BY d.expires_at ASC
#     """).fetchall()
    
#     volunteers = db.execute(
#         "SELECT id, name, vehicle FROM users WHERE role = 'volunteer'"
#     ).fetchall()
    
#     return render_template(
#         'dashboard-admin.html', 
#         donations=donations, 
#         volunteers=volunteers, 
#         user=session
#     )

# @app.route('/assign_volunteer/<int:donation_id>', methods=['POST'])
# @role_required('admin')
# def assign_volunteer(donation_id):
#     db = get_db()
#     volunteer_id = request.form['volunteer_id']
    
#     db.execute(
#         "UPDATE donations SET volunteer_id = ?, status = 'Claimed' WHERE id = ?",
#         (volunteer_id, donation_id)
#     )
#     db.commit()
#     return redirect(url_for('dashboard_admin'))

#3. Volunteer Dashboard Logic
@app.route('/dashboard-volunteer.html')
@role_required('volunteer')
def dashboard_volunteer():
    db = get_db()
    volunteer_id = session['user_id']
    
    

# Available pickups: donations assigned to this volunteer but not yet claimed/completed
    available_pickups = db.execute("""
        SELECT d.*, p.name AS provider_name
        FROM donations d
        JOIN users p ON d.provider_id = p.id
        WHERE d.volunteer_id = ? AND d.status = 'Pending'
        ORDER BY d.expires_at ASC
    """, (volunteer_id,)).fetchall()

    # Distribution status: donations claimed or completed by this volunteer
    my_pickups = db.execute("""
        SELECT d.*, p.name AS provider_name
        FROM donations d
        JOIN users p ON d.provider_id = p.id
        WHERE d.volunteer_id = ? AND d.status IN ('Claimed', 'Completed')
        ORDER BY d.expires_at ASC
    """, (volunteer_id,)).fetchall()

   
   
    return render_template(
        'dashboard-volunteer.html', 
        available_pickups=available_pickups, 
        my_pickups=my_pickups, 
        user=session
    )



@app.route('/claim_donation/<int:donation_id>', methods=['POST'])
@role_required('volunteer')
def claim_donation(donation_id):
    db = get_db()
    volunteer_id = session['user_id']

    db.execute("""
        UPDATE donations
        SET status = 'Claimed'
        WHERE id = ? AND volunteer_id = ? AND status = 'Pending'
    """, (donation_id, volunteer_id))
    db.commit()

    return redirect(url_for('dashboard_volunteer'))




@app.route('/complete_donation/<int:donation_id>', methods=['POST'])
@role_required('volunteer')
def complete_donation(donation_id):
    db = get_db()
    volunteer_id = session['user_id']
    # Update the donation status to Completed
    db.execute("""
        UPDATE donations
        SET status = 'Completed'
        WHERE id = ? AND volunteer_id = ?
    """, (donation_id, volunteer_id))
    db.commit()

    return redirect(url_for('dashboard_volunteer'))

# --- Volunteer Profile Management Route ---
@app.route('/volunteer-profile.html', methods=['GET', 'POST'])
@role_required('volunteer')
def volunteer_profile():
    db = get_db()
    user_id = session['user_id']
    message = None

    if request.method == 'POST':
        name = request.form['name']
        vehicle = request.form['vehicle']
        
        db.execute(
            "UPDATE users SET name = ?, vehicle = ? WHERE id = ?",
            (name, vehicle, user_id)
        )
        db.commit()
        
        session['name'] = name 
        message = "Profile updated successfully!"
        user_data = db.execute("SELECT name, email, vehicle FROM users WHERE id = ?", (user_id,)).fetchone()

    else:
        user_data = db.execute("SELECT name, email, vehicle FROM users WHERE id = ?", (user_id,)).fetchone()
        
    return render_template('volunteer-profile.html', user_data=user_data, user=session, message=message)

# 2. Admin Dashboard Logic
@app.route('/dashboard-admin.html')
@role_required('admin')
def dashboard_admin():
    db = get_db()
    message = request.args.get('message')  # <-- NEW: Fetch success message
    
    # Fetch all pending and claimed donations, including provider and volunteer details
    donations = db.execute("""
        SELECT 
            d.*, 
            p.name AS provider_name, 
            p.location AS provider_location,
            v.name AS volunteer_name,
            v.vehicle AS volunteer_vehicle  -- Fetch vehicle for context
        FROM donations d
        JOIN users p ON d.provider_id = p.id
        LEFT JOIN users v ON d.volunteer_id = v.id
        WHERE d.status IN ('Pending', 'Claimed')
        ORDER BY d.expires_at ASC
    """).fetchall()
    
    # Fetch all volunteers for assignment dropdowns (Volunteer list is here)
    volunteers = db.execute(
        "SELECT id, name, vehicle FROM users WHERE role = 'volunteer'"
    ).fetchall()

    providers = db.execute("""
        SELECT DISTINCT p.id, p.name 
        FROM donations d 
        JOIN users p ON d.provider_id = p.id
        ORDER BY p.name
    """).fetchall()
    
    return render_template(
        'dashboard-admin.html',
        donations=donations,
        volunteers=volunteers,
        providers=providers,
        user=session,
        message=message  # <-- NEW: Pass message to the template
    )

   

# In app.py
# Admin Action: Assign Volunteer
@app.route('/assign_volunteer/<int:donation_id>', methods=['POST'])
@role_required('admin')
def assign_volunteer(donation_id):
    db = get_db()
    volunteer_id = request.form['volunteer_id']

    db.execute("""
        UPDATE donations
        SET volunteer_id = ?
        WHERE id = ?
    """, (volunteer_id, donation_id))
    db.commit()

    return redirect(url_for('dashboard_admin', message="Volunteer assigned successfully!"))





# --- Main ---
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
