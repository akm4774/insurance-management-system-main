from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)
import psycopg2
from datetime import timedelta
from dotenv import load_dotenv
import os
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from flask import abort

load_dotenv()  # reads .env
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY not set in .env")

# Initialize Email Token Serializer
serializer = URLSafeTimedSerializer(SECRET_KEY)

def get_db_connection():
    # psycopg2 can take the full DATABASE_URL as a DSN
    return psycopg2.connect(DATABASE_URL)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.permanent_session_lifetime = timedelta(minutes=10)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name     = request.form['name']
        email    = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            flash('Email already registered—please log in.', 'warning')
            cur.close(); conn.close()
            return redirect(url_for('login'))

        # Insert new user with is_verified defaulting to FALSE.
        cur.execute(
            "INSERT INTO users (name, email, password, is_verified) VALUES (%s, %s, %s, FALSE)",
            (name, email, password)
        )
        conn.commit()
        
        # [EMAIL VERIFICATION START]
        # Generate a secure token for the user's email
        token = serializer.dumps(email, salt='email-confirm')
        # Generate confirmation URL (make sure your server is accessible externally or use localhost for testing)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        # Compose the email message using SendGrid
        from_email = os.getenv("MAIL_DEFAULT_SENDER")
        message = Mail(
            from_email=from_email,
            to_emails=email,
            subject='Please Confirm Your Email Address',
            html_content=f'''
                <p>Hello {name},</p>
                <p>Thank you for registering to our IMS website. Please click the link below to confirm your email address:</p>
                <p><a href="{confirm_url}">{confirm_url}</a></p>
                <p>This link will expire in one hour.</p>
            '''
        )
        try:
            sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
            sg.send(message)
            flash('Registration successful! A confirmation email has been sent.', 'info')
        except Exception as e:
            flash(f'Failed to send confirmation email: {str(e)}', 'warning')
        # [EMAIL VERIFICATION END]

        cur.close(); conn.close()
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        # The token expires in 3600 seconds (1 hour)
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
    except (SignatureExpired, BadSignature):
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur  = conn.cursor()
    cur.execute("UPDATE users SET is_verified = TRUE WHERE email = %s", (email,))
    conn.commit()
    cur.close(); conn.close()

    flash('Email confirmed! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email    = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute(
            "SELECT id, is_verified FROM users WHERE email=%s AND password=%s",
            (email, password)
        )
        user = cur.fetchone()
        cur.close(); conn.close()

        if user:
            # Check if the email is verified
            if not user[1]:
                flash('Email not verified. Please check your inbox.', 'warning')
                return redirect(url_for('login'))
            session['user_id'] = user[0]
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/add_policy', methods=['GET', 'POST'])
def add_policy():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        user_id        = session['user_id']
        policy_name    = request.form['policy_name']
        policy_type    = request.form['policy_type']
        premium_amount = request.form['premium_amount']

        conn = get_db_connection()
        cur  = conn.cursor()

        # Encrypt policy_name using pgcrypto 
        cur.execute( 
            """ 
            INSERT INTO policies 
              (user_id, policy_name, policy_type, premium_amount) 
            VALUES 
              (%s, 
               pgp_sym_encrypt(%s, %s), 
               %s, 
               %s) 
            """, 
            ( 
              user_id, 
              policy_name, 
              os.getenv("ENCRYPTION_KEY"), 
              policy_type, 
              premium_amount 
            ) 
        )
        conn.commit()
        cur.close(); conn.close()

        return redirect(url_for('view_policies'))

    return render_template('add_policy.html')

@app.route('/view_policies')
def view_policies():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cur  = conn.cursor()
    # Decrypt policy_name on the fly 
    cur.execute( 
        """ 
        SELECT 
          id, 
          pgp_sym_decrypt(policy_name, %s)::TEXT AS policy_name, 
          policy_type, 
          premium_amount 
        FROM policies 
        WHERE user_id = %s 
        """, 
        ( 
          os.getenv("ENCRYPTION_KEY"), 
          session['user_id'] 
        ) 
    )
    policies = cur.fetchall()
    cur.close(); conn.close()

    return render_template('view_policies.html', policies=policies)

@app.route('/add_claim', methods=['GET', 'POST'])
def add_claim():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cur  = conn.cursor()

    if request.method == 'POST':
        policy_id    = request.form['policy_id']
        claim_date   = request.form['claim_date']
        claim_amount = request.form['claim_amount']

        cur.execute(
            "INSERT INTO claims (policy_id, claim_date, claim_amount, status) VALUES (%s, %s, %s, %s)",
            (policy_id, claim_date, claim_amount, 'Pending')
        )
        conn.commit()
        cur.close(); conn.close()
        return redirect(url_for('view_claims'))

    # GET: load this user's policies for the dropdown
    cur.execute(
        "SELECT id, policy_name FROM policies WHERE user_id = %s",
        (session['user_id'],)
    )
    policies = cur.fetchall()
    cur.close(); conn.close()
    return render_template('add_claim.html', policies=policies)

@app.route('/view_claims')
def view_claims():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cur  = conn.cursor()
    cur.execute("""
        SELECT p.policy_name, c.claim_date, c.claim_amount, c.status
        FROM claims c
        JOIN policies p ON c.policy_id = p.id
        WHERE p.user_id = %s
    """, (session['user_id'],))
    claims = cur.fetchall()
    cur.close(); conn.close()

    return render_template('view_claims.html', claims=claims)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/chat') 
def chat(): 
    # Only logged‑in users can chat; adjust as needed 
    if 'user_id' not in session: 
        return redirect(url_for('login')) 
    return render_template('chat.html')

if __name__ == "__main__":
    app.run(debug=True)
