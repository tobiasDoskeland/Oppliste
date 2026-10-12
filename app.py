from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# SIKKERHET: Bruker en miljøvariabel hvis den finnes, ellers en fast nøkkel
app.secret_key = os.environ.get('SECRET_KEY', 'en_lang_tilfeldig_streng_12345')

# FINN DATABASEN: Lager en absolutt sti slik at serveren alltid finner fila
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "oppliste.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

# --- RUTER ---

@app.route('/')
def index():
    conn = get_db_connection()
    # Alle ser de samme dataene fra felles database
    leaderboard = conn.execute('SELECT * FROM PersonPoints ORDER BY total_points DESC').fetchall()
    conn.close()
    return render_template('index.html', personer=leaderboard)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)
        
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO User (username, password_hash, is_admin) VALUES (?, ?, ?)',
                         (username, hashed_pw, 0))
            conn.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Brukernavnet er allerede tatt!"
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM User WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            return redirect(url_for('index'))
        return "Feil brukernavn eller passord"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/person/<int:id>')
def person_details(id):
    conn = get_db_connection()
    person = conn.execute('SELECT * FROM Person WHERE ID = ?', (id,)).fetchone()
    logs = conn.execute('''
        SELECT l.*, u.username AS Gitt_av 
        FROM PointLog l 
        JOIN User u ON l.created_by = u.id 
        WHERE l.person_id = ? AND l.is_deleted = 0
        ORDER BY l.created_at DESC
    ''', (id,)).fetchall()
    conn.close()
    return render_template('detaljer.html', person=person, logs=logs)

@app.route('/add_points/<int:person_id>', methods=['POST'])
def add_points(person_id):
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    points = request.form['points']
    message = request.form['message']
    
    conn = get_db_connection()
    conn.execute('INSERT INTO PointLog (person_id, points, message, created_by) VALUES (?, ?, ?, ?)',
                 (person_id, points, message, session['user_id']))
    conn.commit()
    conn.close()
    return redirect(url_for('person_details', id=person_id))

@app.route('/add_person', methods=['POST'])
def add_person():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    name = request.form['name']
    conn = get_db_connection()
    conn.execute('INSERT INTO Person (Name) VALUES (?)', (name,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/delete_log/<int:log_id>')
def delete_log(log_id):
    if not session.get('is_admin'):
        return "Ingen tilgang", 403
    
    conn = get_db_connection()
    conn.execute('UPDATE PointLog SET is_deleted = 1 WHERE id = ?', (log_id,))
    conn.commit()
    conn.close()
    return redirect(request.referrer)

@app.route('/delete_person/<int:person_id>', methods=['POST'])
def delete_person(person_id):
    # Kun admin har tilgang
    if not session.get('is_admin'):
        return "Ingen tilgang", 403

    conn = get_db_connection()
    try:
        # 1. Slett alle poenglogger tilhørende denne personen
        conn.execute('DELETE FROM PointLog WHERE person_id = ?', (person_id,))
        # 2. Slett selve personen fra Person-tabellen
        conn.execute('DELETE FROM Person WHERE ID = ?', (person_id,))
        conn.commit()
    except Exception as e:
        print(f"Feil ved sletting: {e}")
    finally:
        conn.close()
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Debug er True her, men på en ekte server styres dette av server-softwaren
    app.run(debug=True)