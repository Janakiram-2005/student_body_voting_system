from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
from flask_bcrypt import Bcrypt
import mysql.connector
import traceback

app = Flask(__name__)
app.secret_key = 'supersecretkey'
CORS(app)
bcrypt = Bcrypt(app)

# ------------------ DB Connection ------------------
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='janakiram2005',
        database='sbvs'
    )

# ------------------ HTML Routes ------------------
@app.route("/")
@app.route("/index.html")
def homepage():
    return render_template("index.html")

@app.route("/login")
def login():
    return render_template("login.html")

@app.route('/complaints.html')
def complaints_page():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT name, email, message FROM complaints")
    complaints = cursor.fetchall()
    return render_template('complaints.html', complaints=complaints)

@app.route('/submit_complaint', methods=['POST'])
def submit_complaint():
    name = request.form['name']
    email = request.form['email']
    message = request.form['message']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO complaints (name, email, message) VALUES (%s, %s, %s)", (name, email, message))
    conn.commit()
    conn.close()

    return jsonify({"status": "success", "message": "Complaint submitted successfully!"})

@app.route('/delete_complaint/<int:id>', methods=['POST'])
def delete_complaint(id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM complaints WHERE id = %s", (id,))
        conn.commit()
        conn.close()
        return '', 204  # No Content
    except Exception as e:
        print("Delete Error:", e)
        return 'Failed', 500



@app.route('/get_complaints')
def get_complaints():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, name, email, message FROM complaints")
        complaints = cursor.fetchall()
        conn.close()
        return jsonify(complaints)
    except Exception as e:
        print("Error:", e)
        return jsonify([])




# ------------------ Admin Login ------------------
@app.route("/adminlogin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin WHERE adminemail = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user:
            return render_template("admin_login.html", error="User not found")

        if bcrypt.check_password_hash(user[3], password):
            session['admin_logged_in'] = True
            session['admin_id'] = user[0]
            session['admin_name'] = user[1]
            return redirect(url_for("admin_dashboard"))
        else:
            return render_template("admin_login.html", error="Invalid credentials")

    return render_template("admin_login.html")

# ------------------ Admin Dashboard ------------------
@app.route("/admin_dashboard")
def admin_dashboard():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT c.canid, c.canname, c.candesc, COUNT(vh.candidate_id) AS vote_count
        FROM candidates c
        LEFT JOIN vote_history vh ON c.canid = vh.candidate_id
        GROUP BY c.canid
        ORDER BY vote_count DESC
    """)
    final_results = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin_dashboard.html", 
                           admin_name=session['admin_name'],
                           final_results=final_results)

# ------------------ Toggle Voting ------------------
@app.route("/toggle_voting", methods=["POST"])
def toggle_voting():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    status = request.form.get("status") or request.json.get("status")
    if not status:
        return jsonify({"error": "Missing status"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    if status == 'started':
        # New voting round: clear all votes and history
        cursor.execute("DELETE FROM votes")
        cursor.execute("DELETE FROM vote_history")
        cursor.execute("UPDATE voters SET has_voted = FALSE")
        cursor.execute("UPDATE settings SET voting_status = 'started', results_approved = FALSE WHERE id = 1")

    elif status == 'ended':
        # End voting and move votes to history
        cursor.execute("""
            INSERT INTO vote_history (voterreg, candidate_id)
            SELECT voterreg, candidate_id FROM votes
        """)
        cursor.execute("DELETE FROM votes")
        cursor.execute("UPDATE voters SET has_voted = FALSE")
        cursor.execute("UPDATE settings SET voting_status = 'ended' WHERE id = 1")

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'message': f'Voting {status}'})

@app.route('/calculate_final_results')
def calculate_final_results():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Get final votes
    cursor.execute("""
        SELECT c.canid, c.canname, c.candesc, COUNT(vh.candidate_id) AS final_votes
        FROM candidates c
        LEFT JOIN vote_history vh ON c.canid = vh.candidate_id
        GROUP BY c.canid
        ORDER BY final_votes DESC
    """)
    rows = cursor.fetchall()

    # Find max votes
    max_votes = max((r['final_votes'] for r in rows), default=0)
    for r in rows:
        r['is_winner'] = r['final_votes'] == max_votes and max_votes > 0

    # Get approval status
    cursor.execute("SELECT results_approved FROM settings WHERE id = 1")
    approved = cursor.fetchone()
    cursor.close()
    conn.close()

    return jsonify({
        "results": rows,
        "results_approved": approved["results_approved"] if approved else False
    })


# ------------------ Get Voting Status ------------------
@app.route("/get_voting_status")
def get_voting_status():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT voting_status FROM settings WHERE id = 1")
    status = cursor.fetchone()
    cursor.close()
    conn.close()
    return jsonify({"status": status['voting_status'] if status else "unknown"})

# ------------------ Final Results ------------------
@app.route('/get_final_results')
def get_final_results():
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",             # your actual username
            password="janakiram2005",  # your actual password
            database="sbvs"
        )
        cursor = conn.cursor()

        # Check if final results are approved
        cursor.execute("SELECT results_approved FROM settings WHERE id = 1")
        approved = cursor.fetchone()

        if approved and approved[0]:
            # Get the winner (most voted candidate)
            cursor.execute("""
                SELECT c.canname, c.candesc, COUNT(v.id) AS final_votes
                FROM candidates c
                LEFT JOIN votes v ON c.canid = v.candidate_id
                GROUP BY c.canid
                ORDER BY final_votes DESC
                LIMIT 1
            """)
            row = cursor.fetchone()
            if row:
                winner = {
                    "canname": row[0],
                    "candesc": row[1],
                    "final_votes": row[2]
                }
                # Note: return as a list under "results" for frontend compatibility
                return jsonify({ "approved": True, "results": [winner] })
            else:
                return jsonify({ "approved": True, "results": [] })
        else:
            return jsonify({ "approved": False })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({ "error": str(e) }), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()






# ------------------ Live Results ------------------
@app.route("/get_live_results", methods=["GET"])
def get_live_results():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT voting_status FROM settings WHERE id=1")
    status = cursor.fetchone()
    if not status or status["voting_status"] != "started":
        cursor.close()
        conn.close()
        return jsonify([])

    cursor.execute("""
        SELECT c.canid, c.canname, c.candesc, COUNT(v.candidate_id) as vote_count
        FROM candidates c
        LEFT JOIN votes v ON c.canid = v.candidate_id
        GROUP BY c.canid
        ORDER BY vote_count DESC
    """)
    results = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(results)

@app.route("/approve_results", methods=["POST"])
def approve_results():
    if 'admin_id' not in session:
        return jsonify({"error": "Unauthorized"}), 403
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)    

    # Set results_approved to 1 and update status to 'final_released'
    cursor.execute("UPDATE settings SET voting_status = 'final_released', results_approved = 1 WHERE id = 1")
    conn.commit()
    return jsonify({"message": "Results approved"}), 200


# ------------------ Voter Flow ------------------
@app.route("/verify")
def verify():
    return render_template("verify.html")

@app.route("/verify_voter", methods=["POST"])
def verify_voter():
    regno = request.form.get("regno")
    if not regno:
        return render_template("verify.html", error="Registration number required")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT voting_status FROM settings WHERE id = 1")
    status = cursor.fetchone()
    if not status or status['voting_status'] != 'started':
        cursor.close()
        conn.close()
        return render_template("verify.html", error="Voting is not active.")

    cursor.execute("SELECT * FROM voters WHERE voterreg = %s", (regno,))
    voter = cursor.fetchone()
    if not voter:
        cursor.close()
        conn.close()
        return render_template("verify.html", error="Voter not found")

    if voter["has_voted"]:
        cursor.close()
        conn.close()
        return render_template("verify.html", error="You have already voted")

    session['voter_verified'] = True
    session['voter_regno'] = regno

    cursor.execute("SELECT * FROM candidates")
    candidates = cursor.fetchall()

    cursor.close()
    conn.close()
    return render_template("voting.html", candidates=candidates)

@app.route("/submit_vote", methods=["POST"])
def submit_vote():
    if not session.get("voter_verified"):
        return redirect(url_for("verify"))

    voterreg = session.get("voter_regno")
    candidate_id = request.form.get("selected_candidate")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO votes (voterreg, candidate_id) VALUES (%s, %s)", (voterreg, candidate_id))
    cursor.execute("UPDATE voters SET has_voted = TRUE WHERE voterreg = %s", (voterreg,))
    conn.commit()
    cursor.close()
    conn.close()

    session.pop("voter_verified", None)
    session.pop("voter_regno", None)

    return render_template("thankyou.html")

# ------------------ Candidate Login ------------------
@app.route("/candidatelogin", methods=["GET", "POST"])
def candidate_login():
    if request.method == "POST":
        email = request.form.get("email").strip().lower()
        password = request.form.get("password")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM candidates WHERE LOWER(canemail) = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user:
            return render_template("candidate_login.html", error="User not found")

        if bcrypt.check_password_hash(user["canpassword"], password):
            session['candidate_logged_in'] = True
            session['candidate_id'] = user["canid"]
            session['candidate_name'] = user["canname"]
            return redirect(url_for("candidate_dashboard"))
        else:
            return render_template("candidate_login.html", error="Invalid credentials")

    return render_template("candidate_login.html")

@app.route("/candidate_dashboard")
def candidate_dashboard():
    if not session.get("candidate_logged_in"):
        return redirect(url_for("candidate_login"))

    candidate_id = session["candidate_id"]
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM candidates WHERE canid = %s", (candidate_id,))
    candidate = cursor.fetchone()

    cursor.execute("SELECT voting_status FROM settings WHERE id=1")
    st = cursor.fetchone()

    cursor.execute("""
        SELECT c.canid, c.canname, c.candesc, COUNT(vh.candidate_id) AS vote_count
        FROM candidates c
        LEFT JOIN vote_history vh ON c.canid = vh.candidate_id
        GROUP BY c.canid
        ORDER BY vote_count DESC
    """)
    final_results = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("candidate_dashboard.html",
                           candidate=candidate,
                           final_results=final_results if st["voting_status"] == 'ended' else [],
                           voting_status=st["voting_status"])

# ------------------ Logout Routes ------------------
@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/candidate_logout", methods=["POST"])
def candidate_logout():
    session.clear()
    return redirect("/candidatelogin")


# ------------------ Add Admin/Candidate/Voter ------------------
@app.route('/addadmin', methods=['POST'])
def add_admin():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO admin (adminname, adminemail, adminpassword, adminphno) VALUES (%s, %s, %s, %s)",
                   (data['adminname'], data['email'], hashed_password, data['phone']))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'message': 'Admin added successfully'})

@app.route('/addcandidates', methods=['POST'])
def add_candidates():
    data = request.get_json()
    required_fields = ['canname', 'canemail', 'password', 'canphno']
    if not all(data.get(field) for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    candesc = data.get('candesc', "No description provided")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO candidates (canname, canemail, canpassword, canphno, candesc) VALUES (%s, %s, %s, %s, %s)",
               (data['canname'], data['canemail'], hashed_password, data['canphno'], candesc))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'message': 'Candidate added successfully'})

@app.route("/addvoter", methods=["POST"])
def add_voter():
    data = request.get_json()
    voterreg = data.get("regno")
    if not voterreg:
        return jsonify({"error": "Missing registration number"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO voters (voterreg) VALUES (%s)", (voterreg,))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'message': 'Voter added successfully'})

# Add these new Flask routes after your candidate_dashboard route

# ------------------ Update Candidate Info ------------------
@app.route("/update_candidate_info", methods=["POST"])
def update_candidate_info():
    if not session.get("candidate_logged_in"):
        return redirect(url_for("candidate_login"))

    canid = session['candidate_id']
    name = request.form['canname']
    email = request.form['canemail']
    phone = request.form['canphno']
    desc = request.form['candesc']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE candidates
        SET canname=%s, canemail=%s, canphno=%s, candesc=%s
        WHERE canid=%s
    """, (name, email, phone, desc, canid))
    conn.commit()
    conn.close()
    return redirect(url_for("candidate_dashboard"))

# ------------------ Change Candidate Password ------------------
@app.route("/change_candidate_password", methods=["POST"])
def change_candidate_password():
    if not session.get("candidate_logged_in"):
        return redirect(url_for("candidate_login"))

    old_password = request.form['old_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    if new_password != confirm_password:
        return "Passwords do not match", 400

    canid = session['candidate_id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT canpassword FROM candidates WHERE canid=%s", (canid,))
    result = cursor.fetchone()

    if not result or not bcrypt.check_password_hash(result['canpassword'], old_password):
        return "Incorrect current password", 400

    hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    cursor.execute("UPDATE candidates SET canpassword=%s WHERE canid=%s", (hashed_new_password, canid))
    conn.commit()
    conn.close()
    return redirect(url_for("candidate_dashboard"))

# ------------------ Drop From Voting ------------------
@app.route("/drop_candidate", methods=["POST"])
def drop_candidate():
    if not session.get("candidate_logged_in"):
        return redirect(url_for("candidate_login"))

    canid = session['candidate_id']
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM candidates WHERE canid=%s", (canid,))
    cursor.execute("DELETE FROM votes WHERE candidate_id=%s", (canid,))
    cursor.execute("DELETE FROM vote_history WHERE candidate_id=%s", (canid,))

    conn.commit()
    conn.close()

    session.clear()
    return redirect(url_for("candidate_login"))

# from flask import request, jsonify
# import mysql.connector

@app.route('/check_candidate_email')
def check_candidate_email():
    email = request.args.get('email')
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT COUNT(*) FROM candidates WHERE canemail = %s"
    cursor.execute(query, (email,))
    count = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return jsonify({'exists': count > 0})

@app.route('/forgot_password')
def forgot_password():
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    role = data.get('role')
    name = data.get('name')
    new_pass = data.get('new_password')

    if not all([role, name, new_pass]):
        return jsonify({"message": "Missing fields"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if role == 'admin':
        table, name_col, pass_col, id_col = 'admin', 'adminname', 'adminpassword', 'adminid'
    elif role == 'candidate':
        table, name_col, pass_col, id_col = 'candidates', 'canname', 'canpassword', 'canid'
    else:
        return jsonify({"message": "Invalid role"}), 400

    cursor.execute(f"SELECT {id_col} FROM {table} WHERE {name_col} = %s", (name,))
    row = cursor.fetchone()
    if not row:
        return jsonify({"message": "Name not found. Check spelling."}), 404

    hashed = bcrypt.generate_password_hash(new_pass).decode('utf-8')
    cursor.execute(f"UPDATE {table} SET {pass_col} = %s WHERE {id_col} = %s", (hashed, row[id_col]))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Password reset success!"})

@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ------------------ Run App ------------------
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
