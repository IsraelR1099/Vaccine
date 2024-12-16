from flask import Flask, request, render_template
import psycopg2

app = Flask(__name__)

# Database connection details
DB_HOST = "db"
DB_NAME = "test_db"
DB_USER = "postgres"
DB_PASSWORD = "test"

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASSWORD
    )

@app.route("/")
def home():
    return "<h1>Welcome to the Vulnerable Website</h1><p>Visit <a href='/login'>Login</a></p>"

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # **Vulnerable Query (Directly includes user input)**
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute(query)
            user = cur.fetchone()
        except Exception as e:
            return f"<p>Error: {e}</p>"

        conn.close()

        if user:
            return f"<h2>Welcome, {user[1]}</h2>"
        else:
            return "<p>Invalid username or password</p>"

    return '''
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

