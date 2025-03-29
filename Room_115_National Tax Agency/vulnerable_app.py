from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('agency.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS taxpayers
                 (id INTEGER PRIMARY KEY, name TEXT, tax_due REAL)''')
    c.execute("INSERT OR IGNORE INTO taxpayers (id, name, tax_due) VALUES (1, 'John Doe', 1000.00)")
    c.execute("INSERT OR IGNORE INTO taxpayers (id, name, tax_due) VALUES (2, 'Jane Smith', 2000.00)")
    c.execute("INSERT OR IGNORE INTO taxpayers (id, name, tax_due) VALUES (99, 'Congratulations', 0.00)")
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template_string('''
    <!doctype html>
    <html>
    <head>
        <title>National Tax Agency</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
            .container { width: 80%; margin: auto; overflow: hidden; }
            header { background: #50b3a2; color: #ffffff; padding-top: 30px; min-height: 70px; border-bottom: #e8491d 3px solid; }
            header a { color: #ffffff; text-decoration: none; text-transform: uppercase; font-size: 16px; }
            header ul { margin: 0; padding: 0; }
            header li { float: left; display: inline; padding: 0 20px 0 20px; }
            header #branding { float: left; }
            header #branding h1 { margin: 0; }
            header nav { float: right; margin-top: 10px; }
            #showcase { min-height: 400px; background: url('https://via.placeholder.com/1200x400') no-repeat center; text-align: center; color: #ffffff; }
            #showcase h1 { margin-top: 100px; font-size: 55px; margin-bottom: 10px; }
            form { background: #ffffff; padding: 20px; margin-top: 20px; }
            input[type="text"] { width: 100%; padding: 5px; }
            input[type="submit"] { display: block; width: 100%; padding: 10px; background: #e8491d; color: #ffffff; border: 0; }
            footer { background: #50b3a2; color: #ffffff; text-align: center; padding: 20px; margin-top: 20px; }
        </style>
    </head>
    <body>
      <header>
        <div class="container">
          <div id="branding">
            <h1>National Tax Agency</h1>
          </div>
          <nav>
            <ul>
              <li><a href="/">Home</a></li>
            </ul>
          </nav>
        </div>
      </header>
    
      <section id="showcase">
        <div class="container">
          <h1>Your Taxes, Our Priority</h1>
          <p>Access your tax records securely and efficiently.</p>
        </div>
      </section>
    
      <div class="container">
        <form action="/search" method="post">
          <label for="tax_id">Enter your Taxpayer ID:</label>
          <input type="text" id="tax_id" name="tax_id" required>
          <input type="submit" value="Search">
        </form>
      </div>
    
      <footer>
        <p>National Tax Agency &copy; 2023</p>
      </footer>
    </body>
    </html>
    ''')

@app.route('/search', methods=['POST'])
def search():
    tax_id = request.form['tax_id']
    conn = sqlite3.connect('agency.db')
    c = conn.cursor()
    # Vulnerable SQL query (do not use this in production!)
    query = "SELECT * FROM taxpayers WHERE id = %s" % tax_id
    try:
        c.execute(query)
        result = c.fetchone()
        if result and result[1] == 'Congratulations':
            return render_template_string('''
            <!doctype html>
            <html>
            <head><title>Congratulations</title></head>
            <body>
                <h1>Congratulations!</h1>
                <p>You have successfully exploited the SQL Injection vulnerability.</p>
            </body>
            </html>
            ''')
        elif result:
            return render_template_string('''
            <!doctype html>
            <html>
            <head><title>Search Results</title></head>
            <body>
                <h1>Search Results</h1>
                <p><strong>ID:</strong> {{id}}</p>
                <p><strong>Name:</strong> {{name}}</p>
                <p><strong>Tax Due:</strong> ${{tax_due}}</p>
            </body>
            </html>
            ''', id=result[0], name=result[1], tax_due=result[2])
        else:
            return render_template_string('''
            <!doctype html>
            <html>
            <head><title>No Results Found</title></head>
            <body>
                <h1>No Results Found</h1>
                <p>No taxpayer found with that ID.</p>
            </body>
            </html>
            ''')
    except Exception as e:
        return render_template_string('''
        <!doctype html>
        <html>
        <head><title>Error</title></head>
        <body>
            <h1>Error</h1>
            <p>An error occurred: {{error}}</p>
        </body>
        </html>
        ''', error=str(e))
    finally:
        conn.close()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)