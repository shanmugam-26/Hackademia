from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)

# Intentionally misconfigured application settings for demonstration purposes (Security Misconfiguration vulnerability)
app.config['DEBUG'] = True  # Debug mode enabled in production (vulnerability!)
app.config['SECRET_KEY'] = 'insecure_default_key'  # Hardcoded secret

# Main route: Social Media Platform cover page
@app.route("/")
def index():
    # HTML content using Bootstrap 5 from CDN
    html = """
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>MyConnect - The Future of Social Interaction</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {
                background: linear-gradient(to right, #003973, #E5E5BE);
                color: #333;
            }
            .cover {
                min-height:100vh;
                display:flex;
                flex-direction:column;
                justify-content:center;
                align-items:center;
            }
            .card {
                border: none;
                border-radius: 1rem;
                box-shadow: 0 8px 16px rgba(0,0,0,0.3);
            }
            footer {
                margin-top: 2rem;
            }
        </style>
      </head>
      <body>
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
          <div class="container-fluid">
            <a class="navbar-brand" href="#">MyConnect</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
              <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
              <ul class="navbar-nav ms-auto">
                <li class="nav-item">
                  <a class="nav-link active" aria-current="page" href="#">Home</a>
                </li>
                <li class="nav-item">
                  <a class="nav-link" href="#">Features</a>
                </li>
                <li class="nav-item">
                  <a class="nav-link" href="#">About Us</a>
                </li>
              </ul>
            </div>
          </div>
        </nav>
        <div class="cover container text-center mt-5">
          <div class="card p-4 col-md-8">
            <h1 class="mb-3">Welcome to MyConnect!</h1>
            <p class="lead">MyConnect is your safe haven to explore and network while testing your skills, ideas,
               and strategies in an authentic, simulated social media environment. Whether you're a seasoned security professional 
               or an eager coder, immerse yourself in a platform built at the intersection of innovation and challenge.</p>
            <p>Explore features, discover hidden paths, and most importantly, put your expertise to the ultimate test. 
               There’s more than meets the eye – sometimes a little dig beneath the surface reveals secrets meant only for the keenest minds.</p>
            <hr>
            <p class="small text-muted">Note: Some portions of our infrastructure are intentionally misconfigured to serve as training grounds.
               Find them, exploit them, and earn your bragging rights in the cybersecurity community.</p>
          </div>
        </div>
        <footer class="text-center text-light">
          &copy; 2023 MyConnect. All rights reserved.
        </footer>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
      </body>
    </html>
    """
    return render_template_string(html)

# Vulnerable route to demonstrate Security Misconfiguration vulnerability.
# This endpoint exposes sensitive app configuration details without any authentication.
@app.route("/admin/config")
def admin_config():
    # In a secure environment, these details would NEVER be exposed.
    config_data = { key: app.config.get(key) for key in app.config }
    # If the attacker passes the query parameter exploit=true, we display a congratulations prompt.
    exploit = request.args.get("exploit", "false").lower()
    if exploit == "true":
        message = "<br><div class='alert alert-success mt-3 text-center'>Congratulations, you exploited a real security misconfiguration vulnerability!</div>"
    else:
        message = ""
    html = """
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <title>Admin Config - MyConnect</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
      </head>
      <body>
        <div class="container mt-5">
          <h1>Admin Configuration Data</h1>
          <pre>{config}</pre>
          {message}
          <p class="mt-3"><small>This endpoint should not be publicly accessible. (Intentional misconfiguration for training purposes.)</small></p>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
      </body>
    </html>
    """.format(config=jsonify(config_data).get_data(as_text=True), message=message)
    return html

if __name__ == "__main__":
    # Run the flask app. Note: This should not be used in production.
    app.run(host="0.0.0.0", port=500)