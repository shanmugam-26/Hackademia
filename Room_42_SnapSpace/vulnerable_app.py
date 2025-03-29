from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def home():
    landing_page = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SnapSpace</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      background-color: #f8f9fa;
    }
    .cover-container {
      max-width: 42em;
      margin: auto;
      padding: 50px 0;
      text-align: center;
    }
    .inner {
      padding: 20px;
    }
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-light bg-white border-bottom">
    <div class="container-fluid">
      <a class="navbar-brand fw-bold" href="/">SnapSpace</a>
    </div>
  </nav>

  <div class="cover-container">
    <h1 class="display-4 fw-bold">Welcome to SnapSpace</h1>
    <p class="lead">Connect with friends and share your life moments here!</p>
    <div class="inner">
      <form method="POST" action="/profile">
        <div class="mb-3">
          <label for="username" class="form-label">Sign in or Register</label>
          <input type="text" class="form-control" id="username" name="username" placeholder="Enter a username">
        </div>
        <button type="submit" class="btn btn-primary">Proceed</button>
      </form>
    </div>
  </div>
</body>
</html>
"""
    return landing_page

@app.route('/profile', methods=['POST'])
def profile():
    user_input = request.form.get("username", "")
    template = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SnapSpace - Profile</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {{
      background-color: #f8f9fa;
    }}
    .profile-container {{
      margin: 50px auto;
      max-width: 50em;
    }}
    .post-form {{
      margin-top: 30px;
    }}
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-light bg-white border-bottom">
    <div class="container-fluid">
      <a class="navbar-brand fw-bold" href="/">SnapSpace</a>
    </div>
  </nav>

  <div class="profile-container">
    <h1 class="my-4">Your Profile</h1>
    <div class="alert alert-info" role="alert">
      <strong>Hello, {0}!</strong> Tell your friends what's on your mind.
    </div>
    <form method="POST" action="/profile" class="post-form">
      <div class="mb-3">
        <label for="username" class="form-label">New Post</label>
        <input type="text" class="form-control" id="username" name="username" placeholder="Share your status...">
      </div>
      <button type="submit" class="btn btn-primary">Share</button>
    </form>
  </div>
</body>
</html>
""".format(user_input)

    rendered = render_template_string(template)

    # If user_input triggers certain content in the rendered template, show a special message.
    # For demonstration, if the user manages to produce '666' in the rendered page, display a secret alert.
    if "666" in rendered:
        rendered += """
<script>
  alert("Congratulations! You exploited the SSTI vulnerability!");
</script>
        """

    return rendered
if __name__ == "__main__":
      app.run(debug=True)