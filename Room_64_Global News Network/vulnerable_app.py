from flask import Flask, render_template_string

app = Flask(__name__)

SENSITIVE_DATA = {
    'api_key': '12345-abcde-SECRET',
    'admin_password': 'P@ssw0rd!',
    'database_uri': 'postgres://user:pass@localhost:5432/dbname'
}

@app.route('/')
def index():
    html_content = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Global News Network</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<style>
/* Additional custom styles */
body {
    background-color: #f8f9fa;
}
.news-header {
    margin-top: 50px;
}
</style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <a class="navbar-brand" href="#">Global News Network</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" 
          aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>
</nav>
<div class="container news-header">
  <h1>Breaking News: AI Revolutionizes Tech Industry</h1>
  <p>In a stunning turn of events, artificial intelligence has taken the tech industry by storm, leading to unprecedented advancements.</p>
  <p>Stay tuned for more updates.</p>
</div>

<!-- Developer Notes: Remove sensitive info before deployment -->
<!--
API_KEY = "{{ sensitive_data['api_key'] }}"
ADMIN_PASSWORD = "{{ sensitive_data['admin_password'] }}"
DATABASE_URI = "{{ sensitive_data['database_uri'] }}"
-->

<script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.min.js"></script>
</body>
</html>
'''
    return render_template_string(html_content, sensitive_data=SENSITIVE_DATA)

@app.route('/congratulations')
def congratulations():
    return '''
    <!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Congratulations</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
<div class="container text-center" style="margin-top: 100px;">
  <h1>Congratulations!</h1>
  <p>You have successfully exploited the vulnerability and found the sensitive data.</p>
</div>
</body>
</html>
    '''
if __name__ == '__main__':
      app.run(debug=True, host='0.0.0.0', port=5000)