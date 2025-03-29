from flask import Flask, render_template_string, request, abort, jsonify
import base64

app = Flask(__name__)

# Secret API key (this would normally be secure, but it's exposed)
API_KEY = 'SuperSecretAPIKey123!'

# Base64-encoded API key (embedded in client-side JavaScript)
encoded_api_key = base64.b64encode(API_KEY.encode('utf-8')).decode('utf-8')

# HTML template with modern CSS framework (e.g., Bootstrap)
index_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global Care Initiative</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- Modern CSS Framework (Bootstrap) -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        /* Custom Styles */
        body {
            font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
        }
        .hero {
            background-color: #f5f5f5;
            padding: 50px 0;
            text-align: center;
        }
        .hero h1 {
            font-size: 3.5rem;
            margin-bottom: 20px;
        }
        .hero p {
            font-size: 1.5rem;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <div class="container-fluid">
        <a class="navbar-brand" href="#">Global Care Initiative</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" 
          aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
        </button>
      </div>
    </nav>

    <!-- Hero Section -->
    <div class="hero">
        <div class="container">
            <h1>Empowering Communities Worldwide</h1>
            <p>Our mission is to provide resources and support to those in need.</p>
        </div>
    </div>

    <!-- Content -->
    <div class="container my-5">
        <h2>About Us</h2>
        <p>
            Global Care Initiative is a nonprofit organization dedicated to improving the lives of individuals
            and communities around the world through various outreach programs and sustainable development projects.
        </p>
    </div>

    <!-- Footer -->
    <footer class="bg-light text-center py-4">
        &copy; 2023 Global Care Initiative. All rights reserved.
    </footer>

    <!-- Modern JavaScript Frameworks -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Embedded JavaScript with exposed API key -->
    <script>
        // Encoded API key (should be kept secret)
        var encodedApiKey = "{{ encoded_api_key }}";
        // Function to decode and use the API key
        function accessSecretData() {
            var apiKey = atob(encodedApiKey);
            fetch('/api/secret-data', {
                method: 'GET',
                headers: {
                    'X-API-KEY': apiKey
                }
            })
            .then(response => response.json())
            .then(data => {
                console.log('Secret Data:', data);
            });
        }
        // Uncomment the line below to automatically fetch the secret data
        // accessSecretData();
    </script>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(index_html, encoded_api_key=encoded_api_key)

@app.route('/api/secret-data')
def secret_data():
    api_key = request.headers.get('X-API-KEY')
    if api_key == API_KEY:
        # Sensitive data exposure
        data = {
            'message': 'Congratulations! You have found the secret data.',
            'secret': 'The launch code is 12345.',
            'flag': 'FLAG{Sensitive_Data_Exposure_Unlocked}'
        }
        return jsonify(data)
    else:
        abort(403)
if __name__ == '__main__':
            app.run(debug=True)