from flask import Flask, render_template_string

app = Flask(__name__)

# Simulated sensitive data
sensitive_data = {
    'admin_password': 'SuperSecretPassword123!',
    'user_emails': [
        'john.doe@example.com',
        'jane.smith@example.com',
        'alice.brown@example.com'
    ],
    'flag': 'Congratulations! You have found the sensitive data.'
}

# Homepage with the fashion brand
@app.route('/')
def home():
    page = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Fashionista - Trendy Fashion for Everyone</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
        <style>
            body {
                background-color: #f8f9fa;
            }
            .hero {
                background-image: url('https://source.unsplash.com/featured/?fashion');
                background-size: cover;
                background-position: center;
                height: 60vh;
                position: relative;
                color: white;
            }
            .hero-text {
                position: absolute;
                bottom: 20px;
                left: 20px;
            }
            .product-card {
                transition: transform 0.2s;
            }
            .product-card:hover {
                transform: scale(1.05);
            }
        </style>
    </head>
    <body>
        <!-- Navbar -->
        <nav class="navbar navbar-expand-lg navbar-light bg-light">
            <a class="navbar-brand" href="#">Fashionista</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"
                    aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item active">
                        <a class="nav-link" href="#">Home </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">Collections</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">Sale</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">Contact Us</a>
                    </li>
                </ul>
            </div>
        </nav>
        <!-- Hero Section -->
        <div class="hero">
            <div class="hero-text">
                <h1>Fall Collection 2023</h1>
                <p>Discover the trends</p>
                <a href="#" class="btn btn-primary">Shop Now</a>
            </div>
        </div>
        <!-- Products Section -->
        <div class="container mt-5">
            <h2>Best Sellers</h2>
            <div class="row">
                <!-- Example Product -->
                <div class="col-md-4">
                    <div class="card product-card">
                        <img src="https://source.unsplash.com/random/300x300?clothing" class="card-img-top" alt="Product">
                        <div class="card-body">
                            <h5 class="card-title">Stylish Jacket</h5>
                            <p class="card-text">$99.99</p>
                            <a href="#" class="btn btn-outline-primary">Buy Now</a>
                        </div>
                    </div>
                </div>
                <!-- More products can be added similarly -->
            </div>
        </div>
        <!-- Footer -->
        <footer class="bg-light p-3 text-center">
            &copy; 2023 Fashionista. All rights reserved.
        </footer>
        <!-- Intentionally left sensitive data (to simulate Sensitive Data Exposure vulnerability) -->
        <!-- TODO: Remove before deploying -->
        <script>
            var sensitiveData = {{ sensitive_data | tojson }};
            console.log(sensitiveData);
        </script>
    </body>
    </html>
    '''
    return render_template_string(page, sensitive_data=sensitive_data)
if __name__ == '__main__':
        app.run(debug=True)