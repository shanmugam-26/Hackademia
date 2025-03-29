from flask import Flask, request, redirect, render_template_string

app = Flask(__name__)

@app.route('/')
def home():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Helping Hands Nonprofit Organization</title>
    <!-- Include Bootstrap CSS from CDN -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1 class="mt-5">Welcome to Helping Hands</h1>
        <p class="lead">Your generosity makes a difference!</p>
        <p><a href="/donate" class="btn btn-success btn-lg">Donate Now</a></p>
    </div>
</body>
</html>
''')

@app.route('/donate')
def donate():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Donate to Helping Hands</title>
    <!-- Include Bootstrap CSS from CDN -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1 class="mt-5">Donate to Helping Hands</h1>
        <p class="lead">Thank you for your support!</p>
        <form action="/process_donation" method="post">
            <div class="form-group">
                <label for="amount">Donation Amount ($)</label>
                <input type="number" class="form-control" id="amount" name="amount" min="1" required>
            </div>
            <input type="hidden" name="redirect_url" value="{{ request.args.get('redirect_url') }}">
            <button type="submit" class="btn btn-primary">Donate</button>
        </form>
    </div>
</body>
</html>
''')

@app.route('/process_donation', methods=['POST'])
def process_donation():
    amount = request.form.get('amount')
    redirect_url = request.form.get('redirect_url')
    # Simulate processing the donation
    # For demonstration purposes, we'll skip actual processing
    if redirect_url:
        return redirect(redirect_url)
    else:
        return redirect('/thank_you')

@app.route('/thank_you')
def thank_you():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Thank You!</title>
    <!-- Include Bootstrap CSS from CDN -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1 class="mt-5">Thank You for Your Donation!</h1>
        <p class="lead">Your support helps us make a difference.</p>
        <a href="/" class="btn btn-secondary">Return to Home</a>
    </div>
</body>
</html>
''')

@app.route('/redirect')
def unsafe_redirect():
    url = request.args.get('url')
    if url:
        # Unvalidated redirect vulnerability
        return redirect(url)
    else:
        return redirect('/')

@app.route('/congrats')
def congrats():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
    <!-- Include Bootstrap CSS from CDN -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body {
            background-color: #e9f7ef;
        }
        .congrats {
            text-align: center;
            margin-top: 100px;
        }
        .congrats h1 {
            font-size: 3rem;
            color: #28a745;
        }
    </style>
</head>
<body>
    <div class="container congrats">
        <h1>Congratulations!</h1>
        <p class="lead">You have successfully exploited the vulnerability.</p>
        <a href="/" class="btn btn-success">Return to Home</a>
    </div>
</body>
</html>
''')
if __name__ == '__main__':
    app.run(debug=True)