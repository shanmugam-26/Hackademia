The provided Flask web application contains a **Reflected Cross-Site Scripting (XSS)** vulnerability. This vulnerability arises from the application’s handling of user-supplied input without proper sanitization or encoding, allowing attackers to inject and execute malicious scripts in the context of a user's browser.

### **Understanding the Vulnerability**

#### **Code Analysis:**

```python
search_query = request.args.get('q', '')
html_content = f'''
...
<input type="text" class="form-control" id="search" name="q" value="{search_query}">
...
{f'<p class="mt-3">You searched for: {search_query}</p>' if search_query else ''}
...
'''
```

1. **User Input Handling:**
   - The application retrieves the `q` parameter from the URL query string using `request.args.get('q', '')`.

2. **Dynamic HTML Generation:**
   - The `search_query` is directly interpolated into the HTML content using Python f-strings without any form of sanitization or encoding.
   - Specifically, it is inserted into the `value` attribute of an `<input>` element and conditionally rendered within a `<p>` tag.

#### **Exploitation Scenario:**

1. **Crafting Malicious Input:**
   - An attacker can manipulate the `q` parameter to include malicious JavaScript code. For example:
     ```
     https://vulnerable-app.com/?q=<script>alert('XSS')</script>
     ```

2. **Execution Flow:**
   - When a victim accesses the malicious URL, the application embeds the unsanitized `search_query` directly into the HTML.
   - The browser interprets the injected `<script>` tag, executing the JavaScript code.

3. **Potential Impacts:**
   - **Session Hijacking:** Stealing user session cookies.
   - **Phishing:** Redirecting users to malicious websites.
   - **Data Manipulation:** Altering the content displayed to users.
   - **Malware Distribution:** Forcing the download of malicious software.

### **Preventing Reflected XSS Vulnerabilities**

To safeguard against XSS attacks, developers should implement a combination of input validation, output encoding, and secure coding practices. Here's how to achieve this:

#### **1. Use Templating Engines with Auto-Escaping:**

Flask uses the Jinja2 templating engine by default, which auto-escapes variables to prevent XSS.

**Refactored Code Using Templates:**

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Grand Royal Hotel</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/5.3.0/css/bootstrap.min.css">
    <style>
        body {{
            background-image: url('https://images.unsplash.com/photo-1542314831-068cd1dbfeeb');
            background-size: cover;
            color: #fff;
        }}
        .background-overlay {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
        }}
        .content {{
            position: relative;
            z-index: 2;
        }}
    </style>
</head>
<body>
    <div class="background-overlay"></div>
    <div class="content container">
        <nav class="navbar navbar-expand-lg navbar-dark">
            <a class="navbar-brand" href="#">Grand Royal Hotel</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
        </nav>
        <div class="mt-5">
            <h1 class="display-4">Experience Luxury Like Never Before</h1>
            <p class="lead">Book your stay with us and enjoy world-class amenities.</p>
            <form class="mt-4" method="get" action="/">
                <div class="mb-3">
                    <label for="search" class="form-label">Search our site</label>
                    <input type="text" class="form-control" id="search" name="q" value="{{ search_query }}">
                </div>
                <button type="submit" class="btn btn-primary">Search</button>
            </form>
            {% if search_query %}
                <p class="mt-3">You searched for: {{ search_query }}</p>
            {% endif %}
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

@app.route('/')
def index():
    search_query = request.args.get('q', '')
    return render_template_string(HTML_TEMPLATE, search_query=search_query)
```

**Why This Helps:**
- **Auto-Escaping:** Jinja2 escapes special characters in variables, rendering `<script>` tags harmless by converting `<` and `>` to `&lt;` and `&gt;`.
- **Maintainability:** Using templates separates HTML structure from Python logic, enhancing code readability and maintainability.

#### **2. Input Validation and Sanitization:**

- **Whitelist Approach:** Define acceptable input patterns and reject anything that doesn't conform.
- **Length Restrictions:** Limit the length of input to prevent buffer overflows or excessive data processing.
- **Character Escaping:** Escape or remove characters that have special meanings in HTML, JavaScript, or SQL contexts.

**Example:**

```python
import html

@app.route('/')
def index():
    search_query = request.args.get('q', '')
    # Escape special HTML characters
    safe_search_query = html.escape(search_query)
    return render_template_string(HTML_TEMPLATE, search_query=safe_search_query)
```

#### **3. Content Security Policy (CSP):**

Implementing a CSP helps restrict the sources from which content can be loaded, mitigating the impact of XSS attacks.

**Example Using Flask-CSP Extension:**

```python
from flask import Flask
from flask_csp.csp import csp_header

app = Flask(__name__)

@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net;"
    return response
```

**Benefits:**
- **Restricts Script Sources:** Only allows scripts from trusted origins.
- **Prevents Inline Scripts:** Disallows inline JavaScript unless explicitly permitted.

#### **4. Avoid Direct String Concatenation for HTML Generation:**

Constructing HTML using string concatenation or f-strings bypasses the benefits of templating engines and increases the risk of injection vulnerabilities.

**Best Practice:**
- Always use Flask’s `render_template` or `render_template_string` with proper escaping instead of manual string manipulation.

#### **5. Use HTTPOnly and Secure Flags for Cookies:**

While not directly related to XSS, setting cookies with `HttpOnly` and `Secure` flags can mitigate the risk of session hijacking.

**Example:**

```python
from flask import Flask, make_response

app = Flask(__name__)

@app.route('/')
def index():
    resp = make_response(render_template_string(HTML_TEMPLATE, search_query=''))
    resp.set_cookie('session', 'value', httponly=True, secure=True)
    return resp
```

### **Summary of Best Practices:**

1. **Utilize Templating Engines Properly:**
   - Leverage Jinja2’s auto-escaping features.
   - Separate HTML from backend logic using templates.

2. **Validate and Sanitize All User Inputs:**
   - Implement strict input validation rules.
   - Sanitize inputs to remove or escape harmful characters.

3. **Implement Content Security Policies:**
   - Define and enforce CSP headers to control resource loading.

4. **Avoid Unsafe HTML Construction Methods:**
   - Refrain from using string concatenation or interpolation for HTML generation.

5. **Secure Cookie Handling:**
   - Use `HttpOnly` and `Secure` flags to protect session data.

6. **Regular Security Audits and Testing:**
   - Conduct periodic code reviews and penetration testing to identify and remediate vulnerabilities.

7. **Stay Informed and Updated:**
   - Keep abreast of security best practices and updates in frameworks and libraries.

By adhering to these practices, developers can significantly reduce the risk of XSS and other injection-based vulnerabilities, ensuring a more secure web application environment.