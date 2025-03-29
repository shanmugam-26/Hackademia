import os
import random
import importlib.util
import shutil
import sys
from flask import Flask, render_template_string, request, redirect, url_for, send_from_directory, session, abort
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.wrappers import Response
import glob
from flask import g
import re
import sqlite3
import markdown  # New import for Markdown processing

app = Flask(__name__)
app.secret_key = os.urandom(24)
print("Flask application initialized with a secret key.")

import logging
logging.basicConfig(
    filename='room_server.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
print("Logging configured to write to 'room_server.log' with DEBUG level.")

# Set the correct working directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))
print(f"Working directory set to: {os.getcwd()}")

#########################
# Database Setup
#########################
def init_ratings_db():
    """Initializes the ratings database and creates the ratings table if it doesn't exist."""
    db_path = os.path.join(os.getcwd(), 'ratings.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_name TEXT NOT NULL,
            rating INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()
    print("Initialized ratings database and ensured 'ratings' table exists.")

def get_average_rating(room_name):
    """Calculates the average rating for a given room."""
    db_path = os.path.join(os.getcwd(), 'ratings.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT AVG(rating) FROM ratings WHERE room_name = ?", (room_name,))
    result = cursor.fetchone()[0]
    conn.close()
    if result is None:
        return None
    return round(result, 2)  # Round to two decimal places

# Initialize the ratings database
init_ratings_db()

#########################
# HTML Templates
#########################
MAIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Hackademia</title>
    <style>
        :root {
            --primary-color: rgb(199,105,25);
            --primary-dark: rgb(179,94,22);
            --primary-light: rgb(209,115,35);
            --secondary-color: #FBF6F2;
            --text-dark: #23282d;
            --text-light: #646970;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background: #FFFFFF;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
            color: white;
            padding: 30px 0;
            margin-bottom: 40px;
            box-shadow: 0 4px 15px rgba(199, 105, 25, 0.3);
        }
        .header h1 {
            margin: 0;
            text-align: center;
            font-weight: 400;
            letter-spacing: 1.5px;
        }
        .lab-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 30px;
            margin-top: 30px;
        }
        .lab-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
            transition: all 0.3s ease;
            border: 2px solid #FBE9E7;
            position: relative;
            overflow: hidden;
        }
        .lab-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: var(--primary-color);
            transform: scaleX(0);
            transition: transform 0.3s ease;
        }
        .lab-card:hover {
            transform: translateY(-7px);
            box-shadow: 0 10px 20px rgba(199, 105, 25, 0.2);
            border-color: var(--primary-color);
        }
        .lab-card:hover::before {
            transform: scaleX(1);
        }
        .lab-title {
            font-size: 1.3em;
            margin-bottom: 20px;
            color: var(--primary-color);
            font-weight: 500;
        }
        .button {
            display: inline-block;
            padding: 12px 24px;
            background: var(--primary-color);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            transition: all 0.3s ease;
            margin-right: 12px;
            font-weight: 500;
            border: none;
            cursor: pointer;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 0.5px;
        }
        .button:hover {
            background: var(--primary-dark);
            transform: translateY(-2px);
            box-shadow: 0 5px 10px rgba(199, 105, 25, 0.2);
        }
        .random-button {
            background: white;
            color: var(--primary-color);
            border: 3px solid var(--primary-color);
            margin: 30px auto;
            font-weight: 600;
            padding: 15px 30px;
        }
        .random-button:hover {
            background: var(--primary-color);
            color: white;
        }
        .navigation {
            text-align: center;
            margin-bottom: 40px;
        }
        .error-message {
            background: #FFCCBC;
            color: #D84315;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #D84315;
        }
        .success-message {
            background: #DCEDC8;
            color: #33691E;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #33691E;
        }
        /* Rating System Styles */
        .rating {
            display: flex;
            align-items: center;
            margin-top: 10px;
        }
        .star {
            font-size: 1.5em;
            color: #C0C0C0; /* Gray color for inactive stars */
            cursor: pointer;
            transition: color 0.2s;
        }
        .star.gold {
            color: #FFD700; /* Gold color for active stars */
        }
        .average-rating {
            margin-left: 8px;
            font-size: 0.9em;
            color: var(--text-light);
        }
        /* Preview Details Styles */
        .preview-details {
            margin: 10px 0;
            padding: 8px;
            border-radius: 6px;
            background: var(--secondary-color);
        }
        .preview-details summary {
            cursor: pointer;
            color: var(--primary-color);
            font-weight: 500;
        }
        .preview-details[open] summary {
            margin-bottom: 10px;
        }
        .preview-content {
            font-size: 0.9em;
            line-height: 1.5;
            color: var(--text-dark);
        }
    </style>
    <script>
        // JavaScript to handle star ratings
        function setRating(room, rating) {
            document.getElementById('rating-value-' + room).value = rating;
            // Submit the form
            document.getElementById('rate-form-' + room).submit();
        }
        function highlightStars(room, rating) {
            for (let i = 1; i <= 5; i++) {
                const star = document.getElementById('star-' + room + '-' + i);
                if (i <= rating) {
                    star.classList.add('gold');
                    star.classList.remove('gray');
                } else {
                    star.classList.remove('gold');
                    star.classList.add('gray');
                }
            }
        }
    </script>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1>Hackademia</h1>
        </div>
    </div>
    <div class="container">
        {% if error %}
        <div class="error-message">{{ error }}</div>
        {% endif %}
        {% if success %}
        <div class="success-message">{{ success }}</div>
        {% endif %}
        
        <div class="navigation">
            <a href="{{ url_for('random_room') }}" class="button random-button">Random Lab</a>
        </div>
        
        <div class="lab-grid">
            {% for (original_name, clean_name) in rooms %}
            <div class="lab-card">
                {% if previews.get(original_name) %}
                <details class="preview-details">
                    <summary>Preview</summary>
                    <div class="preview-content">
                        {{ previews[original_name] | safe }}
                    </div>
                </details>
                {% endif %}
                <div class="lab-title">{{ original_name.replace('Room_', 'Lab ').replace('_', ' ') }}</div>
                
                <!-- Display Average Rating -->
                {% set avg_rating = get_average_rating(clean_name) %}
                {% if avg_rating %}
                <div class="rating">
                    <span class="average-rating">Average Rating: {{ avg_rating }} / 5</span>
                </div>
                {% else %}
                <div class="rating">
                    <span class="average-rating">No ratings yet.</span>
                </div>
                {% endif %}
                
                <!-- Rating Submission Form -->
                {% if clean_name not in session.get('rated_rooms', []) %}
                <form id="rate-form-{{ clean_name }}" action="{{ url_for('rate_room', room_name=clean_name) }}" method="POST">
                    <div class="rating">
                        {% for i in range(1,6) %}
                            <span id="star-{{ clean_name }}-{{ i }}" class="star gray" onclick="setRating('{{ clean_name }}', {{ i }})">&#9733;</span>
                        {% endfor %}
                        <input type="hidden" name="rating" id="rating-value-{{ clean_name }}" value="0">
                    </div>
                </form>
                {% else %}
                <div class="rating">
                    <span class="average-rating">You have rated this room.</span>
                </div>
                {% endif %}
                
                <a href="/room/{{ clean_name }}/" class="button">Enter Lab</a>
                <a href="{{ url_for('view_solution', room_name=clean_name) }}" class="button">View Solution</a>
            </div>
            {% endfor %}
        </div>
    </div>
    <script>
        // Add event listeners to highlight stars on hover
        {% for (original_name, clean_name) in rooms %}
            {% for i in range(1,6) %}
                document.getElementById('star-{{ clean_name }}-{{ i }}').addEventListener('mouseover', function() {
                    highlightStars('{{ clean_name }}', {{ i }});
                });
                document.getElementById('star-{{ clean_name }}-{{ i }}').addEventListener('mouseout', function() {
                    const currentRating = document.getElementById('rating-value-{{ clean_name }}').value;
                    highlightStars('{{ clean_name }}', currentRating);
                });
            {% endfor %}
        {% endfor %}
    </script>
</body>
</html>
"""

ERROR_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f0f2f5;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .error-container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 500px;
        }
        h1 { color: #c62828; }
        .message { color: #666; margin: 20px 0; }
        .button {
            display: inline-block;
            padding: 10px 20px;
            background: #1a237e;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            transition: background 0.3s;
        }
        .button:hover { background: #283593; }
    </style>
</head>
<body>
    <div class="error-container">
        <h1>{{ title }}</h1>
        <div class="message">{{ message }}</div>
        <a href="{{ url_for('index') }}" class="button">Return to Room Selection</a>
    </div>
</body>
</html>
"""

VIEW_SOLUTION_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ room_title }} - Solution</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f0f2f5;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .header h1 {
            text-align: center;
            color: #1a237e;
        }
        .back-button {
            display: block;
            margin-top: 20px;
            text-align: center;
        }
        .button {
            display: inline-block;
            padding: 10px 20px;
            background: #1a237e;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            transition: background 0.3s;
        }
        .button:hover {
            background: #283593;
        }
        .content {
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ room_title }} - Solution</h1>
        </div>
        <div class="content">
            {{ content | safe }}
        </div>
        <div class="back-button">
            <a href="{{ url_for('index') }}" class="button">Back to Rooms</a>
        </div>
    </div>
</body>
</html>
"""

#########################
# Utility Functions
#########################
def sanitize_folder_name(name):
    """Sanitize folder name for URL routing"""
    print(f"Sanitizing folder name: {name}")
    # Replace special characters with underscores
    sanitized = re.sub(r'[{}@\[\]<>\(\)&%$#@!,?]', '_', name)
    # Replace multiple consecutive underscores with a single one
    sanitized = re.sub(r'_+', '_', sanitized)
    # Replace spaces and hyphens with underscores
    sanitized = sanitized.replace(' ', '_').replace('-', '_')
    print(f"Sanitized folder name: {sanitized}")
    return sanitized

def list_room_folders(base_name):
    """Lists all available room folders in the current directory."""
    print(f"Listing room folders with base name: {base_name}")
    rooms = []
    room_map = {}
   
    for folder_name in os.listdir(os.getcwd()):
        folder_path = os.path.join(os.getcwd(), folder_name)
        if os.path.isdir(folder_path) and folder_name.startswith(base_name):
            clean_name = sanitize_folder_name(folder_name)
            rooms.append((folder_name, clean_name))
            room_map[clean_name] = folder_name
            print(f"Found room: {folder_name} -> {clean_name}")
   
    app.config['ROOM_MAP'] = room_map
    print(f"Room map updated: {room_map}")
    sorted_rooms = sorted(rooms)
    print(f"Total rooms found: {len(sorted_rooms)}")
    return sorted_rooms

def load_room_from_folder(room_folder):
    """Loads the vulnerable app from the specified room folder."""
    print(f"Loading room from folder: {room_folder}")
    room_path = os.path.join(os.getcwd(), room_folder)
    print(f"Room path: {room_path}")
    if not os.path.exists(room_path):
        print(f"Room path does not exist: {room_path}")
        return None
    vuln_file = os.path.join(room_path, 'vulnerable_app.py')
    print(f"Looking for vulnerable app file: {vuln_file}")
    if not os.path.exists(vuln_file):
        print(f"Vulnerable app file does not exist: {vuln_file}")
        return None
    try:
        # Change to room directory before loading
        original_dir = os.getcwd()
        os.chdir(room_path)
        print(f"Changed directory to room path: {room_path}")
        try:
            # Read the module content to analyze it
            with open(vuln_file, 'r', encoding='utf-8') as f:
                content = f.read()
                print(f"Read vulnerable_app.py content for room {room_folder}")
            # Create a unique module name
            module_name = f"room_{sanitize_folder_name(room_folder)}"
            spec = importlib.util.spec_from_file_location(module_name, vuln_file)
            module = importlib.util.module_from_spec(spec)
            # Set up module environment with necessary globals
            module.__dict__.update({
                'os': os,
                'sys': sys,
                'Flask': Flask,
                'render_template_string': render_template_string,
                'request': request,
                'redirect': redirect,
                'url_for': url_for,
                'session': session,
                'Response': Response,
                'send_from_directory': send_from_directory,
                'Session': session,  # Corrected 'Session' assignment
                'sqlite3': sqlite3,
                '__file__': vuln_file,
                '__name__': module_name,
            })
            print(f"Set up module environment for {module_name}")
            # Execute the module
            spec.loader.exec_module(module)
            print(f"Executed module for room {room_folder}")
            if hasattr(module, 'app'):
                # Configure the room's Flask app
                module.app.template_folder = os.path.join(room_path, 'templates')
                module.app.static_folder = os.path.join(room_path, 'static')
                module.app.secret_key = app.secret_key
                print(f"Configured room app {room_folder} with template and static folders")
                # Store the room path and name in app config
                module.app.config['ROOM_PATH'] = room_path
                clean_name = sanitize_folder_name(room_folder)
                module.app.config['ROOM_NAME'] = clean_name
                print(f"Stored room path and name in config for {room_folder}")
                # Patch render_template_string to include room prefix in URLs
                original_render = module.app.jinja_env.from_string
                def patched_render(source, **context):
                    print(f"Rendering template with room prefix {clean_name}")
                    source = source.replace('href="/', f'href="/room/{clean_name}/')
                    source = source.replace('action="/', f'action="/room/{clean_name}/')
                    return original_render(source, **context)
                module.app.jinja_env.from_string = patched_render
                print(f"Patched render_template_string for room {room_folder}")
                # Patch url_for to include room prefix
                original_url_for = module.app.jinja_env.globals['url_for']
                def patched_url_for(endpoint, **values):
                    url = original_url_for(endpoint, **values)
                    if not url.startswith(('http://', 'https://')):
                        if not url.startswith('/'):
                            url = '/' + url
                        if not url.startswith(f'/room/{clean_name}'):
                            url = f'/room/{clean_name}{url}'
                    print(f"url_for called: endpoint={endpoint}, values={values}, url={url}")
                    return url
                module.app.jinja_env.globals['url_for'] = patched_url_for
                print(f"Patched url_for for room {room_folder}")
                return module
            else:
                print(f"No 'app' found in module for room {room_folder}")
        finally:
            os.chdir(original_dir)
            print(f"Reverted directory change to {original_dir}")
    except Exception as e:
        print(f"Error loading room {room_folder}: {str(e)}")
        import traceback
        traceback.print_exc()
    return None

#########################
# Middleware
#########################
class RoomMiddleware:
    def __init__(self, wsgi_app, room_name, room_app):
        self.wsgi_app = wsgi_app
        self.room_name = room_name
        self.room_app = room_app
        self.room_path = self.room_app.config['ROOM_PATH']
        print(f"Initialized RoomMiddleware for {room_name}, path: {self.room_path}")

    def __call__(self, environ, start_response):
        original_dir = os.getcwd()
        print(f"RoomMiddleware __call__: original_dir={original_dir}")
        try:
            # Change to room directory for the request
            os.chdir(self.room_path)
            print(f"Changed directory to room_path: {self.room_path}")
            path_info = environ.get('PATH_INFO', '')
                        
            # Normalize path by removing room prefix and maintaining the rest of the path
            parts = [p for p in path_info.split('/') if p]
            print(f"PATH_INFO before modification: {path_info}")
            print(f"Path parts: {parts}")

            # Remove any part that matches the room name pattern
            if parts:
                if parts[0] == self.room_name or parts[0].replace('_', ' ') == self.room_name:
                    parts = parts[1:]
                    print(f"Removed room name from path parts: {parts}")
                elif parts[0].startswith('Room_'):
                    parts = parts[1:]
                    print(f"Removed Room_ prefix from path parts: {parts}")

            # Construct new path while preserving query string
            query_string = environ.get('QUERY_STRING', '')
            new_path = '/' + '/'.join(parts) if parts else '/'
            if query_string:
                new_path = f"{new_path}?{query_string}"
            print(f"PATH_INFO after modification: {new_path}")
            environ['PATH_INFO'] = new_path
            environ['SCRIPT_NAME'] = f'/room/{self.room_name}'
            print(f"Set SCRIPT_NAME to: {environ['SCRIPT_NAME']}")
            def wrapped_start_response(status, headers, exc_info=None):
                print(f"wrapped_start_response: status={status}")
                new_headers = []
                for name, value in headers:
                    if name.lower() == 'location':
                        print(f"Original Location header: {value}")
                        if not value.startswith(('http://', 'https://')):
                            if not value.startswith('/'):
                                value = '/' + value
                            if not value.startswith(f'/room/{self.room_name}'):
                                value = f'/room/{self.room_name}{value}'
                            print(f"Modified Location header: {value}")
                        new_headers.append((name, value))
                    else:
                        new_headers.append((name, value))
                return start_response(status, new_headers, exc_info)
            print(f"Calling room_app.wsgi_app with modified environ")
            return self.room_app.wsgi_app(environ, wrapped_start_response)
        except Exception as e:
            print(f"Exception in RoomMiddleware: {str(e)}")
            import traceback
            traceback.print_exc()
            raise e
        finally:
            os.chdir(original_dir)
            print(f"Reverted directory back to {original_dir}")

#########################
# Room Management
#########################
room_apps = {}
print("Initialized room_apps dictionary.")

def cleanup_room(room_folder):
    """Clean up resources when unloading a room"""
    print(f"Cleaning up room: {room_folder}")
    try:
        # Remove any temporary files
        temp_files = ['*.db', '*.sqlite', '*.sqlite3']
        room_path = os.path.join(os.getcwd(), room_folder)
        for pattern in temp_files:
            for file in glob.glob(os.path.join(room_path, pattern)):
                try:
                    os.remove(file)
                    print(f"Removed temporary file: {file}")
                except Exception as e:
                    print(f"Warning: Could not remove {file}: {e}")
    except Exception as e:
        print(f"Warning: Cleanup failed for {room_folder}: {e}")

def create_room_app(original_room_name, clean_room_name):
    """Creates a wrapped room application with proper routing"""
    print(f"\nCreating room app for: {original_room_name}")
    print(f"Clean name: {clean_room_name}")
   
    if original_room_name not in room_apps:
        try:
            room_module = load_room_from_folder(original_room_name)
            if not room_module or not hasattr(room_module, 'app'):
                print(f"Failed to load room: {original_room_name}")
                return None
            # Initialize the database if init_db exists
            if hasattr(room_module, 'init_db'):
                print(f"Initializing database for {original_room_name}")
                # Change to room directory for database initialization
                original_dir = os.getcwd()
                try:
                    os.chdir(room_module.app.config['ROOM_PATH'])
                    room_module.init_db()
                    print(f"Database initialized for {original_room_name}")
                finally:
                    os.chdir(original_dir)
                    print(f"Reverted directory back to {original_dir} after DB init")
            print(f"Successfully loaded room: {original_room_name}")
            wrapped_app = RoomMiddleware(app, clean_room_name, room_module.app)
            room_apps[original_room_name] = wrapped_app
            print(f"Room app wrapped and added to room_apps: {original_room_name}")
        except Exception as e:
            print(f"Error creating room app {original_room_name}: {str(e)}")
            import traceback
            traceback.print_exc()
            return None
   
    print(f"Returning room app for: {original_room_name}")
    return room_apps.get(original_room_name)

def dispatch_room_requests(environ, start_response):
    """Dispatcher for room requests"""
    path_info = environ.get('PATH_INFO', '')
    parts = [p for p in path_info.split('/') if p]
    print(f"\nDispatching request: {path_info}")
    print(f"Path parts: {parts}")
    if not parts:
        print("No room specified, delegating to main app")
        return app(environ, start_response)
   
    clean_room_name = parts[0]
    original_room_name = app.config['ROOM_MAP'].get(clean_room_name)
    print(f"Looking for room: {clean_room_name}")
    print(f"Original room name: {original_room_name}")
   
    if not original_room_name:
        print(f"Room not found: {clean_room_name}")
        print("Available rooms:", app.config['ROOM_MAP'])
        response = Response('Room not found', status=404)
        print("Returning 404 response")
        return response(environ, start_response)
   
    room_app = create_room_app(original_room_name, clean_room_name)
    if not room_app:
        print("Failed to create room app")
        response = Response('Failed to load room', status=500)
        return response(environ, start_response)
   
    print(f"Dispatching to room app: {original_room_name}")
    return room_app(environ, start_response)

#########################
# Room Rating Routes
#########################
@app.route('/rate/<room_name>/', methods=['POST'])
def rate_room(room_name):
    """Handles rating submissions for a specific room."""
    if 'rated_rooms' not in session:
        session['rated_rooms'] = []
   
    if room_name in session['rated_rooms']:
        print(f"User has already rated room: {room_name}")
        return redirect(url_for('index', error="You have already rated this room."))
   
    try:
        rating = int(request.form.get('rating'))
        if rating < 1 or rating > 5:
            raise ValueError("Rating must be between 1 and 5.")
    except (TypeError, ValueError) as e:
        print(f"Invalid rating submission: {e}")
        return redirect(url_for('index', error="Invalid rating submitted. Please rate between 1 and 5."))
    # Insert the rating into the database
    db_path = os.path.join(os.getcwd(), 'ratings.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO ratings (room_name, rating) VALUES (?, ?)", (room_name, rating))
    conn.commit()
    conn.close()
    print(f"Received rating of {rating} for room {room_name}.")
    # Mark this room as rated in the session
    session['rated_rooms'].append(room_name)
    session.modified = True
    print(f"User has rated room: {room_name}")
    return redirect(url_for('index', success="Thank you for your rating!"))

#########################
# Routes
#########################
@app.route('/')
def index():
    """Display the room selection page."""
    print("Handling request for index page")
    rooms = list_room_folders("Room")
    error = request.args.get('error')
    success = request.args.get('success')
   
    # Add debug information
    debug_info = "Room Mappings:\n"
    for original, clean in rooms:
        debug_info += f"{original} -> {clean}\n"
    print(f"Rooms found: {rooms}")
    print(f"Error: {error}")
    print(f"Success: {success}")
   
    # Load preview markdown files
    previews = {}
    for original_name, clean_name in rooms:
        preview_path = os.path.join(os.getcwd(), original_name, 'preview.md')
        if os.path.exists(preview_path):
            try:
                with open(preview_path, 'r', encoding='utf-8') as f:
                    preview_content = f.read()
                    previews[original_name] = markdown.markdown(preview_content)
            except Exception as e:
                print(f"Error reading preview for {original_name}: {str(e)}")
   
    # Pass the get_average_rating function to the template
    return render_template_string(MAIN_TEMPLATE,
                                  rooms=rooms,
                                  error=error,
                                  success=success,
                                  debug_info=debug_info,
                                  previews=previews,
                                  get_average_rating=get_average_rating)

@app.route('/random')
def random_room():
    """Select a random room and redirect to it."""
    print("Handling request for a random room")
    rooms = list_room_folders("Room")
    print(f"Available rooms: {rooms}")
    if not rooms:
        print("No rooms available, redirecting to index with error")
        return redirect(url_for('index', error="No rooms available"))
    selected_room = random.choice(rooms)[1]  # Use the clean name
    print(f"Selected random room: {selected_room}")
    return redirect(f'/room/{selected_room}/')

@app.route('/solution/<room_name>/', methods=['GET'])
def view_solution(room_name):
    """Display the solution markdown file for the given room."""
    print(f"Handling request for solution of room: {room_name}")
   
    # Get the original room name from ROOM_MAP
    original_room_name = app.config['ROOM_MAP'].get(room_name)
    if not original_room_name:
        print(f"Room not found: {room_name}")
        abort(404, description="Room not found.")
    room_path = os.path.join(os.getcwd(), original_room_name)
    solution_md_path = os.path.join(room_path, 'explanation_and_mitigation.md')  # assuming the file is named 'explanation_and_mitigation.md'
    if not os.path.exists(solution_md_path):
        print(f"Solution file not found: {solution_md_path}")
        abort(404, description="Solution not found.")
    try:
        with open(solution_md_path, 'r', encoding='utf-8') as f:
            md_content = f.read()
            print(f"Read solution markdown for room {room_name}")
       
        # Convert markdown to HTML
        html_content = markdown.markdown(md_content)
        print(f"Converted markdown to HTML for room {room_name}")
        # Render the solution template with the HTML content
        room_title = original_room_name.replace('Room_', '').replace('_', ' ')
        return render_template_string(VIEW_SOLUTION_TEMPLATE, room_title=room_title, content=html_content)
       
    except Exception as e:
        print(f"Error reading solution for room {room_name}: {str(e)}")
        import traceback
        traceback.print_exc()
        abort(500, description="Error processing solution.")

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    print("Handling 404 error")
    return render_template_string(ERROR_TEMPLATE,
                                  title="Page Not Found",
                                  message=error.description if hasattr(error, 'description') else "The requested page could not be found."), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    print("Handling 500 error")
    return render_template_string(ERROR_TEMPLATE,
                                  title="Internal Server Error",
                                  message=error.description if hasattr(error, 'description') else "An internal server error occurred."), 500

#########################
# Application Setup
#########################
# Create the dispatching application
application = DispatcherMiddleware(app, {
    '/room': dispatch_room_requests
})
print("DispatcherMiddleware set up with '/room' route")

if __name__ == '__main__':
    from werkzeug.serving import run_simple
    print("Starting server...")
    # Clear any existing room apps
    room_apps.clear()
   
    # List available rooms
    rooms = list_room_folders("Room")
    print(f"\nFound {len(rooms)} rooms")
    print("\nRoom mappings:")
    for original, clean in rooms:
        print(f"{original} -> {clean}")
   
    # Install dependencies
    try:
        import pip
        dependencies = ['lxml', 'flask-sqlalchemy', 'werkzeug', 'markdown', 'Crypto']
        for dep in dependencies:
            try:
                __import__(dep)
                print(f"Dependency already installed: {dep}")
            except ImportError:
                print(f"\nInstalling {dep}...")
                pip.main(['install', dep])
                print(f"Installed dependency: {dep}")
    except Exception as e:
        print(f"\nWarning: Could not install dependencies: {e}")
   
    # Retrieve the port from environment variables, default to 8000 if not set
    port = int(os.environ.get("PORT", 8000))
    host = '0.0.0.0'  # Listen on all interfaces
    print(f"\nStarting server on {host}:{port} with debugging...")
    run_simple(host, port, application, use_debugger=True, use_reloader=True)