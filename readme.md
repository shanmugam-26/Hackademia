# Hackademia: Cybersecurity Learning Platform

Hackademia is an interactive learning platform designed to teach cybersecurity concepts through hands-on labs. The application hosts various security "rooms" where users can practice identifying and exploiting vulnerabilities in a safe, controlled environment.

![Alt text](./Hackademia.png)


## Features

- **Interactive Labs**: Multiple cybersecurity labs with different focus areas
- **Rating System**: Users can rate labs and see average ratings
- **Lab Previews**: Markdown previews of lab content
- **Solution Access**: Detailed explanations and mitigations for vulnerabilities
- **Random Lab Selection**: Option to be directed to a random lab

## Installation

### Prerequisites
- Python 3.6 or higher
- pip (Python package manager)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/Trivulzianus/hackademia.git
cd hackademia
```

2. Install required dependencies:
```bash
pip install flask werkzeug markdown
```

Additional dependencies will be automatically installed when the application runs.

## Usage

### Starting the Server

Run the application with:

```bash
python app-testing.py
```

The server will start on port 8000 by default. You can specify a different port using the PORT environment variable:

```bash
PORT=5000 python app_testing.py
```

### Accessing the Platform

Once the server is running, access the platform by navigating to:
```
http://localhost:8000
```

### Lab Structure

Each lab is contained in a folder named `Room_*` and includes:
- `vulnerable_app.py`: The main lab application
- `preview.md`: Markdown preview of the lab content
- `explanation_and_mitigation.md`: Solution and mitigation strategies
- Optional folders:
  - `templates/`: HTML templates used by the lab
  - `static/`: Static files (CSS, JS, images)

## Creating New Labs

1. Create a new folder named `Room_YourLabName`
2. Add a `vulnerable_app.py` file with a Flask application
3. Add `preview.md` and `explanation_and_mitigation.md` files
4. Create templates and static folders if needed

The lab's Flask application should follow this structure:
```python
from flask import Flask, render_template_string, request

app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string("""
        <h1>Your Lab Title</h1>
        <p>Lab content goes here</p>
    """)

# Add more routes as needed

if __name__ == '__main__':
    app.run(debug=True)
```

## Database

The platform uses SQLite to store user ratings:
- `ratings.db`: Contains user ratings for each lab

## Logging

Logs are written to `room_server.log` and include:
- Server startup information
- Request handling details
- Error messages
- Lab loading information

## Architecture

The application uses Flask's DispatcherMiddleware to route requests to the appropriate lab application. Each lab is loaded dynamically and wrapped with middleware that handles path routing.

## License

This project is licensed under the MIT License - see the LICENSE file for details.