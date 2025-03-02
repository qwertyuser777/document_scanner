# Document Scanner

A Flask-based web application for uploading, managing, and scanning documents with AI-powered similarity matching, a credit system, and admin analytics. Users can upload documents, view session-specific or all documents, request credits, and admins can manage credit requests and view analytics.

## Features
- **User Authentication**:
  - Register and login with password hashing.
  - Admin users defined in `admins.json`—admins have additional privileges.
  - Session management with server ID validation to prevent reuse.

- **Document Management**:
  - Upload documents (PDF, PNG, JPG, JPEG, TXT)—costs 1 credit per upload.
  - View session-specific documents (`index.html`) and all documents (`documents.html`).
  - Download or delete documents.
  - AI-powered matching (using spaCy) to find similar documents—optional via checkbox.

- **Credit System**:
  - Users start with 20 credits, reset daily.
  - Non-admin users can request additional credits—requests are pending admin approval.
  - Admins can approve (grants +10 credits) or deny credit requests.

- **Admin Features**:
  - Admins can view and manage pending credit requests.
  - Analytics dashboard (`/admin/analytics`) showing total scans today, most active users, and popular scanned topics.

## Prerequisites
- Python 3.8+
- Virtualenv (recommended)
- SQLite (used as the database)
- spaCy with the `en_core_web_sm` model for AI matching
- Git (for version control)
- C++ build tools (required for spaCy):
  - On Windows: Microsoft Visual C++ Build Tools (https://visualstudio.microsoft.com/visual-cpp-build-tools/)
  - On Mac/Linux: A C++ compiler like `gcc` or `clang` (usually included with `build-essential` or Xcode)

## Setup Instructions
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/qwertyuser777/document_scanner.git
   cd document_scanner/backend

2.  Create and Activate a Virtual Environment:
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate

3.  Install Dependencies:
    Before Installing requirements update the pip setuptools wheel for smoothly installing all required file
    
    pip install --upgrade pip setuptools wheel
    pip install -r requirements.txt

    """Make Sure you have C++ Build tools to for Spacy Installation."""

4.  Install SpaCy Model:
    python -m spacy download en_core_web_md

5.  Run the Application
    Python app.py
    The app will run at http://localhost:5000.



If you want to login as admin follow these Steps:
Create admins.json for Admin Users:
In the backend/ directory, create an admins.json file to define admin users. Follow these steps to create an admin user:

Step 1: Choose a Username and Password: Decide on a username and password for your admin user (e.g., username: admin, password: admin123).
Step 2: Generate the Password Hash: The password must be hashed using SHA-256. Use Python to generate the hash:
# Open a Python interpreter and run this command for Hashed password

python -c "import hashlib; print(hashlib.sha256('your_password'.encode()).hexdigest())"


This will output the hash (e.g., f865b53623b121fd34ee5426c792e5c33af8c227 for admin123).


Now Create a file named admins.json (backend\admin.json) and paste this:

{
    "admins": [
        {"username": "admin", "password_hash": "f865b53623b121fd34ee5426c792e5c33af8c227"}
    ]
}


Replace "admin" with your chosen username and "f865b53623b121fd34ee5426c792e5c33af8c227" with the hash you generated.
Step 4: Verify Admin Creation: After setting up admins.json, stop the program and rerun the file app.py, you can login with the admin credentials (e.g., username: admin, password: admin123) to access admin features like managing credit requests and viewing analytics



# File Structure :
document_scanner/
├── backend/
│   ├── static/
│   │   ├── css/
│   │   │   └── styles.css
│   │   ├── js/
│   │   │   └── script.js
│   ├── templates/
│   │   ├── index.html
│   │   ├── login.html
│   │   ├── register.html
│   │   ├── profile.html
│   │   ├── documents.html
│   │   ├── admin_analytics.html
│   ├── admins.json           # Admin user definitions
│   ├── app.py                # Main Flask app
│   ├── credits.py            # Credit system routes
│   ├── matching.py           # AI matching logic
│   ├── analytics.py          # Analytics routes
│   ├── requirements.txt      # Dependencies
│   └── .gitignore            # Excludes unnecessary files
└── README.md
