# Flask Ticket System

This is a simple ticket system web application built with Flask that implements role-based access control (RBAC) with different user roles and groups.

## Getting Started

These instructions will help you set up and run the project on your local machine.

### Prerequisites

- Python 3.8 or higher
- virtualenv (optional, but recommended)

### Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/Aarrtteemm123/flask-ticket-system.git
    cd flask-test
    ```

2. **Create and activate a virtual environment (optional but recommended):**

    ```sh
    python -m venv venv
    source venv/bin/activate    # On Windows use `venv\Scripts\activate`
    ```

3. **Install the required packages:**

    ```sh
    pip install -r requirements.txt
    ```

4. **Set up the database:**

    Initialize the database and create the necessary tables:

    ```sh
    flask db init
    flask db migrate -m "Initial migration"
    flask db upgrade
    ```

5. **Create environment variables (Optional):**

    Create a `.env` file in the project root and add the following environment variables:

    ```sh
    FLASK_APP=run.py
    FLASK_ENV=development
    SECRET_KEY=your_secret_key
    ```

### Running the Application

1. **Run the Flask application:**

    ```sh
    flask run
    ```

2. **Access the application:**

    Open your web browser and go to `http://127.0.0.1:5000/login`.

