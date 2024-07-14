# Web Programming

This project is a web application developed for managing user profiles. It allows users to register, login, update their information, and delete their accounts. The application is built using Flask, a micro web framework written in Python.

## Author

[Danialmd81](https://github.com/danialmd81)

## Project Structure

- `.gitignore`: Specifies intentionally untracked files to ignore.
- `flask_app`: (This seems to be mentioned but no details provided. It might be a directory or file related to the Flask application setup.)
- `proxy-server/`

  - `tcp_bridge.py`: A TCP bridge for the proxy server, possibly used for handling requests between the client and the web server.

- `README.md`: This file, providing an overview of the project.
- `web-server/`

  - `database/`

    - `create_table.sql`: SQL script for creating the database and the `accounts` table used by the application.

  - `profileApp/`

    - `__pycache__/`: Python cache files. Excluded from version control as specified in `.gitignore`.
    - `app.py`: The main Flask application file. Defines routes and views for the application.
    - `requirements.txt`: Lists all Python packages that the project depends on.
    - `static/`

      - `style.css`: CSS styles used across the web application.

    - `templates/`

      - `delete_account.html`: Template for the account deletion page.
      - `display.html`: Template for displaying user profile information.
      - `home.html`: Template for the homepage after login.
      - `login.html`: Template for the login page.
      - `register.html`: Template for the user registration page.
      - `update.html`: Template for updating user profile information.

## Setup and Installation

1. Ensure Python and Flask are installed on your system.
2. Install the required Python packages by running `pip install -r web-server/profileApp/requirements.txt`.
3. Initialize the database by running the SQL script `web-server/database/create_table.sql` in your MySQL server.
4. Start the Flask application by running `python web-server/profileApp/app.py`.
