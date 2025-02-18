## How to run?

Pre-requisites:

1. Since this application is designed to run only on HTTPS, you need to have an SSL Certificate associated with it. For this demo, you need to create a self-signed certificate using the command below,
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```
2. Setup `SECRET_KEY` environmental variable to sign the user session cookies. You can set this in [config.env](./config.env) file.
3. Install dependencies using `pip install -r requirements.txt`
4. Run the application using `python app.py`

---

## Assignment Description:

In this assignment, you will practice security patterns by using best practices in developing a simple API user control panel.
Tasks

You will implement backend APIs in Python [using Flask](https://flask.palletsprojects.com/en/3.0.x/quickstart/#a-minimal-application) for a simple app with the data stored in a local SQLite3 database.

The app has 2 roles: `user` and `admin`.

When the app starts, it should create an admin user with `admin:admin` as the username and password for the admin user. This can be changed by the admin using the /changepw API.

## APIs to be implemented

**1. POST /register**

- This takes `username` and `password` as JSON request body.
- Every user must have a unique username.
- It returns
    - `201` status code if the user was registered successfully.
    - `400` status code with the correct error message in other cases.

**2. POST /login**

- This takes `username` and `password` as JSON request body
- It returns
    - 200 status code with a valid session cookie in the response headers if the credentials are correct.
    - 401 status code with the response body showing the correct error message in all the other cases.

**3. POST /changepw**

- This takes `username`, `old_password`, and `new_password` as JSON request body
- It returns
    - `201` status code if the password was changed successfully.
    - `400` status code with the response body showing the correct error message otherwise.

**4. GET /admin**

- API is called by setting the session cookie received from the `/login` API.
- If the role is admin, the user should see "Logged in as admin `<username>`"

**5. GET /user**

- API is called by setting the session cookie received from the `/login` API.
- Irrespective of the role, the user should see `Logged in as user <username>`.

## Security Details

Here is a minimal list of security details that you must include in your implementations:

- Role-based Authorization
- All Communication must be secure
- Audit and logging: log when a user logs in and any behavior that can be helpful
- Secure session management: sessions must timeout, use unpredictable sessions
- Password management: store passwords securely
- Input Validation and Sanitization
- Security headers