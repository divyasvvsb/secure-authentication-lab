# Secure Authentication Lab

A small local authentication service (Python + Flask) that demonstrates defensive
authentication controls, proven by automated tests.

## Files
| File | Purpose |
|------|---------|
| `app.py` | The authentication service |
| `test_auth.py` | 20 automated tests covering every control |
| `test_output.txt` | Saved output of the passing test run |
| `SECURITY_NOTE.md` | Authentication security note (controls, threats, limitations) |
| `requirements.txt` | Dependencies (Flask) |

## Run the tests
```
pip install -r requirements.txt
python -m unittest -v
```

## Run the service locally
```
# Linux/macOS
INSECURE_DEV=1 python app.py
# Windows PowerShell
$env:INSECURE_DEV="1"; python app.py
```
`INSECURE_DEV=1` only disables the cookie `Secure` flag so it works over plain
http on localhost. Never use it in production.

## Endpoints
- `POST /register` with JSON `{"username": "...", "password": "..."}`
- `POST /login` with the same JSON, sets a session cookie
- `GET /me` returns the logged-in user (needs the cookie)
- `POST /logout` ends the session

## Controls implemented
1. **Password hashing and validation:** salted scrypt hashes, server-side checks on username and password.
2. **Secure sessions:** HttpOnly, Secure, SameSite=Strict cookie, server-side logout, idle and absolute expiry.
3. **Rate limiting and generic errors:** 5 failed logins per minute per user and IP, identical error for wrong user or wrong password.

See `SECURITY_NOTE.md` for details.
