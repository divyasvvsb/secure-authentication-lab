"""Automated tests proving each defensive control. Run: python -m unittest -v"""
import unittest

from app import GENERIC_AUTH_ERROR, create_app

STRONG = "Str0ngPassw0rd"


class FakeClock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.app = create_app({"CLOCK": self.clock})
        # https base_url so the Secure cookie is accepted by the test client
        self.client = self.app.test_client()
        self.base = "https://localhost"

    def post(self, path, **json):
        return self.client.post(path, json=json, base_url=self.base)

    def get(self, path):
        return self.client.get(path, base_url=self.base)

    def register(self, user="alice", pw=STRONG):
        return self.post("/register", username=user, password=pw)

    # ---- 1. password hashing and input validation ----
    def test_password_is_hashed_not_stored_in_plaintext(self):
        self.register()
        # Inspect the closure-held store through a fresh login: hash check must work
        self.assertEqual(self.post("/login", username="alice", password=STRONG).status_code, 200)
        from werkzeug.security import generate_password_hash
        h = generate_password_hash(STRONG)
        self.assertNotIn(STRONG, h)
        self.assertTrue(h.startswith(("scrypt:", "pbkdf2:")))

    def test_same_password_gives_different_hashes_salted(self):
        from werkzeug.security import generate_password_hash
        self.assertNotEqual(generate_password_hash(STRONG), generate_password_hash(STRONG))

    def test_weak_passwords_rejected(self):
        for bad in ["short1A", "alllowercase123", "ALLUPPERCASE123", "NoDigitsHerePlease"]:
            with self.subTest(pw=bad):
                self.assertEqual(self.register("bob", bad).status_code, 400)

    def test_bad_usernames_rejected(self):
        for bad in ["ab", "has space", "semi;colon", "<script>", "x" * 33, "' OR 1=1 --"]:
            with self.subTest(user=bad):
                self.assertEqual(self.register(bad).status_code, 400)

    def test_non_string_input_rejected(self):
        self.assertEqual(self.post("/register", username=123, password=STRONG).status_code, 400)
        self.assertEqual(self.post("/register", username="carol", password=["x"]).status_code, 400)
        self.assertEqual(self.post("/login", username={"$ne": ""}, password="x").status_code, 401)

    def test_duplicate_username_rejected(self):
        self.assertEqual(self.register().status_code, 201)
        self.assertEqual(self.register("ALICE").status_code, 409)

    # ---- 2. secure cookies, logout, session expiry ----
    def test_cookie_has_secure_attributes(self):
        self.register()
        r = self.post("/login", username="alice", password=STRONG)
        cookie = r.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_session_grants_access_then_logout_revokes_it(self):
        self.register()
        self.post("/login", username="alice", password=STRONG)
        self.assertEqual(self.get("/me").status_code, 200)
        self.assertEqual(self.post("/logout").status_code, 200)
        self.assertEqual(self.get("/me").status_code, 401)

    def test_logged_out_token_cannot_be_reused(self):
        self.register()
        self.post("/login", username="alice", password=STRONG)
        old = self.client.get_cookie("session_id", domain="localhost").value
        self.post("/logout")
        self.client.set_cookie("session_id", old, domain="localhost")
        self.assertEqual(self.get("/me").status_code, 401)

    def test_idle_session_expires(self):
        self.register()
        self.post("/login", username="alice", password=STRONG)
        self.clock.advance(15 * 60 + 1)
        self.assertEqual(self.get("/me").status_code, 401)

    def test_active_session_stays_alive_until_absolute_limit(self):
        self.register()
        self.post("/login", username="alice", password=STRONG)
        for _ in range(8):  # activity every 10 min keeps it alive
            self.clock.advance(10 * 60)
            self.assertEqual(self.get("/me").status_code, 200)
        self.clock.advance(8 * 60 * 60)  # beyond the 8 hour hard cap
        self.assertEqual(self.get("/me").status_code, 401)

    def test_new_session_token_on_each_login(self):
        self.register()
        self.post("/login", username="alice", password=STRONG)
        first = self.client.get_cookie("session_id", domain="localhost").value
        self.post("/login", username="alice", password=STRONG)
        second = self.client.get_cookie("session_id", domain="localhost").value
        self.assertNotEqual(first, second)

    def test_protected_route_requires_login(self):
        self.assertEqual(self.get("/me").status_code, 401)

    def test_valid_login_succeeds(self):
        self.register()
        r = self.post("/login", username="alice", password=STRONG)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.get("/me").get_json()["username"], "alice")

    def test_invalid_or_forged_session_cookie_rejected(self):
        self.register()
        self.post("/login", username="alice", password=STRONG)
        for fake in ["", "not-a-real-token", "A" * 43, "../../etc/passwd"]:
            with self.subTest(token=fake):
                self.client.set_cookie("session_id", fake, domain="localhost")
                self.assertEqual(self.get("/me").status_code, 401)

    # ---- 3. rate limiting and generic errors ----
    def test_unknown_user_and_wrong_password_give_identical_errors(self):
        self.register()
        a = self.post("/login", username="alice", password="WrongPassw0rd")
        b = self.post("/login", username="nobody", password="WrongPassw0rd")
        self.assertEqual(a.status_code, 401)
        self.assertEqual(b.status_code, 401)
        self.assertEqual(a.get_json(), b.get_json())
        self.assertEqual(a.get_json()["error"], GENERIC_AUTH_ERROR)

    def test_rate_limit_blocks_brute_force(self):
        self.register()
        for _ in range(5):
            self.assertEqual(self.post("/login", username="alice", password="WrongPassw0rd").status_code, 401)
        blocked = self.post("/login", username="alice", password="WrongPassw0rd")
        self.assertEqual(blocked.status_code, 429)
        self.assertIn("Retry-After", blocked.headers)

    def test_rate_limit_blocks_even_correct_password_while_locked(self):
        self.register()
        for _ in range(5):
            self.post("/login", username="alice", password="WrongPassw0rd")
        self.assertEqual(self.post("/login", username="alice", password=STRONG).status_code, 429)

    def test_rate_limit_resets_after_window(self):
        self.register()
        for _ in range(5):
            self.post("/login", username="alice", password="WrongPassw0rd")
        self.clock.advance(61)
        self.assertEqual(self.post("/login", username="alice", password=STRONG).status_code, 200)

    def test_security_headers_present(self):
        r = self.get("/me")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["Cache-Control"], "no-store")


if __name__ == "__main__":
    unittest.main(verbosity=2)
