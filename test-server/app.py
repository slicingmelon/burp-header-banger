from flask import Flask, request, redirect, url_for, render_template_string
import re
import time

app = Flask(__name__)

@app.route('/')
def index():
    return '''
        <h2>Welcome to the Test App</h2>
        <ul>
            <li><a href="/login">Login</a></li>
            <li><a href="/register">Register</a></li>
            <li><a href="/search">Search (SQL Injection Test)</a></li>
        </ul>
        
        <div style="margin-top: 20px; padding: 10px; background: #fff3cd; border: 1px solid #ffeaa7;">
            <h3>🔧 Testing Instructions</h3>
            <p>This test server simulates vulnerabilities to test your Burp Header Banger extension:</p>
            <ul>
                <li><strong>Search endpoint:</strong> Detects SQL injection patterns in headers and simulates delays</li>
                <li><strong>All endpoints:</strong> Display headers to verify extra headers are being added</li>
                <li><strong>SQL injection payload:</strong> <code>1'XOR(if(now()=sysdate(),sleep(17),0))OR'Z</code></li>
            </ul>
        </div>
    '''

form_template = '''
    <h2>{{ action.title() }}</h2>
    <form method="post">
        <input name="username" placeholder="Username"><br>
        <input name="password" placeholder="Password" type="password"><br>
        <button type="submit">{{ action.title() }}</button>
    </form>
'''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', 'guest')
        return redirect(url_for('home', username=username))
    return render_template_string(form_template, action='login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', 'guest')
        return redirect(url_for('home', username=username))
    return render_template_string(form_template, action='register')

@app.route('/home')
def home():
    username = request.args.get('username', 'guest')
    user_agent = request.headers.get('User-Agent', 'unknown')
    
    # Show all headers for debugging extra headers
    all_headers = dict(request.headers)
    headers_display = '<br>'.join([f"<strong>{k}:</strong> {v}" for k, v in all_headers.items()])
    
    # Check for extra headers
    extra_headers = []
    for header_name, header_value in all_headers.items():
        if header_name.startswith('X-') and header_name not in ['X-Forwarded-For', 'X-Real-IP']:
            extra_headers.append(f"{header_name}: {header_value}")
    
    extra_headers_display = ""
    if extra_headers:
        extra_headers_display = f'''
            <div style="background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; margin: 10px 0;">
                <h3 style="color: #155724;">✅ Extra Headers Detected!</h3>
                <ul>
                    {"".join([f"<li><code>{header}</code></li>" for header in extra_headers])}
                </ul>
            </div>
        '''
    
    return f'''
        <h2>Welcome {username}!</h2>
        <p>Your user-agent is:</p>
        <pre>{user_agent}</pre>
        
        {extra_headers_display}
        
        <h3>All Request Headers:</h3>
        <div style="background: #f0f0f0; padding: 10px; font-family: monospace; font-size: 12px;">
            {headers_display}
        </div>
        
        <br>
        <a href="/">Back to Home</a>
    '''

def check_for_sqli_and_sleep(headers):
    """Check all headers for SQL injection patterns and simulate sleep if found"""
    sleep_patterns = [
        r"sleep\((\d+)\)",  # Extract sleep(XX) value
        r"SLEEP\((\d+)\)",  # Case insensitive
        r"waitfor\s+delay\s+'00:00:(\d+)'",  # SQL Server WAITFOR DELAY
    ]
    
    for header_name, header_value in headers.items():
        if not header_value:
            continue
            
        print(f"[DEBUG] Checking header {header_name}: {header_value}")
        
        # Check for SQL injection patterns
        sqli_indicators = [
            "XOR(if(now()=sysdate()",
            "1'XOR(if(now()=sysdate()",
            "sleep(",
            "SLEEP(",
            "waitfor delay",
            "benchmark(",
            "pg_sleep(",
        ]
        
        for indicator in sqli_indicators:
            if indicator.lower() in header_value.lower():
                print(f"[ALERT] SQL injection pattern detected in {header_name}: {indicator}")
                
                # Extract sleep value from any sleep pattern
                for pattern in sleep_patterns:
                    matches = re.findall(pattern, header_value, re.IGNORECASE)
                    if matches:
                        sleep_time = int(matches[0])
                        print(f"[ALERT] SQL injection sleep detected! Sleeping for {sleep_time} seconds...")
                        time.sleep(sleep_time)
                        return True, sleep_time, header_name
                
                # If we found an indicator but no sleep value, default to 5 seconds
                print(f"[ALERT] SQL injection detected but no sleep value found. Defaulting to 5 seconds...")
                time.sleep(5)
                return True, 5, header_name
    
    return False, 0, None

@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        query = request.form.get('query', '')
        
        # Check for SQL injection in headers and simulate vulnerability
        sqli_detected, sleep_time, vulnerable_header = check_for_sqli_and_sleep(request.headers)
        
        # Show all headers for debugging
        all_headers = dict(request.headers)
        headers_display = '<br>'.join([f"<strong>{k}:</strong> {v}" for k, v in all_headers.items()])
        
        if sqli_detected:
            alert_message = f'''
                <div style="color: red; border: 2px solid red; padding: 10px; margin: 10px;">
                    <h3>🚨 SQL INJECTION DETECTED! 🚨</h3>
                    <p>Vulnerable Header: <strong>{vulnerable_header}</strong></p>
                    <p>Simulated Sleep Time: <strong>{sleep_time} seconds</strong></p>
                    <p>This simulates a time-based SQL injection vulnerability.</p>
                </div>
            '''
        else:
            alert_message = '<div style="color: green;">No SQL injection detected in headers.</div>'
        
        return f'''
            <h2>Search Results for: "{query}"</h2>
            {alert_message}
            <h3>Mock Results:</h3>
            <ul>
                <li>Result 1 for "{query}"</li>
                <li>Result 2 for "{query}"</li>
                <li>Result 3 for "{query}"</li>
            </ul>
            <h3>All Request Headers:</h3>
            <div style="background: #f0f0f0; padding: 10px; font-family: monospace;">
                {headers_display}
            </div>
            <br>
            <a href="/search">Search Again</a> | <a href="/">Home</a>
        '''
    
    return '''
        <h2>Search</h2>
        <form method="post">
            <input name="query" placeholder="Search query..." style="width: 300px; padding: 5px;"><br><br>
            <button type="submit" style="padding: 5px 10px;">Search</button>
        </form>
        <br>
        <a href="/">Back to Home</a>
        
        <div style="margin-top: 20px; padding: 10px; background: #e8f4f8; border-left: 4px solid #2196F3;">
            <h3>🧪 Testing SQL Injection</h3>
            <p>This endpoint will detect SQL injection patterns in request headers and simulate a vulnerable response by sleeping.</p>
            <p><strong>Patterns detected:</strong></p>
            <ul>
                <li><code>XOR(if(now()=sysdate()</code></li>
                <li><code>sleep(X)</code> - will sleep for X seconds</li>
                <li><code>SLEEP(X)</code> - case insensitive</li>
                <li><code>waitfor delay</code> - SQL Server style</li>
                <li><code>benchmark(</code> - MySQL style</li>
                <li><code>pg_sleep(</code> - PostgreSQL style</li>
            </ul>
        </div>
    '''

if __name__ == '__main__':
    app.run(port=9095)
