from flask import Flask, request, redirect, url_for, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    return '''
        <h2>Welcome to the Test App</h2>
        <ul>
            <li><a href="/login">Login</a></li>
            <li><a href="/register">Register</a></li>
        </ul>
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
    return f'''
        <h2>Welcome {username}!</h2>
        <p>Your user-agent is:</p>
        <pre>{user_agent}</pre>
    '''

if __name__ == '__main__':
    app.run(port=9095)
