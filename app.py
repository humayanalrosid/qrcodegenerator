from flask import Flask, render_template, request, redirect, send_file, session, flash
import qrcode
from io import BytesIO
import base64
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user

app = Flask(__name__)
app.secret_key = "arTiveRInExp"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///db.sqlite"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

MAX_TAPS = 5

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(80), nullable = True)
    username = db.Column(db.String(50), unique = True, nullable = False)
    email = db.Column(db.String(60), unique = True, nullable = False)
    password = db.Column(db.String(60), nullable = False)
    
    def __repr__(self):
        return f"<User {self.username}>"
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def home():
    if 'tap_count' not in session:
        session['tap_count'] = 0
        
    if request.method == 'POST':
        data = request.form['data']
        
        if not data:
            flash('Please enter a text or URL.', 'warning')
            return redirect('/')
        
        session['tap_count'] += 1
        
        if session['tap_count'] > MAX_TAPS:
            flash('There are only 5 free QR codes a day. Sign up to get more.', 'error')
            return redirect('/')
        
        img = qrcode.make(data)
        img_io = BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        qr = 'data:image/png;base64,' + base64.b64encode(img_io.getvalue()).decode()
        
        session['qr_data'] = data 
        flash('Qr code generated successfully!', 'success')
        return render_template('home.html', 
                               qr=qr, 
                               max_tap = MAX_TAPS, 
                               tap=session.get('tap_count', 0))
    
    return render_template('home.html', 
                           max_tap = MAX_TAPS, 
                           tap=session.get('tap_count', 0))

@app.route('/download', methods=['GET'])
def download():
    data = session.get('qr_data') 
    if data:
        img = qrcode.make(data)
        img_io = BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)

        response = send_file(img_io, mimetype='image/png')
        response.headers.add('Content-Disposition', 'attachment', filename='qrcode.png')
        return response
    else:
        flash('Please provide data parameter.', 'warning')
        return render_template('home.html')

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if not current_user.is_authenticated:
        if request.method == "POST":
            name = request.form['name']
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            
            if username == '' or email == '' or password == '':
                flash('Please fill all the fields.', 'warning')
                return redirect('/signup')            
            else:
                check_user = User.query.filter_by(username=username).first()
                check_email = User.query.filter_by(email=email).first()
                
                if check_user:
                    flash('Username already exists.', 'warning')
                    return redirect('/signup')
                
                elif check_email:
                    flash('Email already exists.', 'warning')
                    return redirect('/signup')
                
                elif len(username) < 4:
                    flash('Username must be at least 4 characters long.', 'warning')
                    return redirect('/signup')
                
                elif len(password) < 8:
                    flash('Password must be at least 8 characters long.', 'warning')
                    return redirect('/signup')

                else:
                    new_user = User(name=name, 
                                    username=username, 
                                    email=email, 
                                    password=password)
                
                    db.session.add(new_user)
                    db.session.commit()
                    
                    flash('You have been registered successfully.', 'success')
                    return redirect('/login')  

        return render_template('signup.html')
    else:
        flash('You are already logged in.', 'warning')
        return redirect('/')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if not current_user.is_authenticated:
        if request.method == "POST":
            username = request.form['username']
            password = request.form['password']
            
            if username == '' or password == '':
                flash('Please fill all the fields.', 'warning')
                return redirect('/login')
            else:
                user = User.query.filter_by(username=username).first()
                
                if user and user.password == password:
                    login_user(user)
                    flash('You have successfully logged in!', 'success')
                    return redirect("/")
                else:
                    flash('Invalid username/password!', 'warning')
                    return redirect("login")

        return render_template('login.html')
    else:
        flash('You are already logged in.', 'warning')
        return redirect('/')

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect('/')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
    