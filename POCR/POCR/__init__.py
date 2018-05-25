import os
from flask import Flask, render_template, request, redirect, flash, url_for, send_from_directory, g, session
from werkzeug.utils import secure_filename
import pytesseract
from PIL import Image
from POCR.db_connect import connection
from wtforms import Form, fields, validators, TextField, BooleanField, PasswordField
from passlib.hash import sha256_crypt
from pymysql import escape_string as thwart
import gc
from functools import wraps
from flask import send_file



__author__ = 'ittiRehan'

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config.from_object(__name__) # load config from this file , flaskr.py

UPLOAD_FOLDER = "POCR/Uploads/"
DOWNLOAD_FOLDER = "POCR/Downloads/"
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER
app.config['SESSION_TYPE'] = 'memcached'
app.config['SECRET_KEY'] = 'super secret key'

app.config.from_envvar('FLASKR_SETTINGS', silent=True)


@app.route("/")
def homepage():
    return render_template("index.html")


# wrapper for login page
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("You need to login first")
            return redirect(url_for('homepage'))

    return wrap




# after registeration

class RegistrationForm(Form):
    username = TextField('Username', [validators.Length(min=4, max=20)])
    email = TextField('Email Address', [validators.Length(min=6, max=50)])
    password = PasswordField('New Password', [
        validators.Required(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    accept_tos = BooleanField('I accept the Terms of Service and Privacy Notice (updated Jan 22, 2015)',
                              [validators.Required()])


@app.route("/register", methods=['GET', 'POST'])
def signUp_page():
    try:
        form = RegistrationForm(request.form)

        if request.method == "POST" and form.validate():
            username = form.username.data
            email = form.email.data
            password = sha256_crypt.encrypt((str(form.password.data)))
            c, conn = connection()

            x = c.execute("SELECT * FROM users WHERE username = (%s)",
                          (thwart(username)))

            if int(x) > 0:
                flash("That username is already taken, please choose another")
                return render_template('register.html', form=form)

            else:
                c.execute("INSERT INTO users (username, password, email, tracking) VALUES (%s, %s, %s, %s)",
                          (thwart(username), thwart(password), thwart(email),
                           thwart("/extract/")))

                conn.commit()
                flash("Thanks for registering!")
                c.close()
                conn.close()
                gc.collect()

                session['logged_in'] = True
                session['username'] = username

                return redirect(url_for('homepage'))

        return render_template("register.html", form=form)

    except Exception as e:
        return (str(e))



#for logging in
@app.route('/login', methods=["GET", "POST"])
def login_page():
    error = ''
    try:
        c, conn = connection()
        if request.method == "POST":

            data = c.execute("SELECT * FROM users WHERE username = (%s)",
                             thwart(request.form['username']))

            data = c.fetchone()[1]
            #username = request.form['username']
            #password = request.form['password']
            if sha256_crypt.verify(request.form['password'], data):
                session['logged_in'] = True
                session['username'] = request.form['username']

                flash("You are now logged in. Go to /logoff to log out of the session.")
                return redirect(url_for("homepage"))

            else:
                error = "Invalid credentials, try again."

        gc.collect()

        return render_template("login.html", error=error)

    except Exception as e:
        flash(e)
        error = "Invalid credentials, try again."
        return render_template("login.html", error=error)


# for logging out

@app.route("/logoff")
@login_required
def logoff():
    session.clear()
    flash("You have been logged out!")
    gc.collect()
    return redirect(url_for("homepage"))

# for checking which extensions are allowed for the conversions

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/extract", methods=['GET', 'POST'])
@login_required
def extractPage():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)

            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('uploaded_file',
                                    filename=filename))
    return render_template("upload.html")


@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    try:
        path_to_file =os.path.join(app.config['UPLOAD_FOLDER'], filename)

        im = Image.open(path_to_file,'r')
        pytesseract.pytesseract.tesseract_cmd = 'C:\\Users\\HP\\Tesseract-OCR\\tesseract.exe'

        text = pytesseract.image_to_string(im, lang='eng')

        c, conn = connection()

        c.execute("insert into converted_text(img_loc, con_txt) values(%s, %s)", (path_to_file, text))
        username = session['username']
        c.execute("insert into user_image(username,img_loc, con_txt) values(%s, %s, %s)", (username,path_to_file, text))


        conn.commit()
        c.close()
        conn.close()

        # wriitng txt file
        new_file_name = filename.split('.')[0] + ".txt"
        fo = open(os.path.join(app.config['DOWNLOAD_FOLDER'], new_file_name), "w")
        fo.write(text)
        fo.close()


        return text

    except Exception as e:
        return(str(e))




@app.route("/contact")
@login_required
def contactpage():
    return render_template("contact.html")

if __name__ == "__main__":

    app.debug = True
    app.run()
