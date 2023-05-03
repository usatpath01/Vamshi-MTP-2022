from flask import Flask, render_template
from form import *
from models import *
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

app = Flask(__name__)
app.secret_key = 'replace_later'
app.config['SQLALCHEMY_DATABASE_URI']='postgresql://postgres:postgres@localhost:5432/mtp'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

@app.route("/", methods=['GET', 'POST'])
def index():
    reg_form = RegistrationForm()
    if reg_form.validate_on_submit():
        username = reg_form.username.data
        password = reg_form.password.data
        print("The entered username is", username)
        print("the entered password is", password)

        user_object = db.session.query(User).filter(User.username==username).first()
        # Accessing the selected rows
        # for row in user_object:
        #   print(row.username, row.password)
        if user_object:
            return "User name taken."
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        return "Successful registration"
        
    return render_template("index.html", form=reg_form)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')