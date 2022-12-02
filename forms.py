from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, PasswordField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError


class RegistrationForm(FlaskForm):
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=2, max=20)]
    )
    group = SelectField("Group", validators=[DataRequired()], choices=["staff", "admin"])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Create")


class LoginForm(FlaskForm):
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=2, max=20)]
    )

    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class AddBotForm(FlaskForm):
    id = IntegerField("Bot Id", validators=[DataRequired()])


    type = SelectField("Type", validators=[DataRequired()], choices=["Forklift", "Mover"])
    submit = SubmitField("Add")
