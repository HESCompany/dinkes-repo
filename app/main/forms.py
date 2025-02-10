from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

class UploadFileForm(FlaskForm):
    file = FileField('File', validators=[
        FileRequired(),
        FileAllowed(['pdf', 'jpg', 'jpeg', 'png'], 'Only PDF, JPG, JPEG, and PNG files are allowed!')
    ])
    judul = StringField('Judul', validators=[DataRequired()])
    nama_penulis = StringField('Nama Penulis', validators=[DataRequired()])
    nim = StringField('NIM', validators=[DataRequired()])
    university_name = StringField('University Name', validators=[DataRequired()])
    major = StringField('Major', validators=[DataRequired()])
    tags = StringField('Tags', validators=[DataRequired()])
    submit = SubmitField('Upload')
