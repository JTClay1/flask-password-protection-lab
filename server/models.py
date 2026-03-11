from sqlalchemy.ext.hybrid import hybrid_property
from marshmallow import Schema, fields

from config import db, bcrypt

class User(db.Model):
    __tablename__ = 'users'

    # Primary key for user
    id = db.Column(db.Integer, primary_key=True)

    # Username the user signs up with
    username = db.Column(db.String)

    # This stores the hashed password (NOT the real password)
    _password_hash = db.Column(db.String)


    # Hybrid property prevents direct access to the password hash
    # If someone tries to read user.password_hash it throws an error
    # This protects the hashed password from being exposed
    @hybrid_property
    def password_hash(self):
        raise Exception('Password hashes may not be viewed.')


    # This setter runs when we assign a password
    # Example: user.password_hash = "mypassword"
    # It takes the plain password, hashes it using bcrypt,
    # then stores the hash in the database column _password_hash
    @password_hash.setter
    def password_hash(self, password):

        # bcrypt generates a secure hash of the password
        password_hash = bcrypt.generate_password_hash(password.encode('utf-8'))

        # store the decoded hash string in the database
        self._password_hash = password_hash.decode('utf-8')


    # Authenticate compares the password the user typed
    # with the stored hashed password
    # Returns True if they match, False if they don't
    def authenticate(self, password):

        return bcrypt.check_password_hash(
            self._password_hash,         # stored hashed password
            password.encode('utf-8')     # password user typed
        )


    def __repr__(self):
        return f'User {self.username}, ID: {self.id}'


# Marshmallow schema controls how User objects are converted to JSON
# Only id and username are exposed (never password hash)
class UserSchema(Schema):
    id = fields.Int()
    username = fields.String()