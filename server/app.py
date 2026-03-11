#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User, UserSchema

# Marshmallow serializer used to convert User objects to JSON
user_schema = UserSchema()


class ClearSession(Resource):

    def delete(self):

        # clears session values
        # useful during testing
        session['page_views'] = None
        session['user_id'] = None

        # 204 means successful but no response body
        return {}, 204



class Signup(Resource):

    def post(self):

        # get JSON data sent from frontend
        data = request.get_json()

        # create new user using the submitted username
        user = User(
            username=data['username']
        )

        # set password
        # this triggers the password_hash setter in the model
        # which automatically hashes the password using bcrypt
        user.password_hash = data['password']

        # save the new user to the database
        db.session.add(user)
        db.session.commit()

        # log the user in by saving their id in the session
        session['user_id'] = user.id

        # return the user as JSON
        return user_schema.dump(user), 201



class CheckSession(Resource):

    def get(self):

        # check if a user id exists in the session
        user_id = session.get('user_id')

        if user_id:

            # find the user in the database
            user = User.query.filter_by(id=user_id).first()

            if user:

                # return the authenticated user
                return user_schema.dump(user), 200

        # if no session exists return empty response
        return {}, 204



class Login(Resource):

    def post(self):

        # get login credentials from request
        data = request.get_json()

        # find user by username
        user = User.query.filter_by(username=data['username']).first()

        # if user exists AND password is correct
        if user and user.authenticate(data['password']):

            # store the user's id in the session (log them in)
            session['user_id'] = user.id

            # return user JSON
            return user_schema.dump(user), 200

        # if authentication fails
        return {'error': '401 Unauthorized'}, 401



class Logout(Resource):

    def delete(self):

        # remove the user id from the session
        # effectively logging them out
        session['user_id'] = None

        return {}, 204



# register API routes
api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')


if __name__ == '__main__':
    app.run(port=5555, debug=True)