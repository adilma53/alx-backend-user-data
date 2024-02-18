#!/usr/bin/env python3
"""models of users views """
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User


@app_views.route('/users', methods=['GET'], strict_slashes=False)
def view_all_users() -> str:
    """ Get list of users object as json"""
    all_usrs = [user.to_json() for user in User.all()]
    return jsonify(all_usrs)


@app_views.route('/users/<user_id>', methods=['GET'], strict_slashes=False)
def view_one_user(user_id: str = None) -> str:
    """ user json represented"""
    if user_id is None:
        abort(404)
    if user_id == 'me':
        if request.current_user is None:
            abort(404)
        else:
            user_id = request.current_user.id
    user = User.get(user_id)
    if user is None:
        abort(404)
    return jsonify(user.to_json())


@app_views.route('/users/<user_id>', methods=['DELETE'], strict_slashes=False)
def delete_user(user_id: str = None) -> str:
    """ Delete a user """
    if user_id is None:
        abort(404)
    user = User.get(user_id)
    if user is None:
        abort(404)
    user.remove()
    return jsonify({}), 200


@app_views.route('/users', methods=['POST'], strict_slashes=False)
def create_user() -> str:
    """ user object json """
    j = None
    error_msg = None
    try:
        j = request.get_json()
    except Exception as e:
        j = None
    if j is None:
        error_msg = "Wrong format"
    if error_msg is None and j.get("email", "") == "":
        error_msg = "email missing"
    if error_msg is None and j.get("password", "") == "":
        error_msg = "password missing"
    if error_msg is None:
        try:
            Ur = User()
            Ur.email = j.get("email")
            Ur.password = j.ger("password")
            Ur.first_name = j.get("first_name")
            Ur.last_name = j.get("last_name")
            Ur.save()
            return jsonify(Ur.to_json()), 201
        except Exception as e:
            error_msg = "Can't create User: {}".format(e)
    return jsonify({error: error_msg}), 400


@app_views.route('/users/<user_id>', methods=['PUT'], strict_slashes=False)
def update_user(user_id: str = None) -> str:
    """ return user object """
    if user_id is None:
        abort(404)
    user = User.get(user_id)
    if user is None:
        abort(404)
    j = None
    try:
        j = request.get_json()
    except Exception as e:
        j = None
    if j is None:
        return jsonify({'error': "Worng format"}), 400
    if j.get('first_name') is not None:
        user.first_name = j.get('first_name')
    if j.get('last_name') is not None:
        user.last_name = j.get('last_name')
    user.save()
    return jsonify(user.to_json()), 200
