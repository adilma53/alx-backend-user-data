#!/usr/bin/env python3

import os
from os import getenv
from typing import Tuple

from flask import Flask, abort, jsonify, request
from flask_cors import CORS, cross_origin

from api.v1.auth.auth import Auth
from api.v1.auth.basic_auth import BasicAuth
from api.v1.auth.session_auth import SessionAuth
from api.v1.auth.session_db_auth import SessionDBAuth
from api.v1.auth.session_exp_auth import SessionExpAuth
from api.v1.views import app_views


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})
auth = None

auth_type = getenv('AUTH_TYPE', 'default')
if auth_type == "basic_auth":
    auth = BasicAuth()
elif auth_type == "session_exp_auth":
    auth = SessionAuth()
elif auth_type == "session_db_auth":
    auth = SessionDBAuth()
else:
    auth = Auth()


@app.errorhandler(404)
def not_found(error) -> str:
    """Not found handler"""
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(401)
def unauthorized(error: Exception) -> Tuple[jsonify, int]:
    """ Not auth handler """
    return jsonify({'error': 'Unauthorized'}), 401


@app.errorhandler(403)
def forbidden(error: Exception) -> Tuple[jsonify, int]:
    """ forbidden handler"""
    return jsonify({'error': 'Forbidden'}), 403


@app.before_request
def before_requests():
    """ handle before rendering """
    if auth is None:
        return
    excluded_paths = ['/api/v1/status/',
                      '/api/v1/unauthorized/',
                      '/api/v1/forbidden/',
                      '/api/v1/auth_session/login/']
    if not auth.require_auth(request.path, excluded_paths):
        return
    auth_hd = auth.authorization_header(request)
    session_ck = auth.session_cookie(request)
    if auth_hd is None and session_ck is None:
        abort(401)
    user = auth.current_user(request)
    if user is None:
        abort(403)
    request.current_user = user


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port, debug=True)
