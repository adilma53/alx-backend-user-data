#!/usr/bin/env python3
""" module for authentication"""
from typing import List, TypeVar

from flask import request


class Auth():
    """class represent the the authentication"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ func that returns False -
        path and excluded_paths will be used later,
        now, you don’t need to take care of them """
        if not path:
            return True
        if not excluded_paths:
            return True
        path = path.rstrip("/")
        for excluded_path in excluded_paths:
            if excluded_path.endswith("*") and \
                   path.startswith(excluded_path[:1]):
                return False
            elif path == excluded_path.rstrip("/"):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """ gets the value of autho header from reqs"""
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ func take reqs and return value type user"""
        return None
