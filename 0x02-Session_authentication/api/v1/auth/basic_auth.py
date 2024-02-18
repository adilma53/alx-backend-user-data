#!/usr/bin/env python3
""" module for basic auth"""
import base64
import binascii
from typing import Tuple, TypeVar

from models.user import User

from .auth import Auth


class BasicAuth(Auth):
    """basic auth class"""
    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """ extract base64 of auth header"""
        if authorization_header is None or not \
           isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header.split("Basic ")[1].strip()

    def decode_base64_authorization_header(
      self, base64_authorization_header: str) -> str:
        """ decode the base64 of auth header"""
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded = base64.b64decode(
                base64_authorization_header,
                validate=True
            )
        except (binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(self, decoded_header: str) -> Tuple[str, str]:
        """ extract user mail and password"""
        if decoded_header is None or not isinstance(decoded_header, str):
            return None, None
        try:
            email, password = decoded_header.split(':', 1)
        except ValueError:
            return None, None
        return email, password

    def user_object_from_credentials(
      self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """ returns the user instance based on the email and password"""
        if not all(map(lambda x: isinstance(x, str), (user_email, user_pwd))):
            return None
        try:
            user = User.search(attributes={'email': user_email})
        except Exception:
            return None
        if not user:
            return None
        user = user[0]
        if not user.is_valid_password(user_pwd):
            return None
        return user

    def current_user(self, request=None) -> TypeVar('User'):
        """ retieves the user instance for a requests """
        auth_hd = self.authorization_header(request)
        b64 = self.extract_base64_authorization_header(auth_hd)
        dec_hd = self.decode_base64_authorization_header(b64)
        user_email, user_pwd = self.extract_user_credentials(dec_hd)
        return self.user_object_from_credentials(user_email, user_pwd)
