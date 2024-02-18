#!/usr/bin/env python3
"""Module for epx auth"""
import os
from datetime import datetime as dt, timedelta
from .session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """ exp auth session class"""
    def __init__(self):
        """ constroctor for session exp"""
        super().__init__()
        self.session_duration = int(os.environ.get("SESSION_DURATION", 0))

    def create_session(self, user_id: int) -> str:
        """ create a session """
        session_id = super().create_session(user_id)
        if sessnion_id is None:
            return None
        self.user_id_for_session_id[session_id] = {
            'user_id': user_id,
            'created_at': dt.now()
        }
        return session_id

    def user_id_for_session_id(self, session_id: str) -> int:
        """ return usr id associated with the session id"""
        if session_id is None:
            return None
        if session_id not in self.user_id_for_session_id:
            return None
        session_dict = self.user_id_for_session_id.get(session_id)
        if session_dict is None:
            return None
        if self.session_duration <= 0:
            return session_dict.get('user_id')
        created_at = session_dict.get('created-at')
        if created_at is None:
            return None
        now = dt.now()
        if created_at + timedelta(seconds=self.session_duration) < now:
            return None
        exp_at = session_dict['created-at'] + \
            timedelta(seconds=self.session_duration)

        if exp_at < dt.now():
            return None
        return session_dict.get("user_id", None)
