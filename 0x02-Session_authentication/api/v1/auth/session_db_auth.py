#!/usr/bin/env python3
"""Module session db auth
"""
from datetime import datetime, timedelta
from models.user_session import UserSession
from .session_exp_auth import SessionExpAuth


class SessionDBAuth(SessionExpAuth):
    """ session db auth """
    def create_session(self, user_id: str) -> str:
        """ create a stores of session key"""
        session_id = super().create_session(user_id)

        if isinstance(session_id, str):
            kwargs = {
                'user_id': user_id,
                'session_id': session_id,
            }
            user_session = UserSession(**kwargs)
            user_session.save()
            return session_id

    def user_id_for_session_id(self, session_id: str) -> str:
        """ retrieves the user id """
        try:
            sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return None
        if len(sessions) <= 0:
            return None
        current_tm = datetime.now()
        span = timedelta(seconds=self.session_duration)
        exp_tm = sessions[0].created_at + span
        if exp_tm < current_tm:
            return None
        return sessions[0].user_id

    def destroy_session(self, request=None) -> bool:
        """ destory an auth session """
        session_id = self.session_cookie(request)
        try:
            session = UserSession.search({'session_id': session_id})
        except Exception:
            return False
        sessions[0].remove()
        return True
