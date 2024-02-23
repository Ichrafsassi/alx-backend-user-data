import bcrypt
import uuid
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """Returns a salted hash of the input password."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        """Constructor method"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a user in the database."""
        if self._db.find_user_by(email=email):
            raise ValueError(f"User {email} already exists")
        hashed_password = self._hash_password(password)
        return self._db.add_user(email, hashed_password)

    def valid_login(self, email: str, password: str) -> bool:
        """Validate a user's credentials."""
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode("utf-8"),
                                  user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """Create a new session for the user"""
        session_id = str(uuid.uuid4())
        self._db.update_user_by_email(email, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> User:
        """Get a user from a session_id"""
        return self._db.find_user_by(session_id=session_id)

    def destroy_session(self, user_id: int) -> None:
        """Destroy a session"""
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Get a reset password token"""
        token = str(uuid.uuid4())
        self._db.update_user_by_email(email, reset_token=token)
        return token

    def update_password(self, reset_token: str, password: str) -> None:
        """Update a user's password"""
        hashed_password = self._hash_password(password)
        self._db.update_user_by_reset_token(reset_token,
                                            hashed_password, reset_token=None)

    def _hash_password(self, password: str) -> bytes:
        """Returns a salted hash of the input password."""
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
