"""
This system uses oauth2 to authenticate any api calls that depend on get_current_user.
user: Annotated[User, Depends(get_current_user)]

To add authentication requirement to call add a FastAPI Depends(get_current_user) to the args list on the function
associated with the route. Ex: def route(user: Annotated[User, Depends(get_current_user)]):. The user object this
returns can also be used for permission control by accessing user data, such as the permission to read or write a
specific service.

To use a call that requires authentication the client must first send an oauth2 standard authentication request to
receive a JWT token. The returned token can then be used for authentication for other requests by passing it in an
authentication header like 'Authentication: Bearer <token>'

Internally user data is stored in a SQL database. The username is used as the unique identifier for the user, and the
password is stored hashed. The password cannot be decoded, but it can be used as the salt when hashing another password
to verify that they are the same. A password run through the hash generates a salt that produces the same output when
provided with the same input password.
"""

import sqlite3
from datetime import timedelta, datetime, timezone
from typing import Annotated, Optional

import bcrypt
import secrets
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError

from app.models.auth import UserInDB
from app.utils.log import create_logger

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/v1/auth/login")
token_encryption_key = secrets.token_hex(32)
active_tokens = []

logger = create_logger(__name__)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies that the plain password hashes into the hashed password.
    :param plain_password: A plain text password, usually from an authentication request
    :param hashed_password: The hashed password, usually from the database
    :return: True if the passwords are equivalent after hashing
    """
    return hashed_password.encode() == bcrypt.hashpw(
        plain_password.encode(), hashed_password.encode()
    )


def hash_password(password: str) -> bytes:
    """
    Hashes the password using a randomly generated salt.
    :param password: A plain text password to be hashed
    :return: A hashed password
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password


def get_user(username: str) -> UserInDB | None:
    """
    Gets a user from the database by the username.
    :param username: The user's username
    :return: A UserInDB object containing user data, or None if the user didn't exist
    """
    connection = sqlite3.connect("db.sqlite")
    cursor = connection.cursor()
    user = cursor.execute(f"SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if user:
        return UserInDB(
            username=user[0],
            hashed_password=user[1],
            full_name=user[2],
            email=user[3],
            department=user[4],
            disabled=bool(user[5]),
        )


def create_user(
    username: str,
    password: str,
    full_name: str,
    email: str,
    department: str,
    disabled: bool,
):
    """
    Adds an entry for the new user to the database.
    :param username: A unique username
    :param password: A plain text password
    :param full_name: The user's name
    :param email: The user's email address
    :param department: The user's department
    :param disabled: Disable the user's account from making requests
    :return: None if successful
    """
    logger.debug(f"Creating new user {username}")
    hashed_password = hash_password(password)
    connection = sqlite3.connect("db.sqlite")
    cursor = connection.cursor()
    cursor.execute(
        f"INSERT INTO users VALUES (?, ?, ?, ?, ?, ?);",
        (username, hashed_password, full_name, email, department, disabled),
    )
    connection.commit()


def delete_user(username: str):
    """
    Remove a user entry from the database if it exists.
    :param username: The user's unique username
    :return: None if successful
    """
    logger.debug(f"Deleting user {username}")
    connection = sqlite3.connect("db.sqlite")
    cursor = connection.cursor()
    cursor.execute(f"DELETE FROM users WHERE username='{username}';")
    connection.commit()


def update_user(
    username: str,
    password: Optional[str] = None,
    full_name: Optional[str] = None,
    email: Optional[str] = None,
    department: Optional[str] = None,
    disabled: Optional[bool] = None,
):
    logger.debug(f"Updating user {username}")
    # Get user
    connection = sqlite3.connect("db.sqlite")
    cursor = connection.cursor()
    user = get_user(username)

    # Update user with supplied values
    if password:
        user.hashed_password = hash_password(password)
    user.full_name = full_name or user.full_name
    user.email = email or user.email
    user.department = department or user.department
    if disabled is not None:
        user.disabled = disabled

    cursor.execute(
        f"UPDATE users SET hashed_password = ?, full_name = ?, email = ?, department = ?, disabled = ? WHERE username = ?;",
        (
            user.hashed_password,
            user.full_name,
            user.email,
            user.department,
            user.disabled,
            user.username,
        ),
    )
    connection.commit()


def authenticate_user(username: str, password: str):
    """
    Gets a user from the database if a user with that username exists and the provided plain text password hashes into
    the correct password.
    :param username: The user's username
    :param password: The user's password
    :return: A UserInDB object containing user data or None if either the user didn't exist or the password was
    incorrect
    """
    logger.debug(f"Authenticating user {username}")
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(
    username: str, expires_delta: timedelta = timedelta(minutes=15)
) -> str:
    """
    Generates an encrypted JWT token containing the user's username and an expiration time used for additional requests.
    :param username: The user's username
    :param expires_delta: The time until the token expires, default 15 minutes
    :return: A string containing the JWT token
    """
    logger.debug(
        f"Generating access token for {username} with expiration {expires_delta}"
    )
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode = {
        "sub": username,
        "exp": expire,
    }
    encoded_jwt = jwt.encode(to_encode, token_encryption_key, algorithm="HS256")
    active_tokens.append(encoded_jwt)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> UserInDB:
    """
    Used in requests to enforce user authentication and returns the current user to allow for specific permissions,
    such as limiting routes.
    :param token: A JWT token generated by create_access_token used to authenticate each request
    :return: A UserInDB object containing the user's data
    :raises HTTPException: Code 401 if the token is invalid
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    global active_tokens
    tokens = []
    for token in active_tokens:
        if token["exp"] > datetime.now(timezone.utc):
            tokens.append(token)
    active_tokens = tokens

    try:
        payload = jwt.decode(token, token_encryption_key, algorithms=["HS256"])

        username: str = payload.get("sub")
        if username is None or token not in active_tokens:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    user = get_user(username=username)
    if user is None:
        raise credentials_exception
    return user
