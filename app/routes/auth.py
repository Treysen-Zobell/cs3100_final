import sqlite3
from datetime import timedelta
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.models.auth import Token, User
from app.services.auth import (
    authenticate_user,
    create_access_token,
    get_current_user,
    create_user,
    delete_user,
    update_user,
)

router = APIRouter(prefix="/auth")


@router.post(
    "/login",
    summary="Generate an access token",
    description="Verify the user credentials against the database, if they are correct return a temporary JWT access "
    "token to authenticate additional requests. When the token expires another will need to be acquired by sending "
    "another login request. To authenticate a request supply the token in an authorization header.",
)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=15)
    access_token = create_access_token(
        user.username, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@router.post("/users/{username}")
async def create_new_user(
    username: str,
    password: str,
    department: str,
    user: Annotated[User, Depends(get_current_user)],
    email: str = "",
    full_name: str = "",
    disabled: bool = True,
):
    try:
        create_user(username, password, full_name, email, department, disabled)
    except sqlite3.Error as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.patch("/users/{username}")
async def edit_existing_user(
    username: str,
    user: Annotated[User, Depends(get_current_user)],
    password: Optional[str] = None,
    department: Optional[str] = None,
    email: Optional[str] = None,
    full_name: Optional[str] = None,
    disabled: Optional[bool] = None,
):
    try:
        update_user(username, password, full_name, email, department, disabled)
    except sqlite3.Error as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/users/{username}")
async def delete_existing_user(
    username: str,
    user: Annotated[User, Depends(get_current_user)],
):
    try:
        delete_user(username)
    except sqlite3.Error as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/test", include_in_schema=False)
async def test_authorization(user: Annotated[User, Depends(get_current_user)]):
    return user.username
