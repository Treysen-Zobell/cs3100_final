from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str


class User(BaseModel):
    username: str
    email: str
    full_name: str
    disabled: bool
    department: str


class UserInDB(User):
    hashed_password: str
