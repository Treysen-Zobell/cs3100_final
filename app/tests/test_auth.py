import asyncio
import pytest
from fastapi import HTTPException

from app.models.auth import User
from app.services.auth import (
    hash_password,
    verify_password,
    get_user,
    create_user,
    delete_user,
    authenticate_user,
    create_access_token,
    get_current_user,
    update_user,
)


def test_hash_password():
    """
    Test that password can be hashed, and that password verification works.
    :return:
    """
    raw_password = "thisisatestpassword1234!@#$"
    hashed_password = hash_password(raw_password)
    assert isinstance(hashed_password, bytes)
    assert verify_password(raw_password, hashed_password.decode())


def test_get_user():
    """
    Tests that the test user in the database can be grabbed with the right data.
    :return:
    """
    assert get_user("") is None
    test_user = get_user("testuser")
    assert test_user is not None
    assert test_user.username == "testuser"
    assert test_user.email == "test@email.com"
    assert test_user.full_name == "Testy User"
    assert test_user.disabled
    assert test_user.department == "testdepartment"


@pytest.mark.depends(on=["test_get_user"])
def test_create_user():
    if get_user("testuser2"):
        delete_user("testuser2")

    create_user(
        "testuser2",
        "nosifudnvliunr9vnso79843hof8",
        "Testy User2",
        "test@email.com2",
        "testdepartment2",
        True,
    )
    user = get_user("testuser2")
    assert isinstance(user, User)
    assert user.username == "testuser2"
    assert user.hashed_password != "nosifudnvliunr9vnso79843hof8"
    assert user.full_name == "Testy User2"
    assert user.email == "test@email.com2"
    assert user.department == "testdepartment2"
    assert user.disabled


@pytest.mark.depends(on=["test_create_user", "test_get_user"])
def test_delete_user():
    if not get_user("testuser2"):
        create_user(
            "testuser2",
            "nosifudnvliunr9vnso79843hof8",
            "Testy User2",
            "test@email.com2",
            "testdepartment2",
            True,
        )
    delete_user("testuser2")
    assert not get_user("testuser2")


@pytest.mark.depends(on=["test_create_user", "test_get_user", "test_delete_user"])
def test_update_user():
    if get_user("testuser2"):
        delete_user("testuser2")

    create_user(
        "testuser2",
        "nosifudnvliunr9vnso79843hof8",
        "Testy User2",
        "test@email.com2",
        "testdepartment2",
        True,
    )

    # No changes
    update_user("testuser2")
    user = get_user("testuser2")
    assert isinstance(user, User)
    assert user.username == "testuser2"
    assert user.hashed_password != "nosifudnvliunr9vnso79843hof8"
    assert user.full_name == "Testy User2"
    assert user.email == "test@email.com2"
    assert user.department == "testdepartment2"
    assert user.disabled

    # Change password
    update_user("testuser2", password="ndinvsoifdnvusioljfv")
    user = get_user("testuser2")
    assert isinstance(user, User)
    assert user.username == "testuser2"
    assert user.hashed_password != "ndinvsoifdnvusioljfv"
    assert user.full_name == "Testy User2"
    assert user.email == "test@email.com2"
    assert user.department == "testdepartment2"
    assert user.disabled

    # Change full name
    update_user("testuser2", full_name="Testy User2 Electric Boogaloo")
    user = get_user("testuser2")
    assert isinstance(user, User)
    assert user.username == "testuser2"
    assert user.hashed_password != "ndinvsoifdnvusioljfv"
    assert user.full_name == "Testy User2 Electric Boogaloo"
    assert user.email == "test@email.com2"
    assert user.department == "testdepartment2"
    assert user.disabled

    # Change email
    update_user("testuser2", email="test@email.net")
    user = get_user("testuser2")
    assert isinstance(user, User)
    assert user.username == "testuser2"
    assert user.hashed_password != "ndinvsoifdnvusioljfv"
    assert user.full_name == "Testy User2 Electric Boogaloo"
    assert user.email == "test@email.net"
    assert user.department == "testdepartment2"
    assert user.disabled

    # Change email
    update_user("testuser2", department="notexists")
    user = get_user("testuser2")
    assert isinstance(user, User)
    assert user.username == "testuser2"
    assert user.hashed_password != "ndinvsoifdnvusioljfv"
    assert user.full_name == "Testy User2 Electric Boogaloo"
    assert user.email == "test@email.net"
    assert user.department == "notexists"
    assert user.disabled

    # Change disabled
    update_user("testuser2", disabled=False)
    user = get_user("testuser2")
    assert isinstance(user, User)
    assert user.username == "testuser2"
    assert user.hashed_password != "ndinvsoifdnvusioljfv"
    assert user.full_name == "Testy User2 Electric Boogaloo"
    assert user.email == "test@email.net"
    assert user.department == "notexists"
    print("")
    print(user.disabled)
    print("")
    assert not user.disabled

    # Change all
    update_user(
        "testuser2",
        password="nosifudnvliunr9vnso79843hof8",
        full_name="Testy User2",
        email="test@email.com2",
        department="testdepartment2",
        disabled=True,
    )
    user = get_user("testuser2")
    assert isinstance(user, User)
    assert user.username == "testuser2"
    assert user.hashed_password != "nosifudnvliunr9vnso79843hof8"
    assert user.full_name == "Testy User2"
    assert user.email == "test@email.com2"
    assert user.department == "testdepartment2"
    assert user.disabled

    delete_user("testuser2")
    assert not get_user("testuser2")


@pytest.mark.depends(on=["test_create_user", "test_get_user", "test_delete_user"])
def test_authenticate_user():
    if get_user("testuser2"):
        delete_user("testuser2")

    create_user(
        "testuser2",
        "nosifudnvliunr9vnso79843hof8",
        "Testy User2",
        "test@email.com2",
        "testdepartment2",
        True,
    )

    assert authenticate_user("testuser2", "nosifudnvliunr9vnso79843hof8")
    delete_user("testuser2")
    assert not get_user("testuser2")


def test_create_access_token():
    """
    Tests that a token can be created, verified, and that an invalid token raises a HTTPException
    :return:
    """
    token = create_access_token("testuser")
    assert isinstance(token, str)
    user = asyncio.run(get_current_user(token))
    assert user.username == "testuser"
    with pytest.raises(HTTPException):
        asyncio.run(get_current_user("anveryinvalidtoken"))
