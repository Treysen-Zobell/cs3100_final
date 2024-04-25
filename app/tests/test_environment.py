import pytest

from app.utils.environment import get_environment_var


def test_get_environment_var():
    """
    Test the get_environment_var by fetching an environment variable that does not exist, one from the .env, and PATH
    from the global environment.
    :return:
    """
    with pytest.raises(ValueError):
        get_environment_var("THIS_VAR_SHOULD_NOT_EXIST")

    local_var = get_environment_var("LOCAL_TEST_VALUE")
    assert local_var is not None
    assert local_var == "value"
    assert get_environment_var("PATH") is not None
