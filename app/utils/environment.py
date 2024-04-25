import os

from dotenv import dotenv_values


LOCAL_ENVIRONMENT = dotenv_values(".env")


def get_environment_var(name: str) -> str:
    global_env = os.environ.get(name)
    local_env = LOCAL_ENVIRONMENT.get(name)

    if not global_env and not local_env:
        raise ValueError(f"Environment variable '{name}' not found")

    return local_env or global_env


API_URL = get_environment_var("API_URL")
LOG_LEVEL = get_environment_var("LOG_LEVEL")
LOG_FILE = get_environment_var("LOG_FILE")
