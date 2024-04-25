import string
import random
import re


def is_float(s):
    try:
        float(s)
        return True
    except (ValueError, TypeError):
        return False


def is_int(s):
    try:
        int(s)
        return True
    except (ValueError, TypeError):
        return False


def generate_pydantic_model(data: dict, class_name: str):
    if isinstance(data, list):
        data = data[0]
    if not isinstance(data, dict):
        return

    print(f"class {class_name}(BaseModel):")
    after = []
    for key, value in data.items():
        if value is None:
            print(
                f"    {re.sub(r'(?<!^)(?=[A-Z])', '_', key.replace('-', '_')).lower()}: Optional[str] = Field(None, examples=[\"{value}\"], alias=\"{key}\")"
            )
        elif value == "True" or value == "False":
            print(
                f"    {re.sub(r'(?<!^)(?=[A-Z])', '_', key.replace('-', '_')).lower()}: Optional[bool] = Field(None, examples=[{value}], alias=\"{key}\")"
            )
        elif is_float(value):
            print(
                f"    {re.sub(r'(?<!^)(?=[A-Z])', '_', key.replace('-', '_')).lower()}: Optional[float] = Field(None, examples=[{value}], alias=\"{key}\")"
            )
        elif is_int(value):
            print(
                f"    {re.sub(r'(?<!^)(?=[A-Z])', '_', key.replace('-', '_')).lower()}: Optional[int] = Field(None, examples=[{value}], alias=\"{key}\")"
            )
        elif isinstance(value, dict):
            print(
                f"    {re.sub(r'(?<!^)(?=[A-Z])', '_', key.replace('-', '_')).lower()}: {key}"
            )
            after.append((key, value))
        elif isinstance(value, list):
            if len(value) > 0:
                print(
                    f"    {re.sub(r'(?<!^)(?=[A-Z])', '_', key.replace('-', '_')).lower()}: Optional[List[{key}]] = Field(None, examples=[\"\"], alias=\"{key}\")"
                )
                after.append((key, value[0]))
            else:
                print(
                    f"    {re.sub(r'(?<!^)(?=[A-Z])', '_', key.replace('-', '_')).lower()}: Optional[List[Any]] = Field(None, examples=[\"\"], alias=\"{key}\")  # todo needs model"
                )
        else:
            print(
                f"    {re.sub(r'(?<!^)(?=[A-Z])', '_', key.replace('-', '_')).lower()}: Optional[str] = Field(None, examples=[\"{value}\"], alias=\"{key}\")"
            )

    for a in after:
        generate_pydantic_model(a[1], a[0])


def stringify_dict(data: dict) -> dict:
    converted_data = {}
    for key, value in data.items():
        if isinstance(value, dict):
            converted_data[key] = stringify_dict(value)
        elif value is None:
            converted_data[key] = None
        elif isinstance(value, float):
            converted_data[key] = str(int(value))
        else:
            converted_data[key] = str(value)
    return converted_data
