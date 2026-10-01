from kfp.components import create_component_from_func


@create_component_from_func
def normalize_message(message: str) -> str:
    return message.strip()
