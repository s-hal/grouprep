import json
import yaml


def load_file(file: str) -> dict:
    """
    Parse YAML or JONS file and return content

    :param file: file to load
    :type file: str
    :return: Content of file
    :rtype: dict
    """
    try:
        with open(file, encoding="utf-8") as f:
            if file.endswith(".json"):
                return json.load(f)
            elif file.endswith(".yaml"):
                return yaml.safe_load(f.read())
            else:
                raise ValueError("Unsuported file extension")
    except yaml.YAMLError as e:
        if hasattr(e, "problem_mark"):
            mark = e.problem_mark
            error_position = "({}:{})".format(mark.line + 1, mark.column + 1)
            raise ValueError(e, error_position)
        else:
            raise ValueError(e)
