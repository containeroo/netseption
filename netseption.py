import base64
import json
import logging
import logging.handlers
import os
import sys
from collections import namedtuple
from pathlib import Path
from urllib.parse import quote

import urllib3

try:
    import gitlab
    import requests
    import yaml
    from requests import HTTPError
except:
    sys.stderr.write("requirements are not satisfied! see 'requirements.txt'\n")
    sys.exit(1)

CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4"

__version__ = "0.0.1"


def check_env_vars():
    """get variables from env"""
    path_to_file = os.environ.get("PATH_TO_FILE")
    key_path = os.environ.get("KEY_PATH")

    gitlab_url = os.environ.get("GITLAB_URL")
    gitlab_token = os.environ.get("GITLAB_TOKEN")
    project_id = os.environ.get("PROJECT_ID")
    branch_name = os.environ.get("BRANCH")

    assignees = os.environ.get("ASSIGNEES")
    assignees = ([] if not assignees else
                 [a.strip() for a in assignees.split(",") if a])

    ssl_verify = os.environ.get("SSL_VERIFY", "true") == "true"

    commit_msg = os.environ.get("COMMIT_MESSAGE", "update networkrange")
    mergerequest_title = os.environ.get("MERGEREQUEST_TITLE")

    loglevel = os.environ.get("LOGLEVEL", "info")

    if not path_to_file:
        raise EnvironmentError("environment variable 'PATH_TO_FILE' not set!")

    if not key_path:
        raise EnvironmentError("environment variable 'KEY_PATH' not set!")

    if not gitlab_token:
        raise EnvironmentError("environment variable 'GITLAB_TOKEN' not set!")

    if not gitlab_url:
        raise EnvironmentError("environment variable 'GITLAB_URL' not set!")

    if not project_id:
        raise EnvironmentError("environment variable 'PROJECT_ID' not set!")

    Env_vars = namedtuple('Env_vars', ['path_to_file',
                                       'key_path',
                                       'gitlab_token',
                                       'gitlab_url',
                                       'project_id',
                                       'branch_name',
                                       'assignees',
                                       'commit_msg',
                                       'mergerequest_title',
                                       'loglevel',
                                       'ssl_verify'
                                       ]
                          )
    return Env_vars(
        path_to_file,
        key_path,
        gitlab_token,
        gitlab_url,
        project_id,
        branch_name,
        assignees,
        commit_msg,
        mergerequest_title,
        loglevel,
        ssl_verify
    )


def setup_logger(loglevel='info'):
    """setup logger"""
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    urllib3.disable_warnings()

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    loglevel = loglevel.lower()

    if loglevel == "critical":
        loglevel = logging.CRITICAL
    elif loglevel == "error":
        loglevel = logging.ERROR
    elif loglevel == "warning":
        loglevel = logging.WARNING
    elif loglevel == "info":
        loglevel = logging.INFO
    elif loglevel == "debug":
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO

    default_format = logging.Formatter(
        "%(asctime)s [%(levelname)-7.7s] %(message)s")
    debug_format = logging.Formatter(
        "%(asctime)s [%(filename)s:%(lineno)s - %(funcName)-20s ] %(message)s")

    console_logger = logging.StreamHandler(sys.stdout)
    console_logger.setLevel(loglevel)
    console_logger.setFormatter(
        debug_format if loglevel == logging.DEBUG else default_format)
    root_logger.addHandler(console_logger)


def get_cloudflare_ranges(url: str,
                          ssl_verify: bool = True,
                          timeout: int = 2) -> list:
    """get IPv4 range of CloudFlare

    Args:
        url (str): CloudFlare URL to fetch IP ranges
        ssl_verify (bool, optional): verify ssl cert. Defaults to True.
        timeout (int, optional): connection timeout. Defaults to 2.

    Raises:
        HTTPError: CloudFlare response is not ok

    Returns:
        list: list with CloudFlare IPv4 ranges
    """
    response = requests.get(
        url=url,
        timeout=timeout,
        verify=ssl_verify)

    if not response.ok:
        raise HTTPError(
            f"{response.status_code}: canont get IPv4 ranges from Cloudflare")

    return [r for r in response.text.split("\n") if r]


def Diff(list1: list, list2: list):
    """compare two lists"""
    return (list(list(set(list1)-set(list2)) + list(set(list2)-set(list1))))


def get_value(dictionary: dict,
              path: str,
              delimiter: str = ".") -> object:
    """get a value from a dict. path to key can be passed by a string, separated by a delimiter

    Args:
        dictionary (dict): dict to be search
        path (str): path with keys, separated by delimiter
        delimiter (str, optional): delimiter for path. Defaults to ".".

    Raises:
        TypeError: dictionary object is not a dict
        KeyError: key from path not found

    Returns:
        object: value from key
    """
    if not isinstance(dictionary, dict):
        raise TypeError(f"you must pass a dict. You pass {type(dictionary)}")

    keys = path.split(delimiter)
    for key in keys:
        if not isinstance(dictionary, dict):
            raise KeyError(f"key '{key}' not found")
        dictionary = dictionary.get(key)
        if not dictionary:
            raise KeyError(f"key '{key}' not found")

    return dictionary

def update_value(dictionary: dict,
                 path: str,
                 value: object,
                 delimiter: str = ".") -> dict:
    """update a value from a dict. path to key can be passed by a string, separated by a delimiter

    Args:
        dictionary (dict): dict to be updated
        path (str): path with keys, separated by delimiter
        value (object): value to update.
        delimiter (str, optional): delimiter for path. Defaults to ".".

    Raises:
        TypeError: dictionary object is not a dict
        KeyError: key from path not found

    Returns:
        dict: updated dictionary with new value
    """
    if not isinstance(dictionary, dict):
        raise TypeError(f"you must pass a dict. You pass {type(dictionary)}")

    keys = path.split(delimiter)
    key = keys[0]
    if not dictionary.get(key):
        raise KeyError(f"key '{key}' not found")
    if len(keys) > 1:
        path = delimiter.join(keys[1:])
        update_value(
            dictionary=dictionary[key],
            path=path,
            value=value,
            delimiter=delimiter
        )
    else:
        dictionary[key] = value
    return dictionary


def process_yaml(path_to_file: str,
                 key_path: str,
                 cloudflare_ranges: list) -> dict:
    """compare cloudflare IPv4 ranges with values of a yaml file

    Args:
        path_to_file (str): path to the yaml file
        cloudflare_ranges (list): list with CloudFlare IPv4 ranges

    Raises:
        FileNotFoundError: file not found
        ValueError: cannot open yaml
    Returns:
        dict: yaml file content with updated cloudflare IPv4 ranges
    """
    if not os.path.exists(path_to_file):
        raise FileNotFoundError(f"cannot open file '{path_to_file}'")

    try:
        with open(path_to_file, 'r') as data:
            yaml_content = yaml.safe_load(data)
    except Exception as e:
        raise ValueError(f"cannot open file '{path_to_file}'. {e}")

    current_nets = get_value(
        dictionary=yaml_content,
        path=key_path)

    if not Diff(cloudflare_ranges, current_nets):
        logging.info("IPv4 ranges are equal. nothing to do")
        sys.exit(0)

    new_content = update_value(
        dictionary=yaml_content,
        path=key_path,
        value=cloudflare_ranges)

    return new_content


def update_file(project: object,
                commit_msg: str,
                content: str,
                path_to_file: str,
                branch_name: str = 'master'):
    """update file on a gitlab project

    Args:
        project (gitlab.v4.objects.Project): gitlab project object
        commit_msg (str): commit message
        content (str): file content as string
        path_to_file (str): path to file on the gitlab project
        branch_name (str, optional): [description]. Defaults to 'master'.

    Raises:
        TypeError: project variable is not a type 'gitlab.v4.objects.Project'
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError("you must pass an 'gitlab.v4.objects.Project' object!")

    commited_file = project.files.get(
        file_path=path_to_file,
        ref=branch_name)

    base64_message = commited_file.content
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    commit_conntent = message_bytes.decode('ascii')

    if content == commit_conntent:
        logging.debug("current commit is up to date")
        return

    payload = {
        "branch": branch_name,
        "commit_message": commit_msg,
        "actions": [
            {
                'action': 'update',
                'file_path': path_to_file,
                'content': content,
            }
        ]
    }

    project.commits.create(payload)
    logging.info(f"successfully update file '{path_to_file}'")


def create_branch(project: object,
                  branch_name: str = 'master'):
    """create a branch on gitlab

    Args:
        project (gitlab.v4.objects.Project): gitlab project object
        branch_name (str, optional): [description]. Defaults to 'master'.

    Raises:
        TypeError: project variable is not of type 'gitlab.v4.objects.Project'
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError("you must pass an 'gitlab.v4.objects.Project' object!")

    try:
        project.branches.get(branch_name)
        logging.debug(f"branch '{branch_name}' already exists")
        return
    except gitlab.exceptions.GitlabGetError:
        logging.debug(f"branch '{branch_name}' not found")
    except:
        raise

    project.branches.create(
        {
            'branch': branch_name,
            'ref': 'master',
        })
    logging.info(f"successfully created branch '{branch_name}'")


def create_merge_request(project: object,
                         title: str,
                         branch_name: str = 'master',
                         assignee_ids: list = []):
    """create merge request on a gitlab project

    Args:
        project (gitlab.v4.objects.Project): gitlab project object
        title (str): title of branch
        branch_name (str, optional): name of branch. Defaults to 'master'.
        assignee_ids (list, optional): assign merge request to persons. Defaults to 'None'.

    Raises:
        TypeError: project variable is not of type 'gitlab.v4.objects.Project'
        ValueError: 'assignee_ids' must be a list
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError("you must pass an 'gitlab.v4.objects.Project' object!")

    if assignee_ids and not isinstance(assignee_ids, list):
        raise ValueError("assignee_ids must be a list")

    mrs = project.mergerequests.list(
        state='opened',
        order_by='updated_at')

    for mr in mrs:
        if mr.title != title:
            continue
        logging.debug(f"merge request '{title}' already exists")
        return

    mr = project.mergerequests.create(
        {
            'source_branch': branch_name,
            'target_branch': 'master',
            'title': title,
        })
    if assignee_ids:
        mr.todo()
        mr.assignee_ids = assignee_ids
        mr.save()

    logging.info(f"successfully created merge request '{title}'")


def main():
    try:
        env_vars = check_env_vars()
    except Exception as e:
        sys.stderr.write(f"{str(e)}\n")
        sys.exit(1)

    try:
        setup_logger(loglevel=env_vars.loglevel)
    except Exception as e:
        logging.critical(f"cannot setup logger. {e}")
        sys.exit(1)

    try:
        cloudflare_ranges = get_cloudflare_ranges(
            url=CLOUDFLARE_IPV4_URL,
            ssl_verify=env_vars.ssl_verify)
    except Exception as e:
        logging.critical(f"unable to process ansible yaml. {str(e)}")
        sys.exit(1)

    try:
        content = process_yaml(
            path_to_file=env_vars.path_to_file,
            key_path=env_vars.key_path,
            cloudflare_ranges=cloudflare_ranges)
        new_content = yaml.dump(content)
    except Exception as e:
        logging.critical(f"unable to process yaml. {str(e)}")
        sys.exit(1)

    try:
        cli = gitlab.Gitlab(
            url=env_vars.gitlab_url,
            private_token=env_vars.gitlab_token,
            ssl_verify=env_vars.ssl_verify)
    except Exception as e:
        logging.critical(f"unable to connect to gitlab. {str(e)}")
        sys.exit(1)

    try:
        project = cli.projects.get(int(env_vars.project_id))
    except gitlab.exceptions.GitlabGetError:
        logging.critical(f"project '{env_vars.project_id}' not found")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"unable to connect to gitlab. {str(e)}")
        sys.exit(1)

    if not env_vars.branch_name:
        logging.debug("no branch set. push direct to master")
    else:
        try:
            create_branch(
                project=project,
                branch_name=env_vars.branch_name
            )
        except Exception as e:
            logging.critical(f"unable to create branch. {str(e)}")
            sys.exit(1)

        try:
            assignee_ids = []
            for assignee in env_vars.assignees:
                try:
                    assignee = cli.users.list(search=assignee)
                    if not assignee:
                        logging.warning("cannot assign merge request to user "
                                        f"'{{env_vars.assignee}}'. "
                                        f"no user found {assignee}")
                        continue
                    assignee_ids.append(assignee[0].id)
                except Exception as e:
                    logging.error(
                        f"cannot get id of assignee '{assignee}'. {e}")

            filename = Path(env_vars.path_to_file).name
            create_merge_request(
                project=project,
                branch_name=env_vars.branch_name,
                title=(env_vars.mergerequest_title or
                       f"{filename}: update networkranges"),
                assignee_ids=assignee_ids
            )
        except Exception as e:
            logging.critical(f"unable to create merge request. {str(e)}")
            sys.exit(1)

    try:
        update_file(
            project=project,
            branch_name=env_vars.branch_name or "master",
            commit_msg=env_vars.commit_msg,
            content=new_content,
            path_to_file=env_vars.path_to_file,
        )
    except Exception as e:
        logging.critical(f"unable to upload file. {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
