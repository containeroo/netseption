import json
import logging
import logging.handlers
import os
import sys
from collections import namedtuple
from pathlib import Path
from urllib.parse import quote

import gitlab
import requests
import urllib3
import yaml
from requests import HTTPError

CLOUDFLARE_IPV_URL = "https://www.cloudflare.com/ips-v4"

__version__ = "0.0.1"


def check_env_vars():
    """get variables from env"""
    file_path = os.environ.get("FILE_PATH")
    yaml_path = os.environ.get("YAML_PATH")

    gitlab_url = os.environ.get("GITLAB_URL")
    gitlab_token = os.environ.get("GITLAB_TOKEN")
    project_id = os.environ.get("PROJECT_ID")
    branch_name = os.environ.get("BRANCH")
    ssl_verify = os.environ.get("SSL_VERIFY", "true") == "true"

    commit_msg = os.environ.get("COMMIT_MESSAGE", "update networkrange")
    mergerequest_title = os.environ.get("MERGEREQUEST_TITLE")

    loglevel = os.environ.get("LOGLEVEL", "info").lower()

    if not file_path:
        raise EnvironmentError(
            "environment variable 'FILE_PATH' not set!")

    if not yaml_path:
        raise EnvironmentError(
            "environment variable 'YAML_PATH' not set!")

    if not gitlab_token:
        raise EnvironmentError(
            "environment variable 'GITLAB_TOKEN' not set!")

    if not gitlab_url:
        raise EnvironmentError(
            "environment variable 'GITLAB_URL' not set!")

    if not project_id:
        raise EnvironmentError(
            "environment variable 'PROJECT_ID' not set!")

    Env_vars = namedtuple('Env_vars', ['file_path',
                                       'yaml_path',
                                       'gitlab_token',
                                       'gitlab_url',
                                       'project_id',
                                       'branch_name',
                                       'commit_msg',
                                       'mergerequest_title',
                                       'loglevel',
                                       'ssl_verify'
                                       ]
                          )
    return Env_vars(
        file_path,
        yaml_path,
        gitlab_token,
        gitlab_url,
        project_id,
        branch_name,
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

    default_format = logging.Formatter("%(asctime)s [%(levelname)-7.7s] %(message)s")
    console_logger = logging.StreamHandler(sys.stdout)
    console_logger.setLevel(loglevel)
    console_logger.setFormatter(default_format)
    root_logger.addHandler(console_logger)


def get_cloudflare_nets(url: str, ssl_verify: bool, timeout: int = 2) -> list:
    """get IPv4 range of CloudFlare

    Args:
        url (str): CloudFlare URL to fetch IP ranges
        ssl_verify (bool): verify cert
        timeout (int, optional): connection timeout. Defaults to 2.

    Raises:
        HTTPError: CloudFlare response is not ok

    Returns:
        [type]: list with CloudFlare IPv4 ranges
    """
    response = requests.get(
        url=url,
        timeout=timeout,
        verify=ssl_verify)

    if not response.ok:
        raise HTTPError(f"{response.status_code}: canont get IPv4 nets from Cloudflare")

    return [r for r in response.text.split("\n") if r]


def Diff(list1, list2):
    """compare two lists"""
    return (list(list(set(list1)-set(list2)) + list(set(list2)-set(list1))))


def get_value(dict_: dict, path: str) -> object:
"""get a value from a dict, key passed as dotted path (a.b.c)

    Args:
        dict_ (dict): dict to be search
        path (str): path with keys, separated with a dot (a.b.c)

    Raises:
        TypeError: dict_ object is not a dict

    Returns:
        object: value from key
    """
    if not isinstance(dict_, dict):
        raise TypeError("you must pass a dict")

    keys = path.split('.', 1)
    key = keys[0]
    value = dict_.get(key)
    if not value:
        return None
    if len(keys) > 1:
        path = keys[1]
        return get_value(dict_[key], path)
    return value


def update_value(dict_: dict, path: str, value: object = None) -> dict:
    """update a value from a dict, key passed as dotted path (a.b.c)

    Args:
        dict_ (dict): dict to be updated
        path (str): path with keys, separated with a dot (a.b.c)
        value (object, optional): [description]. Defaults to None.

    Raises:
        TypeError: dict_ object is not a dict

    Returns:
        dict: updated dict
    """
    if not isinstance(dict_, dict):
        raise TypeError("you must pass a dict")

    keys = path.split('.', 1)
    key = keys[0]
    if len(keys) > 1:
        path = keys[1]
        update_value(dict_[key], path, value)
    else:
        dict_[key] = value
    return dict_


def process_yaml(file_path: str, yaml_path: str, cloudflare_nets: list) -> dict:
    """compare cloudflare IPv4 ranges with values of a yaml file

    Args:
        file_path (str): path to the yaml file
        cloudflare_nets (list): list with CloudFlare IPv4 nets

    Raises:
        FileNotFoundError: file not found
        ValueError: cannot open yaml
    Returns:
        dict: yaml file with updated cloudflare IPv4 ranges
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"cannot open file '{file_path}'")

    try:
        with open(file_path, 'r') as conf:
            yaml_content = yaml.safe_load(conf)
    except Exception as e:
        raise ValueError(f"cannot open file '{file_path}'. {e}")

    current_nets = get_value(
        dict_=yaml_content,
        path=yaml_path)

    if not Diff(cloudflare_nets, current_nets):
        logging.info("IPv4 nets are equal. nothing to do")
        sys.exit(0)

    new_content = update_value(
        dict_=yaml_content,
        path=yaml_path,
        value=cloudflare_nets)

    return new_content


def update_file(project: object,
                commit_msg: str,
                content: str,
                file_path: str,
                branch_name: str = 'master'):
    """update file on a gitlab project

    Args:
        project (gitlab.v4.objects.Project): gitlab project object
        commit_msg (str): commit message
        content (str): file content as string
        file_path (str): path to file on the gitlab project
        branch_name (str, optional): [description]. Defaults to 'master'.

    Raises:
        TypeError: project variable is not a type 'gitlab.v4.objects.Project'
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError("you must pass an 'gitlab.v4.objects.Project' object!")

    payload = {
        "branch": branch_name,
        "commit_message": commit_msg,
        "actions": [
            {
                'action': 'update',
                'file_path': file_path,
                'content': content,
            }
        ]
    }

    project.commits.create(payload)
    logging.info(f"successfully update file '{file_path}'")


def create_branch(project: object, branch_name: str = 'master'):
    """create a branch on gitlab

    Args:
        project (gitlab.v4.objects.Project): gitlab project object
        branch_name (str, optional): [description]. Defaults to 'master'.

    Raises:
        TypeError: project variable is not a type 'gitlab.v4.objects.Project'
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError("you must pass an 'gitlab.v4.objects.Project' object!")

    branch = project.branches.get("branch_name")
    if branch:
        logging.debug(f"branch '{branch_name}' already exists")
        return

    project.branches.create(
        {
            'branch': branch_name,
            'ref': 'master'
        })
    logging.info(f"successfully created branch '{branch_name}'")


def create_merge_request(project: object, title: str, branch_name: str = 'master'):
    """create merge request on gitlab

    Args:
        project (gitlab.v4.objects.Project): gitlab project object
        title (str): title of branch
        branch_name (str, optional): [description]. Defaults to 'master'.

    Raises:
        TypeError: project variable is not a type 'gitlab.v4.objects.Project'
    """
    if not isinstance(project, gitlab.v4.objects.Project):
        raise TypeError("you must pass an 'gitlab.v4.objects.Project' object!")

    mrs = project.mergerequests.list(
        state='opened',
        order_by='updated_at')

    for mr in mrs:
        if mr.title != title:
            continue
        logging.debug(f"merge request '{title}' already exists")
        return

    project.mergerequests.create(
        {
            'source_branch': branch_name,
            'target_branch': 'master',
            'title': title,
        })
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
        cloudflare_nets = get_cloudflare_nets(
            url=CLOUDFLARE_IPV_URL,
            ssl_verify=env_vars.ssl_verify)
    except Exception as e:
        logging.critical(f"unable to process ansible yaml. {str(e)}")
        sys.exit(1)

    try:
        content = process_yaml(
            file_path=env_vars.file_path,
            yaml_path=env_vars.yaml_path,
            cloudflare_nets=cloudflare_nets)
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

    filename = Path(env_vars.file_path).name

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
            create_merge_request(
                project=project,
                branch_name=env_vars.branch_name,
                title=env_vars.mergerequest_title or f"{filename}: update networkranges"
            )
        except Exception as e:
            logging.critical(f"unable to create merge request. {str(e)}")
            sys.exit(1)

    try:
        update_file(
            project=project,
            branch_name=env_vars.branch_name,
            commit_msg=env_vars.commit_msg,
            content=new_content,
            file_path=env_vars.file_path,
        )
    except Exception as e:
        logging.critical(f"unable to upload file. {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
