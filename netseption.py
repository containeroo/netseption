import json
import logging
import logging.handlers
import os
import sys
from collections import namedtuple
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import gitlab
import requests
import urllib3
import yaml
from requests import HTTPError

CLOUDFLARE_IPV_URL = "https://www.cloudflare.com/ips-v4"
project = None

__version__ = "0.0.1"

def check_env_vars():
    networkpolicy_file_path = os.environ.get("NETWORKPOLICY_FILE")

    gitlab_url = os.environ.get("GITLAB_URL")
    gitlab_token = os.environ.get("GITLAB_TOKEN")
    project_id = os.environ.get("PROJECT_ID")
    branch_name = os.environ.get("BRANCH")
    ssl_verify = os.environ.get("SSL_VERIFY", "true") == "true"

    commit_msg = os.environ.get("COMMIT_MESSAGE", "update networkrange")
    mergerequest_title = os.environ.get("MERGEREQUEST_TITLE")

    loglevel = os.environ.get("LOGLEVEL", "info").lower()

    if not networkpolicy_file_path:
        raise EnvironmentError(
            "environment variable 'NETWORKPOLICY_FILE' not set!")

    if not gitlab_token:
        raise EnvironmentError(
            "environment variable 'GITLAB_TOKEN' not set!")

    if not gitlab_url:
        raise EnvironmentError(
            "environment variable 'GITLAB_URL' not set!")

    if not project_id:
        raise EnvironmentError(
            "environment variable 'PROJECT_ID' not set!")

    Env_vars = namedtuple('Env_vars', ['networkpolicy_file_path',
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
        networkpolicy_file_path,
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

    default_format = logging.Formatter("%(asctime)s [%(levelname)-7.7s] %(message)s")
    console_logger = logging.StreamHandler(sys.stdout)
    console_logger.setLevel(loglevel)
    console_logger.setFormatter(default_format)
    root_logger.addHandler(console_logger)


def get_cloudflare_ips(url, ssl_verify):
    try:
        response = requests.get(
            url=url,
            verify=ssl_verify)

        if not response.ok:
            raise HTTPError(f"{response.status_code}: canont get IPv4 address from Cloudflare")

        return [r for r in response.text.split("\n") if r]
    except:
        raise


def process_networkpolicy(networkpolicy_file_path, cloudflare_ips):
    try:
        with open(networkpolicy_file_path, 'r') as conf:
            networkpolicy = yaml.safe_load(conf)
    except Exception as e:
        raise FileNotFoundError(f"cannot open file '{networkpolicy_file_path}'. {e}")

    if not networkpolicy.get('spec'):
        raise KeyError(f"'spec' not found in '{networkpolicy_file_path}'")

    if not networkpolicy['spec'].get('nets'):
        raise KeyError(f"'nets' not found in '{networkpolicy_file_path}'")

    networkpolicy_ips = networkpolicy['spec'].get('nets')

    if not Diff(cloudflare_ips, networkpolicy_ips):
        logging.info("IPv4 addresses are equal. nothing to do")
        sys.exit(0)

    networkpolicy['spec']['nets'] = cloudflare_ips  # update networkpolicy

    return networkpolicy


def update_file(branch_name, commit_msg, networkpolicy, networkpolicy_file_path):
    try:
        payload = {
            "branch": branch_name,
            "commit_message": commit_msg,
            "actions": [
                {
                    'action': 'update',
                    'file_path': networkpolicy_file_path,
                    'content': yaml.dump(networkpolicy),
                }
            ]
        }

        project.commits.create(payload)
        logging.info(f"successfully update file '{networkpolicy_file_path}'")
    except Exception as e:
        raise Exception(e.error_message)


def create_branch(branch_name):
    try:
        branch = project.branches.get(branch_name)
        if branch:
            logging.debug(f"branch '{branch_name}' already exists")
            return
    except Exception as e:
        if not e.response_code == 404:
            logging.debug(f"cannot get '{branch_name}'. {e}")
            return

    try:
        project.branches.create({'branch': branch_name,
                                  'ref': 'master'})
        logging.info(f"successfully created branch '{branch_name}'")
    except Exception as e:
        raise Exception(e.error_message)


def create_merge_request(branch_name, title):
    try:
        mrs = project.mergerequests.list(state='opened', order_by='updated_at')
        for mr in mrs:
            if mr.title != title:
                continue
            logging.debug(f"merge request '{title}' already exists")
            return
    except Exception as e:
        logging.debug(f"cannot get '{branch_name}'. {e}")
        return

    try:
        project.mergerequests.create(
            {
                'source_branch': branch_name,
                'target_branch': 'master',
                'title': title,
            })
        logging.info(f"successfully created merge request '{title}'")
    except Exception as e:
        raise Exception(f"{e.error_message}")


def main():
    try:
        now = datetime.today().isoformat()
        sys.stdout.write(f"{now} [INFO   ] start Calico networkpolicy with CloudFlare IPv4 sync: {__version__}\n")
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
        cloudflare_ips = get_cloudflare_ips(
            url=CLOUDFLARE_IPV_URL,
            ssl_verify=env_vars.ssl_verify)
    except Exception as e:
        logging.critical(f"unable to process ansible yaml. {str(e)}")
        sys.exit(1)

    try:
        networkpolicy = process_networkpolicy(
            networkpolicy_file_path=env_vars.networkpolicy_file_path,
            cloudflare_ips=cloudflare_ips)
    except Exception as e:
        logging.critical(f"unable to process networkpolicy yaml. {str(e)}")
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
        global project
        project = cli.projects.get(int(env_vars.project_id))
    except Exception as e:
        logging.critical(f"cannot get project '{env_vars.project_id}'. {e}")
        sys.exit(1)

    filename = Path(env_vars.networkpolicy_file_path).name

    if not env_vars.branch_name:
        logging.debug("no branch set. push direct to master")

    else:
        try:
            create_branch(
                branch_name=env_vars.branch_name
            )
        except Exception as e:
            logging.critical(f"unable to create branch. {str(e)}")
            sys.exit(1)

        try:
            create_merge_request(
                branch_name=env_vars.branch_name,
                title=env_vars.mergerequest_title or f"{filename}: update networkrange"
            )
        except Exception as e:
            logging.critical(f"unable to create merge request. {str(e)}")
            sys.exit(1)

    try:
        update_file(
            branch_name=env_vars.branch_name or 'master',
            commit_msg=env_vars.commit_msg,
            networkpolicy=networkpolicy,
            networkpolicy_file_path=env_vars.networkpolicy_file_path,
        )
    except Exception as e:
        logging.critical(f"unable to upload file. {str(e)}")
        sys.exit(1)


def Diff(list1, list2):
    return (list(list(set(list1)-set(list2)) + list(set(list2)-set(list1)))) 


if __name__ == "__main__":
    main()
