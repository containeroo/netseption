# NetSeption

## Introduction

NetSeption syncs the IPv4 addresses from `https://www.cloudflare.com/ips-v4` with a [calico networkset](https://docs.projectcalico.org/reference/resources/networkset).  
If there is a difference and the environment variable `BRANCH` is set, the script creates a branch and pushes the updated file. If no branch is set, it pushes directly to the `master` branch.

## Requirements

- [calico networkset](https://docs.projectcalico.org/reference/resources/networkset)
- GitLab

## Configration

In our [repository](https://github.com/containeroo/kubernetes-networkpolicies-examples/blob/master/traefik/networkset-cloudflare.yaml) you can find an calico networkset example.

NetSeption takes the following environment variables:

| Variable             | Description                                                       | Example                                                |
| :------------------- | :---------------------------------------------------------------- | :----------------------------------------------------- |
| `NETWORKPOLICY_FILE` | path to networkpolicy file                                        | `networkpolicies/cloudflare-networkpolicy.yaml`        |
| `GITLAB_TOKEN`       | token for authentication                                          | `vTbFeqJYCY3sibBP7BZM`                                 |
| `GITLAB_URL`         | gitlab url                                                        | `https://gitlab.example.com`                           |
| `PROJECT_ID`         | id of project                                                     | `123`                                                  |
| `BRANCH`             | branch (if not set push direct to `master` branch)                | `cloudflare/IPv4`                                      |
| `COMMIT_MESSAGE`     | commit message (default: `update networkrange`)                   | `update networkrange`                                  |
| `MERGEREQUEST_TITLE` | merge request title (default: `filename: update networkrequest `) | `networkset-cloudflare.yaml: update networkrange`      |
| `SSL_VERIFY`         | verify SSL cert (default: `true`)                                 | `true`                                                 |
| `LOGLEVEL`           | Set loglevel (default: `info`)                                    | one of `critical`, `error`, `warning`, `info`, `debug` |

### GitLab

If you want to use NetSeption in a GitLab CI / CD job, you can use the follwing `.gitlab-ci.yml` as an example:

```yaml
image: 
  name: containeroo/netseption:latest
  entrypoint: [""]

stages:
  - netseption

netseption:
  stage: netseption
  only:
    - schedules
  script: python /app/netseption.py
```

In order to set the configration environment variables, go to your project (repository) containing the calico networkset. 
Go to `Settings` -> `CI / CD` -> `Variabels` -> `Expand`.

After you have set all variables you can create a pipeline schedule. This ensures your job runs regularly.
