#!./venv/bin/python

import argparse
import os
import shutil
import pprint
import subprocess

import boto3
import requests

"""

Can fetch artifacts for previous commit and release them, but version built in will be wrong.
Should thus commit changes and version, tag and push, wait for CI to finish, then download
artifacts and upload to pypi.
"""


APPVEYOR_API_TOKEN = os.environ['APPVEYOR_API_TOKEN']
TRAVIS_GITHUB_TOKEN = os.environ['TRAVIS_GITHUB_API_TOKEN']
API_URL = 'https://ci.appveyor.com/api'
TRAVIS_URL = 'https://api.travis-ci.org'
APPVEYOR_ACCOUNT = 'thusoy'
PROJECT_NAME = 'porridge'


def main():
    shutil.rmtree('dist')
    os.makedirs('dist')

    build_source_release()
    collect_artifacts()


def build_source_release():
    subprocess.check_call(['python', 'setup.py', 'sdist'])


def collect_artifacts():
    collect_artifacts_travis()
    collect_artifacts_appveyor()


def collect_artifacts_travis():
    session = requests.Session()
    session.headers['Accept'] = 'application/vnd.travis-ci.2+json'
    session.headers['User-Agent'] = 'Travis porridge-release/1.0.0'
    session.headers['Content-Type'] = 'application/json'
    auth_response = session.post(TRAVIS_URL + '/auth/github', json={
        'github_token': TRAVIS_GITHUB_TOKEN,
    })
    access_token = auth_response.json()['access_token']
    session.headers['Authorization'] = 'token %s' % access_token

    repo_status = session.get(TRAVIS_URL + '/repos/%s/%s' % (APPVEYOR_ACCOUNT, PROJECT_NAME)).json()
    assert repo_status['repo']['last_build_state'] == 'passed'
    last_build_number = repo_status['repo']['last_build_number']

    s3 = boto3.resource('s3')
    bucket = s3.Bucket('porridge-artifacts')
    artifact_prefix = '%s/%s/%s' % (APPVEYOR_ACCOUNT, PROJECT_NAME, last_build_number)
    for artifact in bucket.objects.filter(Prefix=artifact_prefix):
        artifact_name = os.path.basename(artifact.key)
        print('Downloading %s' % artifact_name)
        bucket.download_file(artifact.key, os.path.join('dist', artifact_name))


def collect_artifacts_appveyor():
    session = create_session()
    response = session.get(API_URL + '/projects/thusoy/porridge')
    for job in response.json()['build']['jobs']:
        assert job['status'] == 'success', '%s had status %s' % (job['name'], job['status'])
        artifacts_base = API_URL + '/buildjobs/%s/artifacts' % job['jobId']
        artifacts_list = session.get(artifacts_base)
        artifact_url = '%s/%s' % (artifacts_base, artifacts_list.json()[0]['fileName'])
        download_appveyor_artifact(session, artifact_url)


def create_session():
    session = requests.Session()
    session.headers['Authorization'] = 'Bearer %s' % APPVEYOR_API_TOKEN
    session.headers['Content-Type'] = 'application/json'
    return session


def download_appveyor_artifact(session, url):
    response = session.get(url, stream=True)
    artifact_name = os.path.basename(url)
    print('Downloading %s' % artifact_name)
    destination = os.path.join('dist', artifact_name)
    with open(destination, 'wb') as fh:
        for chunk in response.iter_content(16*2**10):
            fh.write(chunk)


if __name__ == '__main__':
    main()
