#!/usr/bin/env python

import argparse
import datetime
import re


def main():
    args = get_args()
    set_version(args.version)
    set_release_date(args.version)


def set_version(version):
    version_re = r"version='(\d+\.\d+.\d+)',"

    with open('setup.py') as fh:
        setup = fh.read()

    old_version_match = re.search(version_re, setup)
    old_version = old_version_match.group(1)

    assert old_version != version

    setup = re.sub(version_re, "version='%s'," % version, setup)

    with open('setup.py', 'w') as fh:
        fh.write(setup)


def set_release_date(version):
    with open('CHANGELOG.md') as fh:
        changelog = fh.read()

    assert 'UNRELEASED -' in changelog

    release_date = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    changelog_header = '%s - %s' % (version, release_date)

    changelog = re.sub(r'UNRELEASED -', changelog_header, changelog)

    with open('CHANGELOG.md', 'w') as fh:
        fh.write(changelog)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('version')
    return parser.parse_args()


if __name__ == '__main__':
    main()
