#!/usr/bin/env python3

from setuptools import setup, find_packages

MAJOR_VERSION='0'
MINOR_VERSION='0'
PATCH_VERSION='0'

VERSION = "{}.{}.{}".format(MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION)

packages = ['sneks','sneks.crypto']

def main():
    setup(
        name = 'sneks-crypto',
        packages = packages,
        package_dir = {"": "src/"},
        version = VERSION,
        description = 'Basic tools to simplify crypto usage.',
        author = 'Steve Norum',
        author_email = 'sn@drunkenrobotlabs.org',
        url = 'https://github.com/stevenorum/sneks-crypto',
        download_url = 'https://github.com/stevenorum/sneks-crypto/archive/{}.tar.gz'.format(VERSION),
        keywords = ['python','crypto'],
        classifiers = [],
        install_requires = ['pykcs11','pycrypto']
    )

if __name__ == "__main__":
    main()
