#!/usr/bin/env python
"""Test Python TravisCI Client.
"""
import base64
import os
from travisci import TravisCI
# pylint: disable=redefined-outer-name,invalid-name


def test_get_client():
    """Test acquiring a TravisCI Client.
    """
    if "TRAVIS_TOKEN" in os.environ:
        tcli = TravisCI(travis_token=os.environ["TRAVIS_TOKEN"])
    elif "GITHUB_TOKEN" in os.environ:
        tcli = TravisCI(github_token=os.environ["GITHUB_TOKEN"])
    else:
        raise ValueError("Need TRAVIS_TOKEN or GITHUB_TOKEN in environment")
    return tcli


def test_start_sync(tcli):
    """Test starting a sync.
    """
    tcli.start_travis_sync()


def test_retrieve_public_key(tcli, repo):
    """Retrieve public key.
    """
    pubkey = tcli.get_public_key(repo)
    assert pubkey
    return pubkey

# The encrypted strings are salted, so we just test the output format.
# For the encrypted string, it's base64-encoded.


def test_travis_encrypt(tcli, pubkey, encstr):
    """Test travis_encrypt() method.
    """
    ct1 = tcli.travis_encrypt(pubkey, encstr)
    dc1 = base64.b64decode(ct1)
    assert dc1


def test_travis_encrypt_for_repo(tcli, repo, encstr):
    """Test travis_encrypt_for_repo() method.
    """
    ct1 = tcli.travis_encrypt_for_repo(repo, encstr)
    dc1 = base64.b64decode(ct1)
    assert dc1


def test_create_travis_secure_string(tcli, pubkey, encstr):
    """Test create_travis_secure_string() method.
    """
    ct1 = tcli.create_travis_secure_string(pubkey, encstr)
    assert ct1[:9] == "secure: \""
    ss1 = ct1[9:-1]
    dc1 = base64.b64decode(ss1)
    assert dc1


def test_create_travis_secure_string_for_repo(tcli, repo, encstr):
    """Test create_travis_secure_string_for_repo() method.
    """
    ct1 = tcli.create_travis_secure_string_for_repo(repo, encstr)
    assert ct1[:9] == "secure: \""
    ss1 = ct1[9:-1]
    dc1 = base64.b64decode(ss1)
    assert dc1


def test_disable_travis_webhook(tcli, repo):
    """Disable Travis CI Webhook.
    """
    tcli.disable_travis_webhook(repo)


def test_enable_travis_webhook(tcli, repo):
    """Enable Travis CI Webhook.
    """
    tcli.enable_travis_webhook(repo)


def test_set_travis_webhook(tcli, repo, enabled=True):
    """Set Travis CI Webhook to specified value.
    """
    tcli.set_travis_webhook(repo, enabled=enabled)


if __name__ == "__main__":
    repo = "lsst-sqre/pytravisci"
    encstr = "Encrypt me."
    tcli = test_get_client()
    test_start_sync(tcli)
    pubkey = test_retrieve_public_key(tcli, repo)
    test_travis_encrypt(tcli, pubkey, encstr)
    test_travis_encrypt_for_repo(tcli, repo, encstr)
    test_create_travis_secure_string(tcli, pubkey, encstr)
    test_create_travis_secure_string_for_repo(tcli, repo, encstr)
    test_disable_travis_webhook(tcli, repo)
    test_enable_travis_webhook(tcli, repo)
    test_set_travis_webhook(tcli, repo, enabled=False)
    test_set_travis_webhook(tcli, repo, enabled=True)
