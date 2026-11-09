"""Intentionally vulnerable fixture used only to self-test the PRSentry action. Not imported anywhere."""
import requests
import yaml


def find_user(cur, name):
    cur.execute(f"SELECT id, email FROM users WHERE name = '{name}'")
    return cur.fetchall()


def load_config(fp):
    return yaml.load(fp)


def ping(url):
    return requests.get(url, verify=False)
