#!/usr/bin/env python

"""Filter for "ansible-vault"ing YAML Data Values

License: GNU General Public License v3.0
URL: https://github.com/utoddl/av-filter
(Originally https://gist.github.com/utoddl/66baa4154618ba1fc8ec8127483e7e89, but
converted to a full project to facilitate collaboration.)

This script allows an ansible user to pass lines of yaml data
through it to get string values vaulted and/or already-vaulted values
unvaulted, thus simplifying the maintenance of vaulted strings in
Ansible vars files and eliminating the need to vault entire files.

It takes a single optional positional argument, which is the
Ansible vault identity to use for encryption. This defaults to the
value of the ANSIBLE_VAULT_IDENTITY environment variable. If any
encryption is performed, either the environment variable or the
positional parameter must be provided. (Values from any ansible.cfg
files are insufficient.)
"""

import json, sys, re, subprocess, inspect, argparse, os
import ruamel.yaml
from io import StringIO
from types import FunctionType
from inspect import getmembers

if sys.version_info[:2] < (3, 6):
    raise SystemExit(
        "ERROR: {} requires Python version 3.6 or later. Current version: {}".format(
            sys.argv[0], ".".join(sys.version.splitlines())
        )
    )

# see https://docs.python.org/3/howto/argparse.html
#     https://docs.python.org/3/library/argparse.html#module-argparse
parser = argparse.ArgumentParser(
    description="Filter for stdin to encrypt or decrypt yaml values with ansible-vault"
)
parser.add_argument(
    "vaultid",
    nargs="?",
    default=None,
    help="Encryption Vault Identity - overrides ANSIBLE_VAULT_IDENTITY",
)
parser.add_argument(
    "-v",
    "--verbose",
    help="increase display of internal workings",
    action="count",
    default=0,
)
args = parser.parse_args()

if args.vaultid:
    os.environ["ANSIBLE_VAULT_IDENTITY"] = args.vaultid

yaml = ruamel.yaml.YAML()

show_debug_messages = args.verbose
_pd_prefix = ""


def pd(str, delta=0):
    global _pd_prefix
    if delta > 0:
        _pd_prefix = " " + _pd_prefix
    elif delta < 0 and len(_pd_prefix):
        _pd_prefix = _pd_prefix[1:]
    dbg("{}{}".format(_pd_prefix, str))


def dbg(msg):
    if show_debug_messages > len(_pd_prefix):
        eprint(msg)


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def lineno():
    """Returns the line number whence lineno() was called."""
    return inspect.currentframe().f_back.f_lineno


def api(obj):
    return [
        name for name in dir(obj) if not name.startswith("built") or name[0] != "@_"
    ]


def attrs(obj):
    disallowed_properties = {
        name
        for name, value in getmembers(type(obj))
        if isinstance(value, (property, FunctionType))
    }
    return "\n".join(
        [
            "{}: {}".format(name, getattr(obj, name))
            for name in api(obj)
            if name not in disallowed_properties and hasattr(obj, name)
        ]
    )


def ansible_vault_decrypt_string(data):
    pd("decrypt_string: >> ({})".format(data))
    try:
        result = subprocess.run(
            ["ansible-vault", "decrypt"],
            input=str(data, encoding="utf-8"),
            capture_output=True,
            text=True,
        )
        text = str(result.stdout, encoding="utf-8")
    except TypeError:
        result = subprocess.run(
            ["ansible-vault", "decrypt"],
            input=bytes(str(data), "utf-8"),
            stdout=subprocess.PIPE,
        )
        text = str(result.stdout, encoding="utf-8")
    pd("decrypt_string: << ({})".format(text))
    if len(text.splitlines(True)) == 1 and not text.endswith("\n"):
        return text
    else:
        if text.endswith("\n\n"):
            newyml = "- |+\n"
        elif text.endswith("\n"):
            newyml = "- |\n"
        else:
            newyml = "- |-\n"

    newyml = "".join([newyml] + ["  " + line for line in text.splitlines(True)])
    pd("decrypt_reprocess: <{}>".format(newyml))
    newrep = yaml.load(newyml)
    pd(attrs(newrep[0]))
    return newrep[0]


def ansible_vault_encrypt_string(key, data):
    pd("encrypt_string: ({})".format(data))
    if "ANSIBLE_VAULT_IDENTITY" not in os.environ:
        eprint("ANSIBLE_VAULT_IDENTITY not set and no vaultid given.")
        sys.exit("ANSIBLE_VAULT_IDENTITY not set and no vaultid given.")
    try:
        result = subprocess.run(
            [
                "ansible-vault",
                "encrypt_string",
                "--encrypt-vault-id",
                os.environ["ANSIBLE_VAULT_IDENTITY"],
                "--stdin-name",
                key if key else "",
            ],
            input=data,
            capture_output=True,
            text=True,
        )
        text = result.stdout
    except TypeError:
        result = subprocess.run(
            [
                "ansible-vault",
                "encrypt_string",
                "--encrypt-vault-id",
                os.environ["ANSIBLE_VAULT_IDENTITY"],
                "--stdin-name",
                key if key else "",
            ],
            input=bytes(str(data), "utf-8"),
            stdout=subprocess.PIPE,
        )
        text = str(result.stdout, encoding="utf-8")
    pd("raw_result: " + text)  # starts with "!vault |\n"
    text2 = "\n".join([l.lstrip() for l in text.splitlines()[1:]]) + "\n"
    ts = ruamel.yaml.comments.TaggedScalar(text2, tag="!vault", style="|")
    # ts = ruamel.yaml.comments.TaggedScalar(text, tag='!vault', style='|')
    # setattr(ts,'style','|')
    # setattr(ts,'_yaml_tag', ruamel.yaml.comments.Tag())
    # getattr(ts,'_yaml_tag').value = '!vault'
    pd("cooked_result1: {}".format(ts))
    return ts


def what_is(data):
    pd("what_is({})".format(data))
    sys.exit("Error: expected 'key: value' pair; found {}".format(data))
    return


def type_or_str(term):
    if isinstance(term, str):
        return term
    else:
        return type(term)


# walk yaml and report types
def walk_dict(data, level):
    pd(">>>walk_dict[{}]:({})\n::{}".format(lineno(), type_or_str(data), data), 1)
    for key in data:
        pd(
            "walk_dict: key={}, type={}, value={}".format(
                key, type(data[key]), data[key]
            )
        )
        if (
            isinstance(data[key], ruamel.yaml.comments.TaggedScalar)
            and getattr(data[key], "_yaml_tag").value == "!vault"
        ):
            pd("\n=== before ===\n" + attrs(data[key]) + "\n--------------\n")
            data[key] = ansible_vault_decrypt_string(data[key])
            pd("\n=== after  ===\n" + attrs(data[key]) + "\n--------------\n")
        elif isinstance(data[key], str):
            pd("\n=== before ===\n" + attrs(data[key]) + "\n--------------\n")
            data[key] = ansible_vault_encrypt_string(None, data[key])
            pd("\n=== after  ===\n" + attrs(data[key]) + "\n--------------\n")
        elif isinstance(data[key], dict):
            walk_dict(data[key], level + 1)
        elif isinstance(data[key], list):
            walk_list(data[key], level + 1)
        else:
            what_is(data[key])
    pd("<<<walk_dict[{}]:".format(lineno()), -1)


def walk_list(data, level):
    pd(">>>walk_list[{}]:({})\n::{}".format(lineno(), type_or_str(data), data), 1)
    for idx, value in enumerate(data):
        pd("walk_list: value type={}".format(type(value)))
        if (
            isinstance(value, ruamel.yaml.comments.TaggedScalar)
            and getattr(value, "_yaml_tag").value == "!vault"
        ):
            pd("\n=== before ===\n" + attrs(data[idx]) + "\n--------------\n")
            data[idx] = ansible_vault_decrypt_string(value)
            pd("\n=== after  ===\n" + attrs(data[idx]) + "\n--------------\n")
        elif isinstance(value, dict):
            walk_dict(value, level + 1)
        elif isinstance(value, list):
            walk_list(value, level + 1)
        elif isinstance(value, str):
            pd("\n=== before ===\n" + attrs(data[idx]) + "\n--------------\n")
            data[idx] = ansible_vault_encrypt_string(None, value)
            pd("\n=== after  ===\n" + attrs(data[idx]) + "\n--------------\n")
        else:
            what_is(data[idx])
    pd("<<<walk_list[{}]:".format(lineno()), -1)


# @ruamel.yaml.yaml_object(yaml)
# class Vault:
#     yaml_tag = u"!vault"
#
#     def __new__(cls, data):
#         return str.__new__(cls, data)
#
#     # def __repr__(self):
#     #     return self
#
#     @classmethod
#     def to_yaml(cls, representer, node):
#         pd("to_yaml: node={}".format(node))
#         if isinstance(node, tuple):
#             return representer.represent_sequence(cls.yaml_tag, node, style="|")
#         return representer.represent_scalar(cls.yaml_tag, node, style="|")
#
#     @classmethod
#     def from_yaml(cls, constructor, node):
#         pd("from_yaml: node={}".format(node))
#         return cls(node.value)

# yaml.register_class(Vault)
yaml.explicit_start = False
yaml.default_flow_style = False
yaml.indent(mapping=2, sequence=4, offset=2)

lines = sys.stdin.read()

first_line_indent = 0
while first_line_indent < len(lines) and lines[first_line_indent] == " ":
    first_line_indent += 1

data = yaml.load(lines)

if isinstance(data, dict):
    walk_dict(data, 0)
elif isinstance(data, list):
    walk_list(data, 0)
else:
    what_is(data)

string_stream = StringIO()
yaml.dump(data, string_stream)

for line in string_stream.getvalue().splitlines():
    print("{}{}".format(" " * first_line_indent, line))
