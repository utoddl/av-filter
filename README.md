# av-filter
Filter for "ansible-vault"ing YAML Data Values

The idea is to simplify using vaulted strings in Ansible project files.

This project works like an extension of `ansible-vault`, hence the "av" part of the name.
It therefore uses the same license as `ansible`: the GNU General Public License v3.0.

This is a filter in the UNIX/Linux sense, not like an Ansible filter plugin.
As such, it reads on `stdin`, writes on `stdout`, and barfs on `stderr`.

# Use
This script allows an Ansible user to pass lines of yaml data through it
to get string values vaulted and/or already-vaulted values unvaulted.
Most text editors have some facility to select a block of text and
pass it through such a filter.

`av-filter` takes a single optional positional argument, which is the
Ansible vault identity to use for encryption, defaulting to the value
of the ANSIBLE_VAULT_IDENTITY environment variable. If any encryption 
is performed, either that environment variable's value or the positional
parameter must be provided. (Values from any `ansible.dfg` files are insufficient.)
