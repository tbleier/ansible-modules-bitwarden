# ansible-modules-bitwarden

Bitwarden integration for Ansible.

## Installation

The easiest way to install this lookup plugin is to use the
`ansible-galaxy` command:

    ansible-galaxy install git+https://github.com/tbleier/ansible-modules-bitwarden

This will place the `ansible-modules-bitwarden` role into
`$HOME/.ansible/roles`, where it will be available to all playbooks
you run on your system.

## Lookup plugin

To use this plugin, you will need to activate it by including the role
in your play.  For example:

    - hosts: localhost
      roles:
        - ansible-modules-bitwarden

Use Ansible's `lookup()` function with the `bitwarden` argument,
followed by the items you want to retrieve. The default field is
`password`, but any other field can be specified using the `field`
named argument. If you need to specify the path to the Bitwarden CLI
binary, use the `path` named argument.

Additional parameters:

- type:
  - description: field type to fetch ('default' for username/password, 'custom' for custom fields, 'attachment' for attachments)
  - default: 'default'

- organization:
  - description: optional name of organization - if specified, only entries in this org are found.
  - default: None

- collection:
  - description: optional name or collection - if specified, only entries in this collection are found.
  - default: None

- create:
  - description: create the item if it does not exis (in this organization/collection). Only supports type='default' and
     username and password fields. Creates a random password/username for this entry. Can only create either username
     or password
  - default: False
- length:
  - description: length of created password/username
  - default: 20

- chars:
  - description: character sets to use for random password generation. similar to 'password' lookup plugin
  - default: ['ascii_letters', 'digits', ".,:-_"]

- template:
  - description: additional template to use for new entry. See bitwarden documentation for more details
  - default: None

## Examples

### Get a single password

```yaml
# Get password for Google
- debug:
    msg: {{ lookup('bitwarden', 'Google') }}
```

The above might result in:

```
TASK [debug] *********************************************************
ok: [localhost] => {
    "msg": "mysecret"
    }
```

### Get a single username

```yaml
# Get username for Google
- debug:
    msg: {{ lookup('bitwarden', 'Google', field='username') }}
```

The above might result in:

```
TASK [debug] *********************************************************
ok: [localhost] => {
    "msg": "alice"
    }
```

### Get a single password use organization and collection

```
---
- hosts: localhost
  roles:
    - ansible-modules-bitwarden
  tasks:
    - debug:
        msg: "{{ lookup('bitwarden', 'google', field='password', organization='my org', collection='shared accounts', sync=True) }}"
```

The above might result in:

```
TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [debug] *********************************************************
ok: [localhost] => {
    "msg": "mysecret"
}
```

### See all available fields

```yaml
# Get all available fields for an entry
- debug:
    msg: {{ lookup('bitwarden', 'Google', field='item') }}
```

The above might result in:

```
TASK [debug] *********************************************************
ok: [localhost] => {
    "msg": {
        "favorite": false,
        "fields": [
            {
                "name": "mycustomfield",
                "type": 0,
                "value": "the value of my custom field"
            }
        ],
        "folderId": null,
        "id": "12345678-0123-4321-0000-a97001342c31",
        "login": {
            "password": "mysecret",
            "passwordRevisionDate": null,
            "totp": null,
            "username": "alice"
        },
        "name": "Google",
        "notes": null,
        "object": "item",
        "organizationId": "87654321-1234-9876-0000-a96800ed2b47",
        "revisionDate": "2018-10-19T19:20:17.923Z",
        "type": 1
    }
}
```

### Get the value of a custom field

```yaml
# Get the value of a custom field
- debug:
    msg: {{ lookup('bitwarden', 'Google', field='mycustomfield', custom_field=true) }}
```

The above might result in:

```
TASK [debug] *********************************************************
ok: [localhost] => {
    "msg": "the value of my custom field"
    }
```

### download attachments files

```yaml
# Get the value of a custom field
- debug:
    msg: {{ lookup('bitwarden', 'privateKey.pem',  itemid='123456-1234-1234-abbf-60c345aaa3e', attachments=true ) }}
```
Optional parameters - output='/ansible/publicKey.pem'

The above might result in:

```
TASK [debug] *********************************************************
ok: [localhost] => {
    "msg": "Saved /publicKey.pem"
    }
```
