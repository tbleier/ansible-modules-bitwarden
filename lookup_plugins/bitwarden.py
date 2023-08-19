#!/usr/bin/env python

# (c) 2018, Matt Stofko <matt@mjslabs.com>
# GNU General Public License v3.0+ (see LICENSE or
# https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This plugin can be run directly by specifying the field followed by a list of
# entries, e.g.  bitwarden.py password google.com wufoo.com
#
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
import sys
import string
import copy
import logging

from subprocess import Popen, PIPE, STDOUT, check_output
from base64 import b64encode

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.module_utils.six import string_types
from ansible.module_utils.common.text.converters import to_native, to_text
from ansible.utils.encrypt import random_password

VALID_PARAMS = frozenset(('path', 'session', 'sync', 'field', 'type', 'organization', 'collection', 
                          'create', 'length', 'chars', 'template'))

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()


DOCUMENTATION = """
lookup: bitwarden
author:
  - Matt Stofko <matt@mjslabs.com>
  - City Network International AB - https://github.com/citynetwork
  - https://github.com/timvy
  - Thomas Bleier <thomas@bleier.at>
requirements:
  - bw (command line utility)
  - BW_SESSION environment var (from `bw login` or `bw unlock`)
short_description: look up or create entries using a bitwarden vault
description:
  - use the bw command line utility to grab one or more items stored in a
    bitwarden vault, optionally also creating new entries
options:
  _terms:
    description: name of item that contains the field to fetch (exact match)
    required: true
field:
  description: field to return from bitwarden
  default: 'password'
sync:
  description: If True, call `bw sync` before lookup
path:
  description: optional path to bitwarden cli binary
  default: bw
session:
  description: override session id
type:
  description: field type to fetch ('default' for username/password, 'custom' for custom fields, 'attachment' for attachments)
  default: 'default'
organization:
  description: optional name of organization - if specified, only entries in this org are found.
  default: None
collection:
  description: optional name or collection - if specified, only entries in this collection are found.
  default: None
create:
  description: create the item if it does not exis (in this organization/collection). Only supports type='default' and
     username and password fields. Creates a random password/username for this entry. Can only create either username
     or password
  default: False
length:
  description: length of created password/username
  default: 20
chars:
  description: character sets to use for random password generation. similar to 'password' lookup plugin
  default: ['ascii_letters', 'digits', ".,:-_"]
template:
  description: additional template to use for new entry. See bitwarden documentation for more details
  default: None
"""

EXAMPLES = """
- name: get 'username' from Bitwarden entry 'Google'
  debug:
    msg: "{{ lookup('bitwarden', 'Google', field='username') }}"
"""

RETURN = """
  _raw:
    description:
      - Items from Bitwarden vault
"""

# Global variables
bw = None

show_debug = False
def debug(msg):
    if show_debug:
        print(msg)


class Bitwarden(object):
    def __init__(self, path):
        self._cli_path = path
        self._bw_session = ""
        self._cache = dict()
        self._logged_in = None

        try:
            check_output([self._cli_path, "--version"])
        except OSError:
            raise AnsibleError("Command not found: {0}".format(self._cli_path))

    @property
    def session(self):
        return self._bw_session

    @session.setter
    def session(self, value):
        self._bw_session = value

    @property
    def cli_path(self):
        return self._cli_path

    @property
    def logged_in(self):
        if self._logged_in is None:
            # Parse Bitwarden status to check if logged in
            self._logged_in = (self.status() == 'unlocked')

        return self._logged_in

    def cache(func):
        def inner(*args, **kwargs):
            self = args[0]
            key = '//'.join([str(it) for it in args[1:]])

            if key not in self._cache:
                value = func(*args, **kwargs)
                self._cache[key] = value

            return self._cache[key]

        return inner

    def _run(self, args):
        my_env = os.environ.copy()
        if self.session != "":
            my_env["BW_SESSION"] = self.session
        p = Popen([self.cli_path] + args, stdin=PIPE,
                  stdout=PIPE, stderr=STDOUT, env=my_env)
        out, _ = p.communicate()
        out = out.decode()
        rc = p.wait()
        debug(f"_run: {args} -> {rc}")
        if rc != 0:
            display.debug("Received error when running '{0} {1}': {2}"
                          .format(self.cli_path, args, out))
            if out.startswith("Vault is locked."):
                raise AnsibleError("Error accessing Bitwarden vault. Run 'bw unlock' to unlock the vault.")
            elif out.startswith("? Master password:"):
                raise AnsibleError("Error accessing Bitwarden vault. Run 'bw unlock' to unlock the vault.")
            elif out.startswith("You are not logged in."):
                raise AnsibleError("Error accessing Bitwarden vault. Run 'bw login' to login.")
            elif out.startswith("Failed to decrypt."):
                raise AnsibleError("Error accessing Bitwarden vault. Make sure BW_SESSION is set properly.")
            elif out.startswith("Not found."):
                raise AnsibleError("Error accessing Bitwarden vault. Specified item not found: {}".format(args[-1]))
            elif out.startswith("More than one result was found."):
                raise AnsibleError("Error accessing Bitwarden vault. "
                                   "Specified item found more than once: {}".format(args[-1]))
            else:
                raise AnsibleError("Unknown failure in 'bw' command: "
                                   "{0}".format(out))
        debug(f"result: {out.strip()}")            
        return out.strip()

    def sync(self):
        self._cache = dict()   # Clear cache to prevent using old values in cache
        self._run(['sync'])

    @cache
    def status(self):
        try:
            data = json.loads(self._run(['status']))
        except json.decoder.JSONDecodeError as e:
            raise AnsibleError("Error decoding Bitwarden status: %s" % e)
        return data['status']

    @cache
    def organization(self, name):
        try:
            data = json.loads(self._run(['list', 'organizations']))
        except json.decoder.JSONDecodeError as e:
            raise AnsibleError("Error decoding Bitwarden list organizations: %s" % e)
        if not isinstance(data, list):
            raise AnsibleError("Error getting organizations list: no organizations list")
        if len(data) == 0:
            raise AnsibleError("Error getting organizations list: no organizations")
        for organization in data:
            if 'id' in organization.keys() and 'name' in organization.keys() and organization['name'] == name:
                return(organization['id'])
        raise AnsibleError("Error getting organization - organization not found: %s" % name)

    @cache
    def collection(self, name):
        try:
            data = json.loads(self._run(['list', 'collections']))
        except json.decoder.JSONDecodeError as e:
            raise AnsibleError("Error decoding Bitwarden list collections: %s" % e)
        if not isinstance(data, list):
            raise AnsibleError("Error getting collections list: no collections list")
        if len(data) == 0:
            raise AnsibleError("Error getting collections list: no collections")
        for collection in data:
            if 'id' in collection.keys() and 'name' in collection.keys() and collection['name'] == name:
                return(collection['id'])
        raise AnsibleError("Error getting collection - collection not found: %s" % name)

    def _gen_candidate_chars(self, characters):
        '''Generate a string containing all valid chars as defined by ``characters``
        copied from https://github.com/ansible/ansible/blob/devel/lib/ansible/plugins/lookup/password.py

        :arg characters: A list of character specs. The character specs are
            shorthand names for sets of characters like 'digits', 'ascii_letters',
            or 'punctuation' or a string to be included verbatim.

        The values of each char spec can be:

        * a name of an attribute in the 'strings' module ('digits' for example).
        The value of the attribute will be added to the candidate chars.
        * a string of characters. If the string isn't an attribute in 'string'
        module, the string will be directly added to the candidate chars.

        For example::

            characters=['digits', '?|']``

        will match ``string.digits`` and add all ascii digits.  ``'?|'`` will add
        the question mark and pipe characters directly. Return will be the string::

            u'0123456789?|'
        '''
        chars = []
        for chars_spec in characters:
            # getattr from string expands things like "ascii_letters" and "digits"
            # into a set of characters.
            chars.append(to_text(getattr(string, to_native(chars_spec), chars_spec), errors='strict'))
        chars = u''.join(chars).replace(u'"', u'').replace(u"'", u'')
        return chars

    def create_entry(self, name, type, field, organizationId, collectionId, length, pwchars, template):
        chars = self._gen_candidate_chars(pwchars)
        new_entry = random_password(length, chars)
        debug(f'Creating new password: {length} chars {str(pwchars)}: {new_entry}')
        # create new item by getting JSON template from bitwarden
        new_item = json.loads(self._run(['get', 'template', 'item']))
        if not isinstance(new_item, dict):
            raise AnsibleError(f'Error - got invalid template for new item from Bitwarden CLI!')
        # Replace bw default note (which is 'Some notes about this item')
        if 'notes' in new_item:
            new_item['notes'] = 'Created with ansible-modules-bitwarden'            
        if template is None:
            template = {}
        if isinstance(template, string_types):
            try:
                template = json.loads(template)
            except json.decoder.JSONDecodeError as e:
                raise AnsibleError(f"Error decoding new item template: {repr(e)}")
        if not isinstance(template, dict):
            raise AnsibleError(f'Invalid template - has to be a dict!')
        for key, value in template.items():
            new_item[key] = value
        new_item['name'] = name
        if field == 'username':
            password = template['login']['password'] if 'login' in template and 'password' in template['login'] else ''
            new_item['login'] = {'username':new_entry, 'password': password}
        elif field == 'password':
            username = template['login']['username'] if 'login' in template and 'username' in template['login'] else ''
            new_item['login'] = {'username':username, 'password': new_entry}
        else:
            raise AnsibleError(f'Create is only supported for username and password fields')
        if organizationId is not None:
            new_item['organizationId'] = organizationId
        if collectionId is not None:
            if new_item['collectionIds'] is not None:
                new_item['collectionIds'].append(collectionId)
            else:
                new_item['collectionIds'] = [ collectionId ]
        debug(f'New item: {new_item}')
        self._run(['create', 'item', b64encode(json.dumps(new_item).encode('ascii'))])
        return new_entry

    @cache
    def get_entry(self, key, field, organizationId, collectionId, type, create, length, pwchars, template):
        try:
            data = json.loads(self._run(['list', 'items', '--search', key]))
        except json.decoder.JSONDecodeError as e:
            raise AnsibleError("Error decoding Bitwarden list items: %s" % e)
        if not isinstance(data, list):
            raise AnsibleError("Error getting items list: no items list")
        _return = []
        for result in data:
            if 'id' in result.keys() and 'name' in result.keys() and 'collectionIds' in result.keys() and 'organizationId' in result.keys():
                if result['name'] != key:
                    continue
                if organizationId == None:
                    pass
                elif result['organizationId'] != organizationId:
                    continue
                if collectionId == None:
                    pass
                elif collectionId not in result['collectionIds']:
                    continue
                if type == 'default' and field == 'item':
                    _return.append(result)
                elif type == 'default' and field == 'password':
                    _return.append(result['login']['password'])
                elif type == 'default' and field == 'username':
                    _return.append(result['login']['username'])
                elif type == 'custom' and 'fields' in result.keys() and any(field in x['name'] for x in result['fields']):
                    for x in result['fields']:
                        if x['name'] == field:
                            _return.append( x['value'])
                elif type == 'attachment' and 'attachments' in result.keys() and any(field in x['fileName'] for x in result['attachments']):
                    for x in result['attachments']:
                        if x['fileName'] == field:
                            _return.append(self._run(['get', 'attachment', x['id'], '--quiet', '--raw', '--output', '/dev/stdout', '--itemid', result['id']]))
                elif type == 'default' and field in result.keys():
                    _return.append(result[field])
        debug(f'get_entry: {str(_return)}')
        if len(_return) > 1:
            raise AnsibleError(f"Error getting entry: more then one item found for: {key}")
        elif len(_return) == 1:
            return _return[0]
        else:
            if create:
                return self.create_entry(key, type, field, organizationId, collectionId, length, pwchars, template)
            else:
                raise AnsibleError(f"Error getting entry: item '{key}' not found!")


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        global bw

        debug(f'Lookup: {", ".join(terms)}')
        debug(f'Options: {", ".join(f"{key}={value}" for key, value in kwargs.items())}')

        invalid_params = frozenset(kwargs.keys()).difference(VALID_PARAMS)
        if invalid_params:
            raise AnsibleError('Unrecognized parameter(s) given to password lookup: %s' % ', '.join(invalid_params))

        if not bw:
            bw = Bitwarden(path=kwargs.get('path', 'bw'))

        if kwargs.get('session'):
            bw.session = kwargs.get('session')
        if kwargs.get('sync'):
            bw.sync()

        if not bw.logged_in:
            raise AnsibleError("Not logged into Bitwarden: please run 'bw login', or 'bw unlock' and set the "
                               "BW_SESSION environment variable first")

        field = kwargs.get('field', 'password')
        type = kwargs.get('type', 'default')
        organization = kwargs.get('organization', None)
        organizationId = None
        collection = kwargs.get('collection', None)
        collectionId = None
        create = kwargs.get('create', None)
        if create and type not in ['default']:
            raise AnsibleError('Create only supported for "default" type!')
        length = kwargs.get('length', 20)
        if isinstance(length, string_types):
            length = int(length)
        pwchars = kwargs.get('chars', ['ascii_letters', 'digits', ".,:-_"])
        template = kwargs.get('template', None)
        values = []
        if organization != None:
            organizationId = bw.organization(organization)
        if collection != None:
            collectionId = bw.collection(collection)        

        for term in terms:
            values.append(bw.get_entry(term, field, organizationId, collectionId, type, create, length, pwchars, template))
        return values


def main():
    global show_debug
    show_debug = True

    if len(sys.argv) < 2:
        print("Usage: {0} <field> <key=value> ...".format(os.path.basename(__file__)))
        return -1

    kwargs = {}
    for arg in sys.argv[2:]:
        key, value = arg.split("=")
        kwargs[key] = value

    print(LookupModule().run([sys.argv[1]], None, **kwargs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
