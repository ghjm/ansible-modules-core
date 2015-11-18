#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2015, Graham Mainwaring <gmainwaring@ansible.com>
# Adapted from selinux_permissive (c) 2015, Michael Scherer <misc@zarb.org>
# inspired by code of github.com/dandiker/
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: selinux_semanage
short_description: Configure SELinux policy settings
description:
  - Configure SELinux policy settings, similar to the command-line tool semanage
version_added: "2.0"
options:
  selinux_user:
    description:
        - "SELinux user name, like system_u or guest_u"
    required: false
    default: null
  selinux_roles:
    description:
        - "Space delimited list of SELinux role names, like: staff_r sysadm_r"
    required: false
    default: null
  selinux_type:
    description:
        - "SELinux type name, like http_port_t or bin_t"
    required: false
    default: null
  selinux_module:
    description:
        - "SELinux module name"
    required: false
    default: null
  selinux_boolean:
    description:
        - "SELinux boolean name"
    required: false
    default: null
  boolean:
    description:
        - "Set an SELinux boolean (requires selinux_boolean)"
        - "    (Both run-time and boot-time values are set, like setsebool -P)"
    required: false
    choices: [ 'true', 'false' ]
    default: null
  user_roles:
    description:
        - "Assign one or more SELinux roles to a user context"
        - "(requires selinux_user, selinux_roles)"
    required: false
    choices: [ 'assigned' ]
    default: None
  login_name:
    description:
        - "Login username"
    required: false
    default: null
  login_user:
    description:
        - "Delete or assign a Linux login to an SELinux user context"
        - "(requires login_name, selinux_user)"
    required: false
    choices: [ 'assigned', 'deleted' ]
    default: null
  module:
    description:
        - "Enable or disable an SELinux module (requires selinux_module)"
    required: false
    choices: [ 'enabled', 'disabled' ]
    default: null
  port_range:
    description:
        - "Network port number or range, like 80 or 135-139 (required for port=)"
    required: false
    default: null
  protocol:
    description:
        - "Network protocol (used in port=, default tcp)"
    required: false
    default: "tcp"
  port:
    description:
        - "Delete or assign a network port/proto to an SELinux port type"
        - "(requires selinux_type, port_range)"
    required: false
    choices: [ 'assigned', 'deleted' ]
    default: null
  file_spec:
    description:
        - "File spec regular expression (used in fcontext=)"
    required: false
    default: null
  file_type:
    description:
        - "File type (used in fcontext=). Must be one of: socket, regular file,
        - "character device, all files, directory, block device, named pipe,
        - "symbolic link. Defaults to all files."
    required: false
    default: "a"
  fcontext:
    description: 
        - "Delete or assign an SELinux context to a filespec"
        - "(requires file_spec, selinux_type)"
        - "(optional: selinux_user - defaults to system_u)"
        - "(optional: file_type - defaults to all files)"
        - "Note: This module does not change the labels on the filesystem."
        - "      If you need restorecon, you must run it separately."
    required: false
    choices: [ 'assigned', 'deleted' ]
    default: null
  permissive:
    description:
        - "Add or remove an SELinux type to/from the permissive list"
        - "(requires: selinux_type)"
    required: false
    choices: [ 'added', 'deleted' ]
    default: null
  no_reload:
    description:
        - "Suppress reloading SELinux policies after the change is made (default is to reload)"
        - "Note that this doesn't work on older version of the library (example EL 6)."
        - "The module will silently ignore it in this case."
    required: false
    default: false
    choices: [ 'true', 'talse' ]
  store:
    description:
      - "Name of the SELinux policy store to use"
    required: false
    default: null
notes:
    - Requires a version of SELinux recent enough ( ie EL 6 or newer )
requirements: [ policycoreutils-python ]
author: 
    - "Michael Scherer <misc@zarb.org>"
    - "Graham Mainwaring <gmainwaring@ansible.com"

'''

EXAMPLES = '''
# Set an SELinux boolean
- selinux_semanage selinux_boolean="httpd_can_network_connect" boolean=true

# Assign a Linux user to an SELinux user context
- selinux_semanage selinux_user="xguest_u" login_name="guest" login_user=assigned

# Delete a Linux user from all SELinux user contexts
- selinux_semanage login_name="guest" login_user=deleted

# Assign roles to an SELinux user context
- selinux_semanage selinux_user="staff_u" selinux_roles="sysadm_r" user_roles=assigned

# Disable an SELinux module
- selinux_semanage selinux_module="uucp" module=disabled

# Allow sshd to bind to port 1234 (tcp)
- selinux_semanage selinux_type="ssh_port_t" port_range="1234" port=assigned

# Change the default file context for files under /web
- selinux_semanage selinux_type="httpd_sys_content_t" file_spec="/web(/.*)?" fcontext=added

# Put the httpd_t domain into permissive mode
- selinux_semanage selinux_type="httpd_t" permissive=added
'''

import string

HAVE_SEOBJECT = False
try:
    import semanage
    import seobject
    HAVE_SEOBJECT = True
except ImportError:
    pass

def get_boolean(seobj, boolean_name):
    seboolval = seobj.get_all()[boolean_name]
    # Older seobject returns a scalar, newer seobject returns a tuple
    if isinstance(seboolval, list):
        return seboolval[0] != 0
    else:
        return seboolval != 0

def get_module_enabled(seobj, module_name):
    for mod in seobj.get_all():
        if mod[0]==module_name:
            return mod[2]

def sort_roles(roles):
    return string.join(sorted(roles.split()), ' ')

def get_user_roles(seobj, user_name):
    userdict = seobj.get_all()
    if not user_name in userdict:
        # User doesn't exist, therefore has no roles
        return ""
    return sort_roles(userdict[user_name][3])

def set_user_roles(seobj, user_name, roles):
    userdict = seobj.get_all()
    if user_name in userdict:
        seobj.modify(user_name, roles=roles.split())
    else:
        seobj.add(user_name, roles.split(), "", None, "")

def check_login_user(seobj, login_name, user_name):
    # Returns True if login_name assigned to user_name,
    #         False if login_name exists but not assigned to user_name,
    #         None if login_name does not exist.
    logindict = seobj.get_all()
    if not login_name in logindict:
        return None
    else:
        return logindict[login_name][0] == user_name

def set_login_user(seobj, login_name, user_name):
    logindict = seobj.get_all()
    if login_name in logindict:
        seobj.modify(login_name, user_name)
    else:
        seobj.add(login_name, user_name, None)

def parse_port_range(port_range):
    ports = str(port_range).split("-")
    if len(ports) == 1:
        high = low = int(ports[0])
    else:
        low = int(ports[0])
        high = int(ports[1])
    return low, high

def check_port_state(seobj, selinux_type, port_range, protocol):
    # Returns True if port/proto assigned to selinux_type,
    #         False if port/proto exists but not assigned to selinux_type,
    #         None if port/proto does not exist.
    low, high = parse_port_range(port_range)
    p_all = seobj.get_all()
    if not (low, high, protocol) in p_all:
        return None
    ctype, level = p_all[ (low, high, protocol) ]
    return ctype == selinux_type

def check_fcontext_state(seobj, selinux_user, selinux_type, file_spec, file_type):
    # Returns True if file_spec assigned to selinux_type/user,
    #         False if file_spec exists but not assigned to selinux_type/user,
    #         None if file_spec does not exist.
    fc_all = seobj.get_all()
    if not (file_spec, file_type) in fc_all:
        return None
    seuser, serole, setype, semls = fc_all[ (file_spec, file_type) ]
    if selinux_user and (selinux_user != seuser):
        return False
    return selinux_type == setype

def CompareAndReturnValue(comp1, comp2, value_if_equal, value_if_not_equal):
    # Used instead of inline conditional, for Python 2.4 compatibility
    if comp1 == comp2:
        return value_if_equal
    else:
        return value_if_not_equal

def main():
    
    module = AnsibleModule(
        argument_spec = dict(
            selinux_user = dict(required=False),
            selinux_roles = dict(required=False),
            selinux_type = dict(required=False),
            selinux_module = dict(required=False),
            selinux_boolean = dict(required=False),
            boolean = dict(type='bool', required=False),
            user_roles = dict(type='str', choices=['assigned'], required=False),
            login_name = dict(required=False),
            login_user = dict(type='str', choices=['assigned', 'deleted'], required=False),
            module = dict(type='str', choices=['enabled','disabled'], required=False),
            port_range = dict(type='str', required=False),
            protocol = dict(type='str', required=False, default='tcp'),
            port = dict(type='str', choices=['assigned','deleted'], required=False),
            file_spec = dict(type='str', required=False),
            file_type = dict(type='str', required=False, choices=['socket', 'regular file', 'character device', 'all files', 'directory', 'block device', 'named pipe', 'symbolic link'], default='all files'),
            fcontext = dict(type='str', choices=['assigned','deleted'], required=False),
            permissive = dict(type='str', choices=['added','deleted'], required=False),
            store = dict(required=False, default=''),
            no_reload = dict(type='bool', required=False, default=False),
        ),
        mutually_exclusive = [
            ['boolean', 'user_roles', 'login_user', 'module', 'port', 'fcontext', 'permissive'],
        ],
        required_one_of = [
            ['boolean', 'user_roles', 'login_user', 'module', 'port', 'fcontext', 'permissive'],
        ],
        required_if = [
            ['boolean', 'true',        ['selinux_boolean'] ],
            ['boolean', 'false',       ['selinux_boolean'] ],
            ['user_roles', 'assigned', ['selinux_user', 'selinux_roles'] ],
            ['login_user', 'assigned', ['selinux_user', 'login_name'] ],
            ['login_user', 'deleted',  ['login_name'] ],
            ['module', 'enabled',      ['selinux_module'] ],
            ['module', 'disabled',     ['selinux_module'] ],
            ['port', 'assigned',       ['selinux_type', 'port_range'] ],
            ['port', 'deleted',        ['port_range'] ],
            ['fcontext', 'assigned',   ['selinux_type', 'file_spec'] ],
            ['fcontext', 'deleted',    ['file_spec'] ],
            ['permissive', 'added',    ['selinux_type'] ],
            ['permissive', 'deleted',  ['selinux_type'] ],
        ],
        supports_check_mode=True
    )
    
    # global vars
    changed = False
    store = module.params['store']
    no_reload = module.params['no_reload']

    if not HAVE_SEOBJECT:
        module.fail_json(changed=False, msg="policycoreutils-python required for this module")
    
    action_matrix = {
        'boolean': {
            'get_seobject': lambda: seobject.booleanRecords(store),
            'item_name': module.params['selinux_boolean'],
            'desired_state': module.params['boolean'],
            'get_item_state': lambda seobj: get_boolean(seobj, module.params['selinux_boolean']),
            'set_item_state': {
                True:  lambda(seobj): seobj.modify(module.params['selinux_boolean'], 'true'),
                False: lambda(seobj): seobj.modify(module.params['selinux_boolean'], 'false'),
                },
            },
        'user_roles': {
            'get_seobject': lambda: seobject.seluserRecords(store),
            'item_name': module.params['selinux_user'],
            'desired_state': True,
            'get_item_state': lambda seobj: get_user_roles(seobj, module.params['selinux_user']) == sort_roles(module.params['selinux_roles']),
            'set_item_state': {
                True:  lambda(seobj): set_user_roles(seobj, module.params['selinux_user'], module.params['selinux_roles']),
                },
            },
        'login_user': {
            'get_seobject': lambda: seobject.loginRecords(store),
            'item_name': module.params['login_name'],
            'desired_state': CompareAndReturnValue(module.params['login_user'], 'deleted', None, True),
            'get_item_state': lambda seobj: check_login_user(seobj, module.params['login_name'], module.params['selinux_user']),
            'set_item_state': {
                True: lambda(seobj): set_login_user(seobj, module.params['login_name'], module.params['selinux_user']),
                None: lambda(seobj): seobj.delete(module.params['login_name']),
                },
            },
        'module': {
            'get_seobject': lambda: seobject.moduleRecords(store),
            'item_name': module.params['selinux_module'],
            'desired_state': module.params['module'] == 'enabled',
            'get_item_state': lambda seobj: get_module_enabled(seobj, module.params['selinux_module']),
            'set_item_state': {
                True:  lambda(seobj): seobj.enable(module.params['selinux_module']),
                False: lambda(seobj): seobj.disable(module.params['selinux_module']),
                },
            },
        'port': {
            'get_seobject': lambda: seobject.portRecords(store),
            'item_name': str(module.params['port_range']) + '/' + str(module.params['protocol']),
            'desired_state': CompareAndReturnValue(module.params['port'], 'deleted', None, True),
            'get_item_state': lambda seobj: check_port_state(seobj, module.params['selinux_type'], module.params['port_range'], module.params['protocol']),
            'set_item_state': {
                True:  lambda(seobj): seobj.add(module.params['port_range'], module.params['protocol'], None, module.params['selinux_type']),
                None: lambda(seobj): seobj.delete(module.params['port_range'], module.params['protocol']),
                },
            },
        'fcontext': {
            'get_seobject': lambda: seobject.fcontextRecords(store),
            'item_name': module.params['file_spec'],
            'desired_state': CompareAndReturnValue(module.params['fcontext'], 'deleted', None, True),
            'get_item_state': lambda seobj: check_fcontext_state(seobj, module.params['selinux_user'], module.params['selinux_type'], module.params['file_spec'], module.params['file_type']),
            'set_item_state': {
                True:  lambda(seobj): seobj.add(module.params['file_spec'], module.params['selinux_type'], ftype=module.params['file_type'], serange=""),
                None: lambda(seobj): seobj.delete(module.params['file_spec'], module.params['file_type']),
                },
            },
        'permissive': {
            'get_seobject': lambda: seobject.permissiveRecords(store),
            'item_name': module.params['selinux_type'],
            'desired_state': module.params['permissive'] == 'added',
            'get_item_state': 
                lambda seobj: module.params['selinux_type'] in seobj.get_all(),
            'set_item_state': {
                True:  lambda(seobj): seobj.add(module.params['selinux_type']),
                False: lambda(seobj): seobj.delete(module.params['selinux_type']),
                },
            },
        }
    
    action = None
    for a in action_matrix:
        if module.params[a] != None:
            action = a
    if action == None:
        module.fail_json(stage="params", msg="Unknown action")

    item_name = action_matrix[action]['item_name']
    desired_state = action_matrix[action]['desired_state']
    
    try:
        seobj = action_matrix[action]['get_seobject']()
    except ValueError, e:
        module.fail_json(stage="get_seobject", item=item_name, msg=str(e))
    
    # not supported on EL 6
    if 'set_reload' in dir(seobj):
        seobj.set_reload(not no_reload)
    
    try:
        current_state = action_matrix[action]['get_item_state'](seobj) 
    except ValueError, e:
        module.fail_json(stage="get_item_state", item=item_name, msg=str(e))
    
    if desired_state != current_state:
        if not module.check_mode:
            try:
                action_matrix[action]['set_item_state'][desired_state](seobj)
            except ValueError, e:
                module.fail_json(stage="set_item_state", item=item_name, msg=str(e))
        changed = True
    
    module.exit_json(changed=changed, store=store,
                     item_name=item_name, state=desired_state)


#################################################
# import module snippets
from ansible.module_utils.basic import *

main()
