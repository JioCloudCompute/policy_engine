# Copyright 2015 Reliance Jio Infocomm Ltd.
#

"""
Policy Engine Middleware
"""

import re
import os
import wsgi
import webob
import webob.dec
import webob.exc

from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils


auth_opts = [
    cfg.BoolOpt('api_rate_limit',
                default=False,
                help='whether to use per-user rate limiting for the api.'),
    cfg.BoolOpt('use_forwarded_for',
                default=False,
                help='Treat X-Forwarded-For as the canonical remote address. '
                     'Only enable this if you have a sanitizing proxy.'),
]


CONF = cfg.CONF
CONF.register_opts(auth_opts)


class PolicyEngine():
    """Middleware that sets up environment for authorizing client calls."""

    def read_policy_json(self):
        filepath = CONF.find_file(self.mapping_file)
        with open(filepath) as fap:
            data = fap.read()
            return jsonutils.loads(data)
        
    def __init__(self, mapping_file):
        self.mapping_file = CONF.mapping_file
        self.map_file_contents = self.read_policy_json()
        self.action_key = "action"
        self.rsrc_list_key = "resources"
        self.rsrc_key = "resource"
        self.rsrc_val_rqrd_key = "isResourceValueRequired"
        self.rsrc_value_key = "resourcePath"
        self.secondary_actions_key = "secondary_actions"
        self.indices_regex = r'(\w+[\w.]*)\.N\.?([\w.]*)'

    def get_resource_value(self, rsrc_dict, params):
        rsrc_values = []
        path_string = rsrc_dict.get(self.rsrc_value_key)
        if not path_string:
            return None
        if path_string.find('params.') != 0:
            raise webob.exc.HTTPInternalServerError(explanation=("The "
                " policy authorization engine has gone to error state."))
        path_string = path_string[len('params.') : ]
        # Check if resource path is of the form <keyword>.N
        # This would be for cases like DescribeImages
        match = re.match(self.indices_regex, path_string)
        if match:
            idx = 1
            path = match.group(1) + '.' + str(idx)
            if match.group(2): path += '.' + match.group(2)

            while params.get(path):
                rsrc_values.append(params.get(path))
                idx += 1
                path = match.group(1) + '.' + str(idx)
                if match.group(2): path += '.' + match.group(2)
        else:
            rsrc_values.append(params.get(path_string))
        return rsrc_values

    def populate_ra_list(self, action_dict, ra_list, params,
                        implicit_allow=False):
        action = action_dict.get(self.action_key)
        resource_list = action_dict.get(self.rsrc_list_key)
        secondary_actions = action_dict.get(self.secondary_actions_key)
        if not action or not resource_list:
            raise webob.exc.HTTPInternalServerError()
        if not isinstance(resource_list, list):
            raise webob.exc.HTTPInternalServerError(explanation=("The "
                " policy authorization engine has gone to error state."))
        for resource in resource_list:
            rsrc = resource.get(self.rsrc_key)
            rsrc_values = []
            if resource.get(self.rsrc_value_key):
                rsrc_values = self.get_resource_value(resource, params)
            rsrc_value_rqrd = resource.get(self.rsrc_val_rqrd_key)
            rsrc_value_rqrd = rsrc_value_rqrd.lower()
            if rsrc_values:
                for value in rsrc_values:
                    ra_entry = {'action': action, 
                                'resource': rsrc + ':' + value,
                                'implicit_allow': implicit_allow}
                    ra_list.append(ra_entry)
            elif rsrc_value_rqrd == 'true':
                raise webob.exc.HTTPBadRequest(explanation=("The "
                            "request is missing required paramters for "
                            "authorization."))
            else:
                ra_entry = {'action': action, 'resource': rsrc, 
                        'implicit_allow': implicit_allow}
                ra_list.append(ra_entry)
        if secondary_actions:
            for sa in secondary_actions:
                action_dict = self.map_file_contents.get(sa)
                if not action_dict:
                    raise webob.exc.HTTPInternalServerError(explanation=("The "
                    " policy authorization engine has gone to error state."))
                self.populate_ra_list(action_dict, ra_list, params,
                                      implicit_allow=True)

    def handle_params(self, params):
        action = params.get('Action')
        if not action:
            raise webob.exc.HTTPBadRequest(explanation=("The request is "
                                "missing the keyword \'Action\' in it."))
        action_dict = self.map_file_contents.get(action)
        if not action_dict:
            raise webob.exc.HTTPUnauthorized(explanation=("Action \" " +
                    action + "\" is not authorized for the user."))
        ra_list = []
        self.populate_ra_list(action_dict, ra_list, params)
        return ra_list

