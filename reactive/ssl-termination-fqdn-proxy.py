#!/usr/bin/env python3
# Copyright (C) 2017  Qrama, developed by Tengu-team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
from charmhelpers.core.hookenv import status_set, config
from charms.reactive import when, when_not, set_flag, clear_flag, when_any, hook
from charms.reactive.relations import endpoint_from_flag
from charms.reactive.helpers import data_changed
from charms.reactive.flags import is_flag_set


config = config()

########################################################################
# Install
########################################################################

@when('endpoint.ssl-termination.available')
@when_not('config.set.upstreams')
def missing_http_relation():
    status_set('blocked', 'Waiting for upstreams config')


@when('config.set.upstreams')
@when_not('endpoint.ssl-termination.available')
def missing_ssl_termination_relation():
    status_set('blocked', 'Waiting for ssl-termination-proxy relation')


@when_any('config.changed.fqdns',
          'config.changed.credentials',
          'config.changed.nginx-config',
          'config.changed.upstreams')
def fqdns_changed():
    clear_cert_flags()


########################################################################
# Upgrade-charm
########################################################################

@hook('upgrade-charm')
def upgrade_charm():
    status_set('maintenance', 'Upgrading charm..')
    if is_flag_set('cert-created'):
        clear_flag('cert-created')
        set_flag('client.cert-created')


########################################################################
# Configure certificate
########################################################################

@when('config.set.upstreams',
      'endpoint.ssl-termination.available')
@when_not('client.cert-requested')
def create_cert_request():
    if not config.get('fqdns'):
        status_set('blocked', 'Waiting for fqdns config')
        return
    ssl_termination = endpoint_from_flag('endpoint.ssl-termination.available')

    upstream_config = config.get('upstreams').split(' ')
    upstreams = []

    for u in upstream_config:
        host, port = u.split(':')
        upstreams.append({
            'hostname': host,
            'port': port,
        })

    cert_request = {
        'fqdn': config.get('fqdns').rstrip().split(),
        'contact-email': config.get('contact-email', ''),
        'credentials': config.get('credentials', ''),
        'upstreams': upstreams,
        'nginx-config': parse_nginx_config(),
    }

    ssl_termination.send_cert_info(cert_request)
    status_set('waiting', 'Waiting for proxy to register certificate')
    set_flag('client.cert-requested')


@when('config.set.upstreams',
      'endpoint.ssl-termination.joined')
@when_any('endpoint.ssl-termination.update',
          'client.cert-requested')
@when_not('client.cert-created')
def check_cert_created():
    ssl_termination = endpoint_from_flag('endpoint.ssl-termination.joined')
    status = ssl_termination.get_status()
    # Only one fqdn will be returned for shared certs.
    # If any fqdn match, the cert has been created.
    match_fqdn = config.get('fqdns').rstrip().split()
    for unit_status in status:
        if unit_status['status']:
            for fqdn in unit_status['status']:
                if fqdn in match_fqdn:
                    status_set('active', 'Ready')
                    set_flag('client.cert-created')
                    clear_flag('endpoint.ssl-termination.update')


########################################################################
# Unconfigure certificate
########################################################################

@when('endpoint.ssl-termination.available',
      'client.cert-created')
@when_not('config.set.upstreams')
def website_removed():
    endpoint = endpoint_from_flag('endpoint.ssl-termination.available')
    endpoint.send_cert_info({})
    clear_cert_flags()


@when('config.changed.upstreams',
      'client.cert-created')
def website_updated_changed():
    clear_cert_flags()


########################################################################
# Helper methods
########################################################################

def parse_nginx_config():
    nginx_configs = []
    for n_config in config.get('nginx-config', '').split(';'):
        # Remove unnecessary whitespace, tabs and newlines
        nginx_configs.append(' '.join(n_config.split()))    
    return [x for x in nginx_configs if x] # Remove empty entries

def clear_cert_flags():
    clear_flag('client.cert-requested')
    clear_flag('client.cert-created')
    