# ***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# ***** END LICENSE BLOCK *****

"""Main entry point
"""
from mozsvc.config import get_configurator

import crypto


def includeme(config):
    # authorization
    #config.include('pyramid_ipauth')

    config.include("cornice")

    config.scan("trunion.views")

    crypto.init(key=config.registry.settings['trunion.keyfile'],
                cert=config.registry.settings['trunion.certfile'],
                chain=config.registry.settings['trunion.chainfile'],
                engine=config.registry.settings.get('trunion.engine', None))

    issuers = config.registry.settings.get('trunion.permitted_issuers', '')
    issuers = issuers.split(',')
    iss = []
    for issuer in issuers:
        iss.append(issuer.strip())
    if len(iss) < 1:
        raise Exception("No issuers provided in the config file!")
    config.registry.settings['trunion.permitted_issuers'] = iss


def main(global_config, **settings):
    config = get_configurator(global_config, **settings)
    config.include('pyramid_exclog')
    config.include(includeme)
    return config.make_wsgi_app()
