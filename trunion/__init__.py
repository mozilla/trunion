# ***** BEGIN LICENSE BLOCK *****
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
# ***** END LICENSE BLOCK *****

"""Main entry point
"""
import mozsvc.config

import trunion.crypto as crypto


def includeme(config):
    # authorization
    #config.include('pyramid_ipauth')

    config.include('pyramid_exclog')

    config.include("cornice")

    config.scan("trunion.views")

    crypto.init(key=config.registry.settings['trunion.keyfile'],
                cert=config.registry.settings['trunion.certfile'],
                chain=config.registry.settings['trunion.chainfile'],
                engine=config.registry.settings.get('trunion.engine', None))

    # So many fugly hacks
    if config.registry.settings.get('trunion.we_are_signing', None) == 'addons':
        crypto.init_ca(sectionify(config.registry.settings, 'addons'),
                       sectionify(config.registry.settings, 'dnbase'),
                       sectionify(config.registry.settings, 'extensions'))

    issuers = config.registry.settings.get('trunion.permitted_issuers', '')
    issuers = issuers.split(',')
    iss = []
    for issuer in issuers:
        iss.append(issuer.strip())
    if len(iss) < 1:
        raise Exception("No issuers provided in the config file!")
    config.registry.settings['trunion.permitted_issuers'] = iss

# Work around for WEIRD behaviour seen with an attempt to upgrade to mozsvc 0.8
def sectionify(settings, section):
    section_items = {}
    prefix = section + '.'
    for key, value in settings.iteritems():
        if key.startswith(prefix):
            section_items[key[len(prefix):]] = value
    return section_items


def get_configurator(global_config, **settings):
    config = mozsvc.config.get_configurator(global_config, **settings)
    config.begin()
    try:
        config.include(includeme)
    finally:
        config.end()
    return config


def main(global_config, **settings):
    config = get_configurator(global_config, **settings)
    return config.make_wsgi_app()
