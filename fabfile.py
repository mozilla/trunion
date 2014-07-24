import os
from os.path import join as pjoin
from fabric.api import (env, execute, lcd, local, parallel,
                        run, roles, task)

from fabdeploytools.rpm import RPMBuild
from fabdeploytools import helpers
import fabdeploytools.envs

import deploysettings as settings


env.key_filename = settings.SSH_KEY
fabdeploytools.envs.loadenv(settings.CLUSTER)

ROOT, TRUNION = helpers.get_app_dirs(__file__)

SCL_NAME = getattr(settings, 'SCL_NAME', False)
if SCL_NAME:
    helpers.scl_enable(SCL_NAME)

VIRTUALENV = os.path.join(ROOT, 'venv')
PYTHON = os.path.join(VIRTUALENV, 'bin', 'python')


@task
def create_virtualenv(update_on_change=False):
    helpers.create_venv(VIRTUALENV, settings.PYREPO,
                        pjoin(TRUNION, 'prod-reqs.txt'),
                        update_on_change=update_on_change)


@task
def setup_install():
    with lcd(TRUNION):
        local("%s setup.py install" % PYTHON)


@task
def update_info(ref='origin/master'):
    helpers.git_info(TRUNION)
    with lcd(TRUNION):
        local("/bin/bash -c "
              "'source /etc/bash_completion.d/git && __git_ps1'")


@task
def deploy():
    helpers.deploy(name='trunion',
                   env=settings.ENV,
                   cluster=settings.CLUSTER,
                   domain=settings.DOMAIN,
                   root=ROOT,
                   package_dirs=['trunion', 'venv', 'ssl'])


@task
def pre_update(ref=settings.UPDATE_REF):
    local('date')
    execute(helpers.git_update, TRUNION, ref)
    execute(update_info, ref)


@task
def update():
    execute(create_virtualenv)
    execute(setup_install)
