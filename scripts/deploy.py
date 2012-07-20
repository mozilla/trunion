#!/usr/bin/commander

import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from commander.deploy import hostgroups, task

import commander_settings as settings


@task
def create_virtualenv(ctx):
    ctx.local("virtualenv --distribute --system-site-packages --never-download %s" % settings.VIRTUAL_ENV)
    ctx.local("rm -f %s/lib64 && ln -s ./lib %s/lib64" % (settings.VIRTUAL_ENV, settings.VIRTUAL_ENV))
    ctx.local("%s/bin/pip install -I --download-cache=/tmp/pip-cache -M -r %s/prod-reqs.txt" % (settings.VIRTUAL_ENV, settings.APP_DIR))
    ctx.local("virtualenv --relocatable %s" % settings.VIRTUAL_ENV)


@hostgroups('addons-signer', remote_kwargs={'ssh_key': settings.SSH_KEY})
def shipit(ctx):
    ctx.remote(settings.REMOTE_UPDATE_SCRIPT)
    ctx.remote("/sbin/service gunicorn-addons-signer graceful")


@task
def verify_keys(ctx):
    ctx.local('%s/bin/python %s/scripts/verify_keys.py %s %s' % (
        settings.VIRTUAL_ENV,
        settings.APP_DIR,
        settings.CERT,
        settings.KEY,
    ))

    ctx.local('chmod 644 %s %s' % (settings.CERT, settings.KEY))
    ctx.local('chown root:root %s %s' % (settings.CERT, settings.KEY))


@task
def pre_update(ctx, ref='origin/master'):
    with ctx.lcd(settings.APP_DIR):
        ctx.local("git fetch")
        ctx.local("git reset --hard %s" % ref)


@task
def update(ctx):
    create_virtualenv()


@task
def deploy(ctx):
    verify_keys()
    ctx.local(settings.DEPLOY_SCRIPT)
    shipit()
