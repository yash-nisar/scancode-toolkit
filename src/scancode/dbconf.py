#
# Copyright (c) 2016 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/scancode-toolkit/
# The ScanCode software is licensed under the Apache License version 2.0.
# Data generated with ScanCode require an acknowledgment.
# ScanCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with ScanCode or any ScanCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with ScanCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  ScanCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  ScanCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/scancode-toolkit/ for support and download.

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals


"""
Configuration helpers for the embedded sqlite DB used through Django's ORM.
You must call configure() before calling or importing anything else from ScanCode.

WARNING: DO NOT USE THESE IF YOU WANT TO USE SCANCODE IN A REGULAR DJANGO WEB APP.
THE SETTINGS DEFINED HERE ARE ONLY FOR USING SCANCODE AS A COMMAND LINE OR WHEN USING
SCANCODE AS A LIBRARY OUTSIDE OF A DJANGO WEB APPLICATION.
"""


def configure(settings_module='scancode.dbsettings'):
    """
    Configure minimally Django (in particular the ORM and DB) using the
    settings_modules module. When using ScanCode has a library you must call this
    function at least once before calling other code.
    """
    import os
    os.environ['DJANGO_SETTINGS_MODULE'] = settings_module

    import django
    from django.apps import apps
    if not apps.ready:
        # call django.setup() only once
        django.setup()
    create_db()


def get_database(database_file=None):
    """
    Return the path to a new, temporary SQLite database file or an existing file if
    database_file is provided.
    """
    if not database_file:
        import os
        from commoncode import fileutils
        tmp_dir = fileutils.get_temp_dir(base_dir='db')
        database_file = os.path.join(tmp_dir, 'scancode.db')
    return database_file


def create_db(verbosity=4):
    """
    Create the database by invoking the migrate command behind the scenes.
    """
    from django.core.management import call_command

    call_command('migrate', verbosity=verbosity, interactive=False, run_syncdb=True)


class FakeMigrations(dict):
    """
    Fake migration class to avoid running migrations at all. For the ScanCode CLI
    usage, a new DB is created on each run, so running migrations has no value.
    inspired by https://github.com/henriquebastos/django-test-without-migrations
    """
    def __getitem__(self, item):
        return "do not run any migrations"
    def __contains__(self, item):
        return True
