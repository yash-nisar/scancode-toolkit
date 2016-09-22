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

from __future__ import print_function, absolute_import

from scancode import dbconf


"""
Settings for the embedded sqlite DB used through Django's ORM.
"""

# Embedded SQLIte database settings.
# a new database is created each time a new process is started
DATABASES = dict(
    default=dict(
        ENGINE='django.db.backends.sqlite3',
        NAME=dbconf.get_database()
    )
)


# We recreate a new temp DB on each run, migrations are not needed: use a fake
MIGRATION_MODULES = dbconf.FakeMigrations()


INSTALLED_APPS = [
    'packagedcode',
]

# SECURITY WARNING: keep the secret key used in a production webapp!
# here we are running a local CLI-only application and do not need a Django secret
SECRET_KEY = '# SECURITY WARNING: keep the secret key used in a production webapp!'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# On Unix systems, a value of None will cause Django to use the same
# timezone as the operating system.
TIME_ZONE = None
