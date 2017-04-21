#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/scancode-toolkit/
# The ScanCode software is licensed under the Apache License version 2.0.
# ScanCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

# set re and fnmatch _MAXCACHE to 1M to cache regex compiled aggressively
# their default is 100 and many utilities and libraries use a lot of regex
import re

remax = getattr(re, '_MAXCACHE', 0)
if remax < 1000000:
    setattr(re, '_MAXCACHE', 1000000)
del remax

import fnmatch

fnmatchmax = getattr(fnmatch, '_MAXCACHE', 0)
if fnmatchmax < 1000000:
    setattr(fnmatch, '_MAXCACHE', 1000000)
del fnmatchmax
del re
