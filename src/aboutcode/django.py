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

"""
Django-based data ABCD basic structures(fields, models) and utilities.
"""

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals


import re
import uuid

from django.db import models
from django.core.exceptions import ValidationError


#####################################################################################
# Fields
#####################################################################################

class OptionalCharField(models.CharField):
    description = 'Optional character field.'

    def __init__(self, *args, **kwargs):
        kwargs['null'] = True
        kwargs['blank'] = True
        super(OptionalCharField, self).__init__(*args, **kwargs)


class OptionalTextField(models.TextField):
    description = 'Optional Text field.'

    def __init__(self, *args, **kwargs):
        kwargs['null'] = True
        kwargs['blank'] = True
        super(OptionalTextField, self).__init__(*args, **kwargs)


def validate_hexadecimal(value):
    """
    Validate that value is in hexadecimal such as 548a671d66d5f53fee2bb1cb6096f830.

    For example:
    >>> validate_hexadecimal('548a671d66d5f53fee2bb1cb6096f830')
    >>> validate_hexadecimal('548a671d66d5f53fee2bb1cb6096f830')
    >>> validate_hexadecimal('sha1:f6ec903d36327ec93143c0c77d3fea8a7ff67867')
    >>> try:
    ...    validate_hexadecimal('XZY')
    ... except ValidationError, ve:
    ...    assert 'is not a valid hexadecimal string.' in str(ve)
    >>> try:
    ...    validate_hexadecimal('soho:xyz')
    ... except ValidationError, ve:
    ...    assert 'is not a valid hexadecimal string' in str(ve)
    """
    # it is OK to have an empty value
    if not value:
        return

    # check that we have only HEX aka. base 16
    try:
        int(value.lower(), 16)
    except ValueError:
        raise ValidationError(
            ('%(value)s is not a valid hexadecimal string.'),
            params={'value': value, },
        )


class BaseChecksumField(models.CharField):
    """
    Abstract base field for hex checksums.
    """
    default_validators = [validate_hexadecimal]

    # subclasses need to provide this class attribute
    hex_length = 0

    def __init__(self, *args, **kwargs):
        """
        Create a new checksum field. Checksums must be in hex.
        """
        kwargs['max_length'] = self.hex_length
        super(BaseChecksumField, self).__init__(*args, **kwargs)

    def to_python(self, value):
        # ensure value is always lowercase
        if not value:
            return value
        value = value.strip()
        return value.lower()


class MD5Field(BaseChecksumField):
    description = 'MD5 checksum in hexadecimal.'
    hex_length = 32


class SHA1Field(BaseChecksumField):
    description = 'SHA1 checksum in hexadecimal.'
    hex_length = 40


class SHA256Field(BaseChecksumField):
    description = 'SHA256 checksum in hexadecimal.'
    hex_length = 64


class SHA512Field(BaseChecksumField):
    description = 'SHA512 checksum in hexadecimal.'
    hex_length = 128


def validate_pgpsig(value):
    """
    Validate a PGPO signature in the form of:
    -----BEGIN PGP SIGNATURE-----
    [...]
    -----END PGP SIGNATURE-----
    """
    # it is OK to have an empty value
    if not value:
        return

    start = '-----BEGIN PGP SIGNATURE-----'
    end = '-----END PGP SIGNATURE-----'

    # check that we start and end with the correct header/footer
    value = value.strip()
    if not value.startswith(start) or not value.startswith(end):
        raise ValidationError(
            ('%(value)s is not a valid PGP signature string.'),
            params={'value': value, },
        )


class PGPSignatureField(models.TextField):
    description = 'PGP Signature text.'
    default_validators = [validate_hexadecimal]



class URLField(models.URLField):
    description = 'HTTP or FTP URL.'

    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = 2048
        super(URLField, self).__init__(*args, **kwargs)


class OptionalURLField(URLField):
    description = 'Optional HTTP or FTP URL.'

    def __init__(self, *args, **kwargs):
        kwargs['null'] = True
        kwargs['blank'] = True
        super(OptionalURLField, self).__init__(*args, **kwargs)


def validate_uri(value):
    """
    Validate value as a URI with several supported schemes beyond HTTP.
    """
    # Regex is derived from the code of schematics.URLType.
    # Copyright (c) 2013-2016 Schematics Authors. see AUTHORS for details
    # All rights reserved.
    #
    # Redistribution and use in source and binary forms, with or without modification,
    # are permitted provided that the following conditions are met:
    #
    #   1. Redistributions of source code must retain the above copyright notice,
    #      this list of conditions and the following disclaimer.
    #
    #   2. Redistributions in binary form must reproduce the above copyright
    #      notice, this list of conditions and the following disclaimer in the
    #      documentation and/or other materials provided with the distribution.
    #
    #   3. Neither the name of Schematics nor the names of its contributors may be
    #      used to endorse or promote products derived from this software without
    #      specific prior written permission.
    #
    # THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
    # ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
    # WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    # DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
    # ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    # (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    # LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
    # ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    # (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    # SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    URI_REGEX = re.compile(
        r'^'
        r'(?:'
            r'(?:https?'
            r'|ftp|sftp|ftps'
            r'|rsync'
            r'|ssh'

            r'|git|git\+https?|git\+ssh|git\+git|git\+file'
            r'|hg|hg\+https?|hg\+ssh|hg\+static-https?'
            r'|bzr|bzr\+https?|bzr\+ssh|bzr\+sftp|bzr\+ftp|bzr\+lp'
            r'|svn|svn\+http?|svn\+ssh|svn\+svn'
            r')'
            r'://'

        r'|'
            r'git\@'
        r')'

        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,2000}[A-Z0-9])?\.)+[A-Z]{2,63}\.?|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )

    if not URI_REGEX.match(value):
        raise ValidationError(
            ('%(value)s is not a valid URI.'),
            params={'value': value, },
        )


class ExtendedURLField(models.CharField):
    description = 'Extended URL field with several supported schemes beyond HTTP.'
    default_validators = [validate_uri]

    def __init__(self, *args, **kwargs):
        """
        Create a new URI field. The value is not validated. Call uri_validator() for
        an optional validation.
        """
        kwargs['max_length'] = 2048
        super(ExtendedURLField, self).__init__(*args, **kwargs)


class OptionalExtendedURLField(ExtendedURLField):
    description = 'Optional extended URL field.'

    def __init__(self, *args, **kwargs):
        """
        Create a new optional URI field. The value is not validated. Call
        uri_validator() for an optional validation.
        """
        kwargs['null'] = True
        kwargs['blank'] = True
        super(OptionalExtendedURLField, self).__init__(*args, **kwargs)



#####################################################################################
# Abstract models
#####################################################################################

class AbstractUUIDPrimaryKeyMixin(models.Model):
    """
    A mixin abtract model to add a UUID field as a primary key.
    """
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        abstract = True


class AbstractExternalReference(models.Model):
    """
    Abstract base model for external references. Concrete subclasses models must
    define a ForeignKey to the objects that are referenced.

    An object may have
    several ExternalReference when it is referenced in multiple places, such as a
    package name at Debian or Fedora.
    """
    source = OptionalCharField(
        max_length=100,
        help_text=('The source in which this external reference exists, such as '
                   'an internet domain or some string that defines some '
                   'identifying source (e.g. Rubygems, NPMJS'),
    )

    identifier = OptionalCharField(
        max_length=500,
        help_text=('Identifier used in the source to reference the object, such '
                    'as a name.'),
    )

    url = OptionalURLField(
        help_text=('URL to the object in the source.'),
    )

    class Meta:
        abstract = True

    def __str__(self):
        return '{}: {}'.format(self.domain, self.identifier)


class AbstractParty(models.Model):

    ORG = 'Organization'
    PERSON = 'Person'
    PROJECT = 'Project'

    TYPE_CHOICES = (
        (ORG, 'Organization: an ongoing, formally established entity.'),
        (PERSON, 'Person: an individual.'),
        (PROJECT, 'Project: a dynamic collection of persons working on a software project. Often less formally defined.'),
    )

    type = OptionalCharField(
        max_length=20,
        choices=TYPE_CHOICES,
        help_text=('A party type differentiates individuals, ongoing businesses, and '
                    'dynamic organizations (such as software projects).'),
    )

    name = OptionalCharField(
        max_length=255,
        help_text='Name of a party.',
    )

    homepage_url = OptionalURLField(
        help_text='Homepage URL of the party.',
    )

    contact_info = OptionalCharField(
        max_length=500,
        help_text='Information on how to contact this party, such an email.',
    )

    class Meta:
        abstract = True

    def __str__(self):
        return '{}: {}'.format(self.type, self.name)


class AbstractLicense(models.Model):
    """
    License essentials.
    """
    key = OptionalCharField(
        max_length=1000,
        help_text='Key for the license.',
    )

    name = OptionalCharField(
        max_length=1000,
        help_text='Full name of the license, as provided by the original authors.',
    )

    short_name = OptionalCharField(
        max_length=1000,
        help_text='Most commonly used name for the license, often abbreviated.',
    )

    homepage_url = OptionalURLField(
        help_text='Homepage URL for the license.',
    )

    category = OptionalCharField(
        max_length=50,
        help_text='Name of a license category such as Copyleft.',
    )

    full_text = OptionalTextField(
        help_text='Full text of the license.',
    )

    class Meta:
        abstract = True


class AbstractPackageRepository(models.Model):
    """
    A package repository.
    """
    BOWER = 'bower'
    CPAN = 'cpan'
    DEBIAN = 'debian'
    RUBYGEMS = 'rubygems'
    GODOC = 'godoc'
    IVY = 'ivy'
    MAVEN = 'maven'
    YUM = 'yum'
    PYPI = 'pypi'
    NUGET = 'nuget'
    NPMJS = 'npmjs'

    REPO_TYPES_CHOICES = (
        (BOWER, 'Bower'),
        (CPAN, 'CPAN'),
        (DEBIAN, 'Debian'),
        (RUBYGEMS, 'Rubygems'),
        (GODOC, 'Godoc'),
        (IVY, 'Ivy'),
        (MAVEN, 'Maven'),
        (NPMJS, 'Npmjs'),
        (NUGET, 'Nuget'),
        (PYPI, 'Pypi'),
        (YUM, 'Yum'),
    )

    # note: we do not enforce the choices
    type = models.CharField(
        choices=REPO_TYPES_CHOICES,
        max_length=50,
        help_text='Type of package repository.'
    )

    base_url = ExtendedURLField(
        help_text='Base URL for this package repository.'
    )

    public = models.NullBooleanField(
        help_text='True of this is a public repository.'
    )

    class Meta:
        abstract = True

    def download_url(self, package):
        """
        Return a direct download URL for `package` object in this repository.
        """
        return NotImplementedError()

    def packages_index(self, query=None, limit=100):
        """
        Return an iterable of Package objects available in this repository using the
        `query` search string and returning up to `limit` packages.
        """
        return NotImplementedError()


class AbstractPackage(models.Model):
    """
    A unified model for packages. The way a
    package is created and serialized should be uniform across all Package
    types.
    """
    # content types data to recognize a package
    FILETYPES = tuple()
    MIMETYPES = tuple()
    EXTENSIONS = tuple()

    # list of known METAFILES for a package type, to recognize a package
    METAFILES = []

    # list of supported repository types a package type, for reference
    REPO_TYPES = []


    # Proxy subclasses can override this attribute with a default that will be set on save()
    TYPE = None
    type = OptionalCharField(
        max_length=50,
        help_text=('Type of package such as a npm, rpm, etc. '
                   'By convention this is a lowercase value only composed of '
                   'ASCII characters and digits.')
    )

    name = OptionalCharField(
        max_length=100,
        help_text='Name of the package.'
    )

    version = OptionalCharField(
        max_length=100,
        help_text=('Version of the package. This is the full version and may '
                   'include multiple segments such release for RPMs.'),
    )

    # Proxy subclasses can override this attribute with a default that will be set on save()
    PRIMARY_LANGUAGE = None
    primary_language = OptionalCharField(
        max_length=50,
        help_text=('Primary programming language for this package, often derived '
                   'from the Package type i.e. RubyGems are primarily ruby, etc.')
    )

    summary = OptionalTextField(help_text='Short, summary description of a package.')

    description = OptionalTextField(help_text='Long descriptive description of a package.')

    PAYLOAD_SRC = 'src'
    # binaries include minified JavaScripts and similar obfuscated texts formats
    PAYLOAD_BIN = 'bin'
    PAYLOAD_DOC = 'doc'
    PAYLOADS = (
        (PAYLOAD_SRC, 'Source code'),
        (PAYLOAD_BIN, 'Compiled binary or similar (minified, etc.)'),
        (PAYLOAD_DOC, 'Documentation')
    )

    payload_type = OptionalCharField(
        max_length=5,
        choices=PAYLOADS,
        help_text=('Type of primary payload in this package such as source, documentation or binary.')
    )

    homepage_url = OptionalURLField(
        help_text=('URL to the homrpage for this package.')
    )

    bug_tracking_url = OptionalURLField(
        help_text='URL to an issue or bug tracker.'
    )

    code_view_url = OptionalURLField(
        help_text='URL where the code can be browsed online.'
    )

    VCS_TOOL_CHOICES = (
        ('git', 'Git'),
        ('svn', 'Subversion'),
        ('hg', 'Mercurial'),
        ('bzr', 'Bazaar'),
        ('cvs', 'CVS'),
    )
    # one of git, svn, hg, etc
    vcs_tool = OptionalCharField(
        max_length=5,
        choices=VCS_TOOL_CHOICES,
        help_text='A VCS tool: one of git, svn, hg, etc.'
    )

    vcs_repository = OptionalExtendedURLField(
        # a URL in the SPDX form of:
        # git+https://github.com/nexb/scancode-toolkit.git
        help_text='URL to the repository (using SPDX conventions).'
    )

    vcs_revision = OptionalCharField(
        max_length=100,
        help_text=('A VCS revision, commit, branch or tag reference corresponding '
                   'to the version of this package.')
    )

    # List of paths legal files  (such as COPYING, NOTICE, LICENSE, README, etc.)
    # Paths are relative to the root of the package
    # legal_file_locations = ListType(OptionalCharField())

    license_expression = OptionalCharField(
        max_length=1024,
        help_text=(
            'A License expression relates one or more licenses together such as '
            'conjunctive licensing (using AND where all the licenses apply), '
            'disjunctive licensing (using OR for a choice of licenses). The general '
            'syntax is the SPDX license expression syntax, using license keys.'
        ),
    )

    notice_text = OptionalTextField(
        help_text='Notie text when available (such as an Apache NOTICE).')

    notes = OptionalTextField(help_text='Notes about this package.')

    # checksums for the package archive
    md5 = MD5Field(null=True, blank=True)
    sha1 = SHA1Field(null=True, blank=True)
    sha256 = SHA256Field(null=True, blank=True)
    sha512 = SHA512Field(null=True, blank=True)

    file_name = OptionalCharField(
        max_length=255,
        help_text='Filename of the package archive if any.'
    )

    size = models.IntegerField(
        null=True,
        help_text='Size of the package archive (if any) in bytes.'
    )

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        """
        Add sensible defaults provided by Proxy subclasses
        """
        if not self.type:
            self.type = self.TYPE

        if not self.primary_language:
            self.type = self.PRIMARY_LANGUAGE

        super(AbstractPackage, self).save(*args, **kwargs)

    @property
    def identifier(self):
        """
        Return a tuple of identifiers for this package.
        """
        return self.type, self.name, self.version

    @classmethod
    def recognize(cls, location):
        """
        Return a Package object or None given a location to a file or directory
        pointing to a package archive, metafile or similar.

        Sub-classes should override to implement their own package recognition.
        """
        return
