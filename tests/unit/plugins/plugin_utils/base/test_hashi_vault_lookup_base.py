# -*- coding: utf-8 -*-
# Copyright (c) 2021 Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import pytest

from re import escape as re_escape

from ansible.errors import AnsibleError, AnsibleOptionsError
from ansible.plugins.lookup import LookupBase

from ......plugins.plugin_utils._hashi_vault_plugin import HashiVaultPlugin
from ......plugins.plugin_utils._hashi_vault_lookup_base import HashiVaultLookupBase
from ......plugins.plugin_utils import _hashi_vault_lookup_base as lookup_base_module


@pytest.fixture
def hashi_vault_lookup_module():
    return FakeLookupModule()


class FakeLookupModule(HashiVaultLookupBase):
    def run(self, terms, variables=None, **kwargs):
        pass


class TestHashiVaultLookupBase(object):

    def test_is_hashi_vault_plugin(self, hashi_vault_lookup_module):
        assert issubclass(type(hashi_vault_lookup_module), HashiVaultPlugin)

    def test_is_ansible_lookup_base(self, hashi_vault_lookup_module):
        assert issubclass(type(hashi_vault_lookup_module), LookupBase)
        hashi_vault_lookup_module.run([])  # run this for "coverage"

    @pytest.mark.parametrize(
        'term,unqualified',
        [
            ('value1 key2=value2 key3=val_w/=in_it key4=value4', 'key1'),
            ('key1=value1 key2=value2 key3=val_w/=in_it key4=value4', None),
            ('key1=value1 key2=value2 key3=val_w/=in_it key4=value4', 'NotReal'),
        ]
    )
    def test_parse_kev_term_success(self, term, unqualified, hashi_vault_lookup_module):
        EXPECTED = {
            'key1': 'value1',
            'key2': 'value2',
            'key3': 'val_w/=in_it',
            'key4': 'value4',
        }
        parsed = hashi_vault_lookup_module.parse_kev_term(term, plugin_name='fake', first_unqualified=unqualified)

        assert parsed == EXPECTED

    @pytest.mark.parametrize(
        'term,unqualified',
        [
            ('value1 key2=value2 key3=val_w/=in_it key4=value4', None),
            ('key1=value1 value2 key3=val_w/=in_it key4=value4', None),
            ('key1=value1 value2 key3=val_w/=in_it key4=value4', 'key2'),
            ('key1=val1 invalid key3=val3', None),
            ('key1=val1 invalid key3=val3', 'key1'),
        ]
    )
    def test_parse_kev_term_invalid_term_strings(self, term, unqualified, hashi_vault_lookup_module):
        with pytest.raises(AnsibleError):
            parsed = hashi_vault_lookup_module.parse_kev_term(term, plugin_name='fake', first_unqualified=unqualified)

    def test_parse_kev_term_plugin_name_required(self, hashi_vault_lookup_module):
        with pytest.raises(TypeError):
            parsed = hashi_vault_lookup_module.parse_kev_term('key1=value1', first_unqualified='fake')

    @pytest.mark.parametrize('term', [
        'one secret=two a=1 b=2',
        'a=1 secret=one b=2 secret=two',
        'secret=one secret=two a=z b=y',
    ])
    def test_parse_kev_term_duplicate_option(self, term, hashi_vault_lookup_module):
        dup_key = 'secret'
        expected_template = "Duplicate key '%s' in the term string '%s'."
        expected_msg = expected_template % (dup_key, term)
        expected_re = re_escape(expected_msg)
        expected_match = "^%s$" % (expected_re,)

        with pytest.raises(AnsibleOptionsError, match=expected_match):
            hashi_vault_lookup_module.parse_kev_term(term, plugin_name='fake', first_unqualified=dup_key)


class TestHashiVaultLookupBaseSecretRegistration(object):

    @pytest.fixture
    def registered(self, monkeypatch):
        calls = []
        monkeypatch.setattr(lookup_base_module, 'register_secrets', calls.extend)
        return calls

    def test_register_secret_values_walks_nested_values(self, hashi_vault_lookup_module, registered):
        hashi_vault_lookup_module.register_secret_values({'a': 'one', 'b': ['two', {'c': 'three'}], 'n': 5, 't': True, 'z': None})

        assert sorted(registered) == ['5', 'one', 'three', 'two']

    def test_register_secret_values_without_api(self, hashi_vault_lookup_module, monkeypatch):
        monkeypatch.setattr(lookup_base_module, 'register_secrets', None)

        hashi_vault_lookup_module.register_secret_values({'a': 'one'})

    def test_register_response_secrets_kv2_skips_metadata(self, hashi_vault_lookup_module, registered):
        response = {
            'data': {
                'data': {'password': 'hunter2-kv2'},
                'metadata': {'created_time': '2026-11-17T00:00:00Z', 'version': 3},
            },
        }

        hashi_vault_lookup_module.register_response_secrets(response)

        assert registered == ['hunter2-kv2']

    def test_register_response_secrets_kv1_and_auth(self, hashi_vault_lookup_module, registered):
        response = {
            'data': {'password': 'hunter2-kv1'},
            'auth': {'client_token': 'hvs.token', 'accessor': 'not-a-secret'},
            'lease_id': 'lease',
        }

        hashi_vault_lookup_module.register_response_secrets(response)

        assert registered == ['hunter2-kv1', 'hvs.token']

    @pytest.mark.parametrize('response', [None, b'raw body', 'text'])
    def test_register_response_secrets_ignores_non_mapping(self, response, hashi_vault_lookup_module, registered):
        hashi_vault_lookup_module.register_response_secrets(response)

        assert registered == []
