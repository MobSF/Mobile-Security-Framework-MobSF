"""Tests for boolean environment values."""
import unittest

from mobsf.MobSF.env import apply_config_flags, flag_from_value


class FlagFromValueTests(unittest.TestCase):
    def test_only_one_enables_text(self):
        self.assertTrue(flag_from_value('1'))
        self.assertTrue(flag_from_value('"1"'))
        self.assertTrue(flag_from_value(True))
        self.assertFalse(flag_from_value('0'))
        self.assertFalse(flag_from_value('false'))
        self.assertFalse(flag_from_value('no'))
        self.assertFalse(flag_from_value(''))
        self.assertFalse(flag_from_value(False))
        self.assertFalse(flag_from_value(None))

    def test_environment_overrides_old_bool_config(self):
        # bool("0") is True. The environment value must win.
        namespace = {'VT_UPLOAD': True}
        apply_config_flags(namespace, {'MOBSF_VT_UPLOAD': '0'})
        self.assertFalse(namespace['VT_UPLOAD'])

    def test_hand_edited_true_is_kept_when_env_is_unset(self):
        namespace = {'VT_ENABLED': True, 'PERM_MAPPING_ENABLED': '1'}
        apply_config_flags(namespace, {})
        self.assertTrue(namespace['VT_ENABLED'])
        self.assertTrue(namespace['PERM_MAPPING_ENABLED'])

    def test_missing_flag_uses_its_default(self):
        namespace = {}
        apply_config_flags(namespace, {})
        self.assertFalse(namespace['VT_ENABLED'])
        self.assertTrue(namespace['APKID_ENABLED'])
        self.assertTrue(namespace['UPSTREAM_PROXY_SSL_VERIFY'])
