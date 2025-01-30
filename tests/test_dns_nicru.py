"""Tests for certbot_dns_nicru"""

import sys
from unittest import mock

from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util
from certbot._internal.display import obj

from certbot_dns_nicru.dns_nicru import Authenticator


class AuthenticatorTest(
    test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest
):
    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        path = os.path.join(self.tempdir, "file.ini")
        dns_test_common.write(
            {
                "dns_nicru_username": "fake-user",
                "dns_nicru_password": "fake-password",
                "dns_nicru_client_id": "fake-client-id",
                "dns_nicru_client_secret": "fake-client-secret",
                "dns_nicru_scope": "empty",
                "dns_nicru_service": "service",
                "dns_nicru_zone": "zone"
            },
            path,
        )

        super(AuthenticatorTest, self).setUp()
        self.config = mock.MagicMock(
            dns_nicru_credentials=path, dns_nicru_propagation_seconds=0
        )  # don't wait during tests

        self.auth = Authenticator(self.config, "dns_nicru")

        self.mock_client = mock.MagicMock()
        # Set up the default_zone property
        type(self.mock_client).default_zone = mock.PropertyMock(return_value="zone")
        self.auth._get_client = mock.MagicMock(return_value=self.mock_client)

        obj.set_display(obj.FileDisplay(sys.stdout, False))

    def test_perform(self):
        type(self.mock_client).default_zone = mock.PropertyMock(return_value="example.com")
        self.auth.perform([self.achall])
        
        expected = [mock.call.add_record(mock.ANY), mock.call.commit()]
        self.assertEqual(expected, self.mock_client.mock_calls)
        self.assertEqual(
            "_acme-challenge", self.mock_client.mock_calls[0][1][0].name
        )

    def test_cleanup(self):
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

    def test_perform_with_subdomain(self):
        from certbot.achallenges import KeyAuthorizationAnnotatedChallenge
        from acme import challenges
        import josepy as jose

        challb = challenges.DNS01(token=jose.b64decode("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+oA"))
        domain = "*.test.example.com"

        # Set up the default_zone property for this test
        type(self.mock_client).default_zone = mock.PropertyMock(return_value="example.com")
        achall = KeyAuthorizationAnnotatedChallenge(
            challb=challb, domain=domain, account_key=jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem")))
        
        self.auth.perform([achall])

        expected = [mock.call.add_record(mock.ANY), mock.call.commit()]
        self.assertEqual(expected, self.mock_client.mock_calls)
        # Verify that the record name includes the subdomain
        self.assertEqual(
            "_acme-challenge.test", self.mock_client.mock_calls[0][1][0].name
        )
