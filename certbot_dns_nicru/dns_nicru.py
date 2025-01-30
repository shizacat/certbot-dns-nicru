"""DNS Authenticator for nic.ru."""
import logging

import zope.interface

from sh_nic_api import DnsApi
from sh_nic_api.models import TXTRecord
from sh_nic_api.exceptions import DnsApiException
from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """
    DNS Authenticator for nic.ru
    This Authenticator uses the nic.ru Remote REST API
    to fulfill a dns-01 challenge.
    """

    description = (
        "Obtain certificates using a DNS TXT record "
        "(if you are using nic.ru for DNS)."
    )
    ttl: int = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=120
        )
        add("credentials", help="nic.ru credentials INI file.")

    def more_info(self) -> str:
        return (
            "This plugin configures a DNS TXT record to respond to "
            "a dns-01 challenge using the nic.ru Remote REST API."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "nic.ru credentials INI file",
            {
                "client_id": "The id of application",
                "client_secret": "The token of application",
                "username": "Username for nic.ru Remote API (---/NIC-D).",
                "password": "Password for nic.ru Remote API.",
                "scope": "Scope for access (GET:/dns-master/.+)",
                "service": "Service name",
                "zone": "Zone name",
            },
        )

    def _perform(self, domain: str, validation_name: str, validation: str):
        client = self._get_client()
        try:
            client.add_record(TXTRecord(
                txt=validation,
                ttl=self.ttl,
                name=self._extract_name(
                    name=validation_name, zone=client.default_zone
                )
            ))
            client.commit()
        except DnsApiException as e:
            raise errors.PluginError(f"Add record error: {e}")

    def _cleanup(self, domain: str, validation_name: str, validation: str):
        client = self._get_client()
        name = self._extract_name(
            name=validation_name, zone=client.default_zone)
        try:
            for record in client.records():
                if record.name != name:
                    continue
                client.delete_record(record_id=record.id)
                client.commit()
        except DnsApiException as e:
            raise errors.PluginError(f"Delete record error: {e}")

    def _get_client(self) -> DnsApi:
        client = DnsApi(
            client_id=self.credentials.conf("client_id"),
            client_secret=self.credentials.conf("client_secret"),
            username=self.credentials.conf("username"),
            password=self.credentials.conf("password"),
            scope=self.credentials.conf("scope"),
            default_service=self.credentials.conf("service"),
            default_zone=self.credentials.conf("zone"),
        )
        try:
            client.get_token()
        except DnsApiException as e:
            raise errors.PluginError(f"Get token error: {e}")
        return client

    def _extract_name(self, name: str, zone: str) -> str:
        """
        Extract subdomain from validation name
        """
        # Extract everything before the zone name
        # to preserve subdomain structure
        name = name.replace(f".{zone}", "")
        # Remove wildcard prefix if present
        name = name.replace("*.", "")
        return name
