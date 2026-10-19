"""DNS Authenticator for Domain Chief DNS."""
import logging
from importlib.metadata import version
from typing import Any
from typing import Callable
from typing import Optional

import requests

try:
    _version = version("certbot-dns-domainchief")
except Exception:
    _version = "unknown"

USER_AGENT = f"certbot-dns-domainchief/{_version}"

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

API_BASE_URL = "https://domain.chief.app/api/v1"
CREDENTIAL_URL = "https://domain.chief.app/api/token/create?scopes=domainchief:acme:write&ref=certbot-dns-domainchief"

DEFAULT_PROPAGATION_SECONDS = 60


class Authenticator(dns_common.DNSAuthenticator):
    """
    DNS Authenticator for Domain Chief

    This Authenticator uses the Domain Chief API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using Domain Chief for DNS)."

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(
            cls, add: Callable[..., None], default_propagation_seconds: int = DEFAULT_PROPAGATION_SECONDS
    ) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add("credentials", help="Domain Chief credentials INI file.")

    def more_info(self) -> str:
        return "This plugin configures a DNS TXT record to respond to a dns-01 challenge using the Domain Chief API."

    def _validate_credentials(self, credentials: CredentialsConfiguration) -> None:
        api_key = credentials.conf("api-key")
        if not api_key:
            raise errors.PluginError(
                "{}: api-key required for authentication (see {})".format(
                    credentials.confobj.filename, CREDENTIAL_URL
                )
            )

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            "credentials",
            "Domain Chief credentials INI file",
            None,
            self._validate_credentials,
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_domainchief_client().add_txt_record(
            domain, validation_name, validation
        )

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_domainchief_client().del_txt_record(domain, validation_name, validation)

    def _get_domainchief_client(self) -> "_DomainChiefClient":
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")
        return _DomainChiefClient(self.credentials.conf("api-key"))


class _DomainChiefClient:
    """
    Encapsulates all communication with the Domain Chief API.
    """

    def __init__(self, api_key: str) -> None:
        self.headers = {
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
            "Authorization": f'Bearer {api_key}',
        }

    def add_txt_record(
            self, domain: str, record_name: str, record_content: str
    ) -> None:
        """
        Publish an ACME challenge value using the supplied information.

        The Domain Chief API resolves the domain from the record name itself, so the
        domain is only used for logging.

        :param str domain: The domain the certificate is requested for.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Domain Chief API
        """

        payload = {
            "name": record_name,
            "value": record_content,
        }

        logger.debug("Attempting to publish challenge for %s: %s", domain, payload)

        response = requests.post(
            f"{API_BASE_URL}/acme/challenges",
            json=payload,
            headers=self.headers,
        )

        if not response.ok:
            raise errors.PluginError(
                f"API error ({response.status_code}): {response.text}"
            )

        record_id = response.json().get("data", {}).get("id")
        logger.debug("Successfully published challenge with record_id: %s", record_id)

    def del_txt_record(
            self, domain: str, record_name: str, record_content: str
    ) -> None:
        """
        Delete an ACME challenge value using the supplied information.

        Only the record with this exact name and value is deleted, so challenges created
        concurrently (e.g., due to concurrent invocations of this plugin) are kept.

        Failures are logged, but not raised.

        :param str domain: The domain the certificate is requested for.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        logger.debug("Attempting to delete challenge for %s: %s", domain, record_name)

        try:
            response = requests.delete(
                f"{API_BASE_URL}/acme/challenges",
                params={
                    "name": record_name,
                    "value": record_content,
                },
                headers=self.headers,
            )
        except requests.RequestException as e:
            logger.error("Encountered error deleting challenge: %s", e)
            return

        if not response.ok:
            logger.error(
                "API error (%s): %s", response.status_code, response.text
            )
