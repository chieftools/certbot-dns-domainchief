"""DNS Authenticator for Domain Chief DNS."""
import logging
from importlib.metadata import version
from typing import Any
from typing import Callable
from typing import Tuple
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
CREDENTIAL_URL = "https://domain.chief.app/api/tokens"
DEFAULT_PROPAGATION_SECONDS = 60
DEFAULT_TTL = 300


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Domain Chief

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
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the Domain Chief domain ID.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Domain Chief API
        """

        domain_id, domain_name = self._find_domain_id(domain)
        record_name = self._strip_domain_suffix(record_name, domain_name)

        payload = {
            "type": "TXT",
            "name": record_name,
            "content": record_content,
            "ttl": DEFAULT_TTL,
            "metadata": {
                "automation": "certbot-dns-domainchief"
            }
        }

        logger.debug("Attempting to add record to zone %s: %s", domain_id, payload)

        response = requests.post(
            f"{API_BASE_URL}/domains/{domain_id}/dns/records",
            json=payload,
            headers=self.headers,
        )

        if response.status_code != 200:
            raise errors.PluginError(
                f"API error ({response.status_code}): {response.text}"
            )

        record_id = self._find_txt_record_id(domain_id, record_name, record_content)
        logger.debug("Successfully added TXT record with record_id: %s", record_id)

    def del_txt_record(
            self, domain: str, record_name: str, record_content: str
    ) -> None:
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain: The domain to use to look up the Domain Chief domain ID.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        try:
            domain_id, domain_name = self._find_domain_id(domain)
        except errors.PluginError as e:
            logger.debug("Encountered error finding domain_id during deletion: %s", e)
            return

        record_name = self._strip_domain_suffix(record_name, domain_name)
        record_id = self._find_txt_record_id(domain_id, record_name, record_content)

        if record_id:
            response = requests.delete(
                f"{API_BASE_URL}/domains/{domain_id}/dns/records/{record_id}",
                headers=self.headers,
            )
            if response.status_code != 200:
                logger.error(
                    "API error (%s): %s", response.status_code, response.text
                )
        else:
            logger.debug("TXT record not found; no cleanup needed.")

    def _find_domain_id(self, domain: str) -> Tuple[str, str]:
        """
        Find the domain ID for a given domain name.

        :param str domain: The domain name for which to find the ID.
        :returns: The ID and domain name, if found.
        :rtype: tuple(str, str)
        :raises certbot.errors.PluginError: if no domain is found.
        """

        zone_name_guesses = dns_common.base_domain_name_guesses(domain)

        for zone_name_guess in zone_name_guesses:
            # Skip TLDs without a dot (e.g., "com", "org")
            if "." not in zone_name_guess:
                continue

            response = requests.get(
                f"{API_BASE_URL}/domains/{zone_name_guess}",
                headers=self.headers,
            )

            # Domain not found, try the next guess
            if response.status_code == 404:
                continue

            if response.status_code != 200:
                raise errors.PluginError(
                    f"API error ({response.status_code}): {response.text}"
                )

            data = response.json().get("data")
            if data and "id" in data:
                return data["id"], zone_name_guess

        raise errors.PluginError("Could not find domain in account.")

    def _find_txt_record_id(
            self, domain_id: str, record_name: str, record_content: str
    ) -> Optional[str]:
        """
        Find the record_id for a TXT record with the given name and content.

        :param str domain_id: The domain_id which contains the record.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :returns: The record_id, if found.
        :rtype: str
        """

        response = requests.get(
            f"{API_BASE_URL}/domains/{domain_id}/dns/records?query={record_name}&metadata[automation]=certbot-dns-domainchief",
            headers=self.headers
        )

        if response.status_code != 200:
            raise errors.PluginError(
                f"API error ({response.status_code}): {response.text}"
            )

        # Iterate through records and find the TXT record with the right name and value
        for record in response.json()["data"]:
            if (
                    record["type"] == "TXT"
                    and record["name"] == record_name
                    # record content is wrapped in quotes for TXT records
                    and record["content"] == f'"{record_content}"'
            ):
                return record["id"]

        logger.debug("Unable to find TXT record.")
        return None

    @staticmethod
    def _strip_domain_suffix(record_name: str, domain_name: str) -> str:
        """
        Strip the domain suffix from a record name.

        :param str record_name: The full record name (e.g., '_acme-challenge.example.com').
        :param str domain_name: The domain name to strip (e.g., 'example.com').
        :returns: The record name without the domain suffix (e.g., '_acme-challenge').
        :rtype: str
        """
        if record_name.endswith(domain_name):
            return record_name[: -(len(domain_name) + 1)]
        return record_name
