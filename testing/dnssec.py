import logging

import dns.resolver

logger = logging.getLogger(__name__)


class Dnssec:
    def __init__(self, domain: str):
        self.domain = domain

    def check_dnssec(
        self,
    ):
        """
        Check if DNSSEC is enabled for the domain.

        Args:
            domain (str): The domain to check.

        Returns:
            dict: A dictionary containing DNSSEC status and details.
        """
        result = {"enabled": False, "keys": [], "error": None}
        try:
            dnskey = dns.resolver.resolve(self.domain, "DNSKEY")
            result["enabled"] = True
            result["keys"] = [key.to_text() for key in dnskey]
        except dns.resolver.NXDOMAIN:
            result["error"] = "Domain does not exist"
        except dns.resolver.NoAnswer:
            result["error"] = "No DNSKEY records found"
        except dns.exception.DNSException as e:
            result["error"] = f"DNS error: {str(e)}"
        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"

        logger.info(
            f"DNSSEC check for {self.domain}: {'Enabled' if result['enabled'] else 'Disabled'}"
        )
        if result["error"]:
            logger.warning(f"DNSSEC check error for {self.domain}: {result['error']}")

        return result
