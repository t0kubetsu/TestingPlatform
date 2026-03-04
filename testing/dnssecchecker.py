"""
DNSSEC Chain-of-Trust Validator
Mimics the Verisign DNSSEC Debugger (https://dnssec-debugger.verisignlabs.com)

Validates the full chain: Trust Anchor → . → TLD → SLD → domain

Usage:
    python dnssec_checker.py <domain> [record_type]

Examples:
    python dnssec_checker.py nc3.lu
    python dnssec_checker.py example.com AAAA

Requirements:
    pip install dnspython requests
"""

from __future__ import annotations

import logging
import secrets
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.resolver
import dns.rrset
import requests
from dns.rdata import Rdata

logging.basicConfig(stream=sys.stdout, level=logging.WARNING, format="%(message)s")
logger = logging.getLogger("dnssec")

GREEN = "✅"
RED = "❌"
INFO = "   "

ALGORITHM_MAP = {
    1: "RSAMD5",
    3: "DSA",
    5: "RSASHA1",
    6: "DSA-NSEC3-SHA1",
    7: "RSASHA1-NSEC3-SHA1",
    8: "RSASHA256",
    10: "RSASHA512",
    12: "ECC-GOST",
    13: "ECDSAP256SHA256",
    14: "ECDSAP384SHA384",
    15: "Ed25519",
    16: "Ed448",
}

DIGEST_MAP = {
    1: "SHA-1",
    2: "SHA-256",
    3: "GOST R 34.11-94",
    4: "SHA-384",
}

ROOT_SERVERS = {
    "a.root-servers.net": "198.41.0.4",
    "b.root-servers.net": "170.247.170.2",
    "c.root-servers.net": "192.33.4.12",
    "d.root-servers.net": "199.7.91.13",
    "e.root-servers.net": "192.203.230.10",
    "f.root-servers.net": "192.5.5.241",
    "g.root-servers.net": "192.112.36.4",
    "h.root-servers.net": "198.97.190.53",
    "i.root-servers.net": "192.36.148.17",
    "j.root-servers.net": "192.58.128.30",
    "k.root-servers.net": "193.0.14.129",
    "l.root-servers.net": "199.7.83.42",
    "m.root-servers.net": "202.12.27.33",
}


def _pick_root_server() -> tuple[str, str]:
    """Randomly select a root name server using a cryptographically secure RNG.

    Returns:
        A (name, ip) tuple, e.g. ("k.root-servers.net", "193.0.14.129").
    """
    names = list(ROOT_SERVERS.keys())
    name = names[secrets.randbelow(len(names))]
    return name, ROOT_SERVERS[name]


DNS_TIMEOUT = 5
DNS_PORT = 53


def _udp_query(
    qname: str | dns.name.Name,
    rdtype: int,
    nameserver: str,
    port: int = DNS_PORT,
    timeout: float = DNS_TIMEOUT,
) -> dns.message.Message:
    """Send a DNSSEC-enabled UDP query and return the raw response."""
    q = dns.message.make_query(qname, rdtype, want_dnssec=True)
    try:
        resp = dns.query.udp(q, nameserver, timeout=timeout, port=port)
    except Exception as exc:
        raise RuntimeError(
            f"UDP query for {qname}/{dns.rdatatype.to_text(rdtype)} "
            f"to {nameserver} failed: {exc}"
        ) from exc
    return resp


def _extract_rrsets(
    response: dns.message.Message, rdtype: int
) -> tuple[Optional[dns.rrset.RRset], Optional[dns.rrset.RRset]]:
    """Return (rrset, rrsig_rrset) from any section of a response."""
    rrset = rrsig = None
    for section in (response.answer, response.authority, response.additional):
        for rr in section:
            if rr.rdtype == rdtype and rrset is None:
                rrset = rr
            elif rr.rdtype == dns.rdatatype.RRSIG and rrsig is None:
                # Check RRSIG covers rdtype
                for sig in rr:
                    if sig.type_covered == rdtype:
                        rrsig = rr
                        break
    return rrset, rrsig


def _get_ns_for_zone(zone: str, parent_ns: str) -> list[tuple[str, str]]:
    """
    Query parent_ns for zone's NS records.
    Returns list of (name, ip) tuples for the nameservers.
    """
    resp = _udp_query(zone, dns.rdatatype.NS, parent_ns)
    ns_names: list[str] = []
    for section in (resp.answer, resp.authority):
        for rr in section:
            if rr.rdtype == dns.rdatatype.NS:
                ns_names = [r.target.to_text() for r in rr]
                break
        if ns_names:
            break

    # Resolve IPs from glue (additional section) or fall back to system resolver
    glue: dict[str, str] = {}
    for rr in resp.additional:
        if rr.rdtype == dns.rdatatype.A:
            glue[rr.name.to_text()] = rr[0].address

    result: list[tuple[str, str]] = []
    for name in ns_names:
        if name in glue:
            result.append((name, glue[name]))
        else:
            try:
                ans = dns.resolver.resolve(name, "A")
                result.append((name, ans[0].address))
            except Exception:
                pass
    return result


def _get_ds_from_parent(
    zone: str, parent_ns: str
) -> tuple[Optional[dns.rrset.RRset], Optional[dns.rrset.RRset]]:
    """Query parent_ns for zone's DS records + covering RRSIG."""
    resp = _udp_query(zone, dns.rdatatype.DS, parent_ns)
    return _extract_rrsets(resp, dns.rdatatype.DS)


def _get_dnskey(
    zone: str, ns: str
) -> tuple[Optional[dns.rrset.RRset], Optional[dns.rrset.RRset]]:
    """Query ns for zone's DNSKEY records + covering RRSIG."""
    resp = _udp_query(zone, dns.rdatatype.DNSKEY, ns)
    return _extract_rrsets(resp, dns.rdatatype.DNSKEY)


def _get_rrset(
    qname: str, rdtype: int, ns: str
) -> tuple[Optional[dns.rrset.RRset], Optional[dns.rrset.RRset]]:
    """Query ns for qname/rdtype + covering RRSIG."""
    resp = _udp_query(qname, rdtype, ns)
    return _extract_rrsets(resp, rdtype)


def _fmt_ds(ds: Rdata) -> str:
    digest_name = DIGEST_MAP.get(ds.digest_type, str(ds.digest_type))
    return f"DS={ds.key_tag}/{digest_name}"


def _fmt_dnskey(dnskey: Rdata) -> str:
    tag = dns.dnssec.key_id(dnskey)
    sep = "/SEP" if dnskey.flags & 0x0001 else ""
    return f"DNSKEY={tag}{sep}"


def _fmt_rrsig(rrsig: Rdata) -> str:
    return f"RRSIG={rrsig.key_tag}"


def _algo_name(alg: int) -> str:
    return ALGORITHM_MAP.get(alg, f"ALG{alg}")


def _ds_matches_dnskey(ds: Rdata, dnskey: Rdata, zone: str) -> bool:
    """Return True if ds is a valid hash of dnskey."""
    try:
        computed = dns.dnssec.make_ds(zone, dnskey, ds.digest_type)
        return computed.digest == ds.digest
    except Exception:
        return False


def _validate_rrsig_over_rrset(
    rrset: dns.rrset.RRset,
    rrsig_rrset: dns.rrset.RRset,
    dnskeys: dns.rrset.RRset,
    zone: str,
) -> tuple[bool, Optional[int]]:
    """
    Try to validate rrsig_rrset over rrset using any key in dnskeys.
    Returns (success, key_tag_used).
    """
    zone_name = dns.name.from_text(zone)
    for dnskey in dnskeys:
        key_tag = dns.dnssec.key_id(dnskey)
        try:
            key_rrset = dns.rrset.from_rdata(zone_name, dnskeys.ttl, dnskey)
            dns.dnssec.validate(rrset, rrsig_rrset, {zone_name: key_rrset})
            return True, key_tag
        except (dns.exception.ValidationFailure, Exception):
            continue
    return False, None


class DNSSECChecker:
    """
    Full DNSSEC chain-of-trust validator.

    Walks: Trust Anchor → root (.) → TLD → ... → target zone
    and validates each DS → DNSKEY → RRSIG link.
    """

    def __init__(self, domain: str, record_type: str = "A"):
        self.domain = dns.name.from_text(
            domain
        ).to_text()  # canonical with trailing dot
        self.rdtype = dns.rdatatype.from_text(record_type)
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def check(self) -> bool:
        domain_label = self.domain.rstrip(".")
        print(f"\n{'=' * 70}")
        print(f"  DNSSEC Validation for: {domain_label}")
        print(f"{'=' * 70}\n")

        zones = self._build_zone_list(self.domain)

        trust_anchor_ds = self._load_trust_anchor()
        if not trust_anchor_ds:
            self._fail("Could not load IANA trust anchor")
            return False

        # We'll track the validated DNSKEY rrset per zone so we can
        # verify the DS in the child zone is signed by the parent's ZSK.
        # Structure: zone → (dnskey_rrset, rrsig_rrset)
        validated_keys: dict[str, dns.rrset.RRset] = {}

        # ── Step 1: Root zone ─────────────────────────────────────────────────
        root_ok = self._check_root(trust_anchor_ds, validated_keys)
        if not root_ok:
            return False

        # ── Steps 2..N: Each zone in the hierarchy ────────────────────────────
        for i in range(1, len(zones)):
            parent_zone = zones[i - 1]  # e.g. "."
            child_zone = zones[i]  # e.g. "com."

            ok = self._check_zone(
                parent_zone=parent_zone,
                child_zone=child_zone,
                parent_validated_keys=validated_keys[parent_zone],
                validated_keys=validated_keys,
            )
            if not ok:
                return False

        # ── Final: Validate the A/AAAA/etc. record itself ─────────────────────
        target_zone = zones[-1]
        self._check_final_rrset(target_zone, validated_keys[target_zone])

        print(f"\n{'=' * 70}")
        if self.errors:
            print(f"  {RED}  Validation FAILED — {len(self.errors)} error(s)")
            for e in self.errors:
                print(f"     • {e}")
        else:
            print(f"  {GREEN}  Full chain-of-trust validated successfully!")
        print(f"{'=' * 70}\n")

        return not bool(self.errors)

    def _build_zone_list(self, fqdn: str) -> list[str]:
        """
        Return the chain of *actual DNS zones* from root to the zone that
        is authoritative for fqdn, e.g.:
            example.com     → ['.', 'com.', 'example.com.']
            www.example.com → ['.', 'com.', 'example.com.'] ← no extra zone

        We detect real zone cuts by querying for a SOA record at each
        candidate name.  If the SOA answer section contains the candidate
        name itself (aa=1 answer) that candidate is a zone apex; otherwise
        it is just a record inside an ancestor zone and we skip it.
        """
        name = dns.name.from_text(fqdn)
        labels = name.labels

        # Build candidate zones from TLD down to the full name
        candidates: list[str] = []
        for i in range(len(labels) - 1, 0, -1):
            zone = dns.name.Name(labels[i - 1 :]).to_text()
            if zone != ".":
                candidates.append(zone)

        zones = ["."]
        _, root_ns_ip = _pick_root_server()
        # Start resolution from a root server; after each confirmed zone we
        # use one of its own nameservers for the next query.
        current_ns_ip = root_ns_ip

        for candidate in candidates:
            is_zone = self._is_zone_apex(candidate, current_ns_ip)
            if is_zone:
                zones.append(candidate)
                # Update resolver to use the new zone's own NS for the next step
                new_ns_ip = self._get_first_ns_ip(candidate, current_ns_ip)
                if new_ns_ip:
                    current_ns_ip = new_ns_ip

        return zones

    def _is_zone_apex(self, candidate: str, ns_ip: str) -> bool:
        """
        Return True if *candidate* is the apex of its own zone.

        We send a SOA query with DO=1.  A real zone apex returns the SOA
        in the ANSWER section (aa bit set).  A name that is merely a record
        inside a parent zone returns the parent's SOA in the AUTHORITY section.
        """
        try:
            resp = _udp_query(candidate, dns.rdatatype.SOA, ns_ip)
            for rr in resp.answer:
                if rr.rdtype == dns.rdatatype.SOA:
                    # The answer contains a SOA whose owner matches the candidate
                    if rr.name == dns.name.from_text(candidate):
                        return True
            return False
        except Exception:
            # On timeout / SERVFAIL assume it is not a separate zone
            return False

    def _get_first_ns_ip(self, zone: str, fallback_ns_ip: str) -> Optional[str]:
        """
        Return the IP of the first nameserver we can resolve for *zone*,
        preferring glue records from the delegation response.
        """
        try:
            resp = _udp_query(zone, dns.rdatatype.NS, fallback_ns_ip)
            ns_names: list[str] = []
            for section in (resp.answer, resp.authority):
                for rr in section:
                    if rr.rdtype == dns.rdatatype.NS:
                        ns_names = [r.target.to_text() for r in rr]
                        break
                if ns_names:
                    break

            glue: dict[str, str] = {}
            for rr in resp.additional:
                if rr.rdtype == dns.rdatatype.A:
                    glue[rr.name.to_text()] = rr[0].address

            for name in ns_names:
                if name in glue:
                    return glue[name]
                try:
                    ans = dns.resolver.resolve(name, "A")
                    return ans[0].address
                except Exception:
                    continue
        except Exception:
            pass
        return None

    def _load_trust_anchor(self) -> list[Rdata]:
        print(f"{'─' * 70}")
        print("  Trust Anchor (IANA root-anchors.xml)")
        print(f"{'─' * 70}")

        try:
            xml_data = requests.get(
                "https://data.iana.org/root-anchors/root-anchors.xml",
                timeout=10,
            ).content
        except Exception as exc:
            self._fail(f"Could not fetch root-anchors.xml: {exc}")
            return []

        now = datetime.now(timezone.utc)
        active: list[Rdata] = []

        for kd in ET.fromstring(xml_data).findall(".//KeyDigest"):
            valid_from = kd.attrib.get("validFrom")
            valid_until = kd.attrib.get("validUntil")
            flags_el = kd.find("Flags")
            if flags_el is None:
                continue
            if int(flags_el.text) != 257:
                continue  # Only KSK / SEP
            keytag = int(kd.find("KeyTag").text)
            algorithm = int(kd.find("Algorithm").text)
            digest_type = int(kd.find("DigestType").text)
            digest = kd.find("Digest").text.strip().lower()

            if valid_from and datetime.fromisoformat(valid_from) > now:
                continue
            if valid_until and datetime.fromisoformat(valid_until) < now:
                continue

            ds = dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.DS,
                f"{keytag} {algorithm} {digest_type} {digest}",
            )
            active.append(ds)
            algo_name = _algo_name(algorithm)
            digest_name = DIGEST_MAP.get(digest_type, str(digest_type))
            print(
                f"  {GREEN} Trust anchor DS={keytag}/{digest_name} "
                f"(algorithm {algo_name}) — active"
            )

        if not active:
            self._fail("No active trust anchor DS records found")
        return active

    def _check_root(
        self,
        trust_anchor_ds: list[Rdata],
        validated_keys: dict,
    ) -> bool:
        print(f"\n{'─' * 70}")
        print("  Zone: . (root)")
        print(f"{'─' * 70}")

        root_ns_name, root_ns_ip = _pick_root_server()

        # Fetch root DNSKEY + RRSIG
        print(f"\n  Fetching DNSKEY for . from {root_ns_name} ({root_ns_ip})")
        try:
            dnskey_rrset, rrsig_rrset = _get_dnskey(".", root_ns_ip)
        except RuntimeError as exc:
            self._fail(str(exc))
            return False

        if not dnskey_rrset:
            self._fail("No DNSKEY records found for root zone")
            return False

        print(f"  {GREEN} Found {len(dnskey_rrset)} DNSKEY record(s) for .")
        for dk in dnskey_rrset:
            tag = dns.dnssec.key_id(dk)
            kind = "KSK/SEP" if dk.flags & 0x0001 else "ZSK"
            algo = _algo_name(dk.algorithm)
            print(f"  {INFO}   keytag={tag}  type={kind}  algorithm={algo}")

        # Verify each trust anchor DS against the root DNSKEYs
        any_matched = False
        for ta_ds in trust_anchor_ds:
            for dnskey in dnskey_rrset:
                if _ds_matches_dnskey(ta_ds, dnskey, "."):
                    tag = dns.dnssec.key_id(dnskey)
                    print(f"  {GREEN} {_fmt_ds(ta_ds)} verifies {_fmt_dnskey(dnskey)}")
                    any_matched = True

        if not any_matched:
            self._fail("No trust anchor DS matched any root DNSKEY")
            return False

        # Verify RRSIG over the DNSKEY RRset
        if not rrsig_rrset:
            self._fail("No RRSIG found over root DNSKEY RRset")
            return False

        ok, key_tag_used = _validate_rrsig_over_rrset(
            dnskey_rrset, rrsig_rrset, dnskey_rrset, "."
        )
        if ok:
            print(
                f"  {GREEN} {_fmt_rrsig(rrsig_rrset[0])} and DNSKEY={key_tag_used}/SEP "
                f"verifies the DNSKEY RRset"
            )
        else:
            self._fail("RRSIG over root DNSKEY RRset could not be validated")
            return False

        # All root DNSKEYs are now trusted
        validated_keys["."] = dnskey_rrset
        return True

    def _check_zone(
        self,
        parent_zone: str,
        child_zone: str,
        parent_validated_keys: dns.rrset.RRset,
        validated_keys: dict,
    ) -> bool:
        print(f"\n{'─' * 70}")
        print(f"  Zone: {child_zone}  (parent: {parent_zone})")
        print(f"{'─' * 70}")

        # ── 1. Get DS from parent ─────────────────────────────────────────────
        # Find a nameserver for the parent zone
        parent_ns_ip = self._get_ns_ip_for_zone(parent_zone, validated_keys)
        if not parent_ns_ip:
            self._fail(f"Could not find a nameserver for parent zone {parent_zone}")
            return False

        print(f"\n  [DS check: {parent_zone} → {child_zone}]")
        print(f"  Querying {parent_zone} NS for {child_zone} DS records")

        try:
            ds_rrset, ds_rrsig = _get_ds_from_parent(child_zone, parent_ns_ip)
        except RuntimeError as exc:
            self._fail(str(exc))
            return False

        if not ds_rrset:
            self._fail(
                f"No DS records for {child_zone} in parent zone {parent_zone} "
                f"— zone is unsigned or DS is missing"
            )
            return False

        print(f"  {GREEN} Found {len(ds_rrset)} DS record(s) for {child_zone}")
        for ds in ds_rrset:
            algo_name = _algo_name(ds.algorithm)
            print(f"  {INFO}   {_fmt_ds(ds)}  algorithm={algo_name}")
            print(
                f"  {INFO}   {child_zone} IN DS ( {ds.key_tag} {ds.algorithm} "
                f"{ds.digest_type} {ds.digest.hex()} )"
            )

        # Verify RRSIG over DS using parent's validated keys
        if not ds_rrsig:
            self._fail(f"No RRSIG found over {child_zone} DS RRset in {parent_zone}")
            return False

        ok, key_tag_used = _validate_rrsig_over_rrset(
            ds_rrset, ds_rrsig, parent_validated_keys, parent_zone
        )
        if ok:
            print(
                f"  {GREEN} {_fmt_rrsig(ds_rrsig[0])} and DNSKEY={key_tag_used} "
                f"verifies the DS RRset"
            )
        else:
            self._fail(
                f"RRSIG over {child_zone} DS RRset could not be validated "
                f"using {parent_zone} keys"
            )
            return False

        # ── 2. Fetch child zone DNSKEY ────────────────────────────────────────
        child_ns_list = self._resolve_ns_for_child(child_zone, parent_ns_ip)
        if not child_ns_list:
            self._fail(f"Could not resolve any nameserver for {child_zone}")
            return False

        print(f"\n  [DNSKEY check: {child_zone}]")
        dnskey_rrset = rrsig_rrset = None
        for ns_name, ns_ip in child_ns_list:
            print(f"  Querying {ns_name} ({ns_ip}) for {child_zone} DNSKEY")
            try:
                dnskey_rrset, rrsig_rrset = _get_dnskey(child_zone, ns_ip)
                if dnskey_rrset:
                    break
            except RuntimeError:
                continue

        if not dnskey_rrset:
            self._fail(f"No DNSKEY records found for {child_zone}")
            return False

        print(f"  {GREEN} Found {len(dnskey_rrset)} DNSKEY record(s) for {child_zone}")
        for dk in dnskey_rrset:
            tag = dns.dnssec.key_id(dk)
            kind = "KSK/SEP" if dk.flags & 0x0001 else "ZSK"
            algo = _algo_name(dk.algorithm)
            print(f"  {INFO}   keytag={tag}  type={kind}  algorithm={algo}")

        # ── 3. Verify DS matches DNSKEY ───────────────────────────────────────
        any_matched = False
        for ds in ds_rrset:
            for dnskey in dnskey_rrset:
                if _ds_matches_dnskey(ds, dnskey, child_zone):
                    tag = dns.dnssec.key_id(dnskey)
                    print(f"  {GREEN} {_fmt_ds(ds)} verifies {_fmt_dnskey(dnskey)}")
                    any_matched = True

        if not any_matched:
            self._fail(f"No DS record for {child_zone} matched any DNSKEY")
            return False

        # ── 4. Verify RRSIG over DNSKEY RRset ────────────────────────────────
        if not rrsig_rrset:
            self._fail(f"No RRSIG found over {child_zone} DNSKEY RRset")
            return False

        ok, key_tag_used = _validate_rrsig_over_rrset(
            dnskey_rrset, rrsig_rrset, dnskey_rrset, child_zone
        )
        if ok:
            print(
                f"  {GREEN} {_fmt_rrsig(rrsig_rrset[0])} and DNSKEY={key_tag_used}/SEP "
                f"verifies the DNSKEY RRset"
            )
        else:
            self._fail(f"RRSIG over {child_zone} DNSKEY RRset could not be validated")
            return False

        validated_keys[child_zone] = dnskey_rrset
        return True

    def _check_final_rrset(
        self,
        zone: str,
        zone_dnskeys: dns.rrset.RRset,
    ) -> bool:
        rdtype_text = dns.rdatatype.to_text(self.rdtype)
        qname = self.domain

        print(f"\n{'─' * 70}")
        print(f"  Record validation: {qname} {rdtype_text}")
        print(f"{'─' * 70}")

        ns_list = self._get_authoritative_ns(zone, zone_dnskeys)
        if not ns_list:
            self._fail(f"Could not find authoritative NS for {zone}")
            return False

        rrset = rrsig_rrset = None
        for ns_name, ns_ip in ns_list:
            print(f"\n  Querying {ns_name} ({ns_ip}) for {qname} {rdtype_text}")
            try:
                rrset, rrsig_rrset = _get_rrset(qname, self.rdtype, ns_ip)
                if rrset:
                    break
            except RuntimeError:
                continue

        if not rrset:
            # Could be NXDOMAIN or genuinely no record — check NSEC/NSEC3 for proof
            print(f"  {RED} No {rdtype_text} record found for {qname}")
            self._fail(f"No {rdtype_text} record for {qname}")
            return False

        print(f"  {GREEN} Found {len(rrset)} {rdtype_text} record(s):")
        for r in rrset:
            print(f"  {INFO}   {qname} {rrset.ttl} IN {rdtype_text} {r.to_text()}")

        if not rrsig_rrset:
            self._fail(f"No RRSIG found over {qname} {rdtype_text} RRset")
            return False

        ok, key_tag_used = _validate_rrsig_over_rrset(
            rrset, rrsig_rrset, zone_dnskeys, zone
        )
        if ok:
            print(
                f"  {GREEN} {_fmt_rrsig(rrsig_rrset[0])} and DNSKEY={key_tag_used} "
                f"verifies the {rdtype_text} RRset"
            )
        else:
            self._fail(f"RRSIG over {qname} {rdtype_text} RRset could not be validated")
            return False

        # Check RRSIG expiry
        for sig in rrsig_rrset:
            exp = datetime.fromtimestamp(sig.expiration, tz=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            if exp < now:
                self._fail(
                    f"RRSIG over {rdtype_text} RRset is EXPIRED (expired {exp.isoformat()})"
                )
            else:
                days_left = (exp - now).days
                print(
                    f"  {GREEN} RRSIG expires {exp.strftime('%Y-%m-%d')} "
                    f"({days_left} days remaining)"
                )

        return True

    def _get_ns_ip_for_zone(self, zone: str, validated_keys: dict) -> Optional[str]:
        """Return an IP for a nameserver of zone (root → use hardcoded list)."""
        if zone == ".":
            _, ip = _pick_root_server()
            return ip

        # For other zones we already resolved their NS during parent traversal
        # but we can also query the system resolver
        try:
            ns_list = dns.resolver.resolve(zone, "NS")
            for ns_rr in ns_list:
                ns_name = ns_rr.target.to_text()
                try:
                    a_list = dns.resolver.resolve(ns_name, "A")
                    return a_list[0].address
                except Exception:
                    continue
        except Exception:
            pass
        return None

    def _resolve_ns_for_child(
        self, child_zone: str, parent_ns_ip: str
    ) -> list[tuple[str, str]]:
        """
        Ask the parent NS for the child zone's NS delegation,
        then resolve IPs.
        """
        try:
            resp = _udp_query(child_zone, dns.rdatatype.NS, parent_ns_ip)
        except RuntimeError:
            return []

        ns_names: list[str] = []
        for section in (resp.answer, resp.authority):
            for rr in section:
                if rr.rdtype == dns.rdatatype.NS:
                    ns_names = [r.target.to_text() for r in rr]
                    break
            if ns_names:
                break

        glue: dict[str, str] = {}
        for rr in resp.additional:
            if rr.rdtype == dns.rdatatype.A:
                glue[rr.name.to_text()] = rr[0].address

        result: list[tuple[str, str]] = []
        for name in ns_names:
            if name in glue:
                result.append((name, glue[name]))
            else:
                try:
                    ans = dns.resolver.resolve(name, "A")
                    result.append((name, ans[0].address))
                except Exception:
                    pass
        return result

    def _get_authoritative_ns(
        self, zone: str, zone_dnskeys: dns.rrset.RRset
    ) -> list[tuple[str, str]]:
        """Return authoritative NS list for zone using system resolver as fallback."""
        try:
            ns_ans = dns.resolver.resolve(zone, "NS")
            result = []
            for ns_rr in ns_ans:
                ns_name = ns_rr.target.to_text()
                try:
                    a_ans = dns.resolver.resolve(ns_name, "A")
                    result.append((ns_name, a_ans[0].address))
                except Exception:
                    pass
            return result
        except Exception:
            return []

    def _fail(self, msg: str):
        self.errors.append(msg)
        print(f"  {RED} ERROR: {msg}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)

    domain = sys.argv[1]
    record_type = sys.argv[2] if len(sys.argv) > 2 else "A"

    checker = DNSSECChecker(domain, record_type)
    success = checker.check()
    sys.exit(0 if success else 1)
