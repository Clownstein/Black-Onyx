"""Dormant destination validation helpers and fail-closed runner egress."""
from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from security_runner.egress_policy import (
    BLOCKED_TCP_PORTS,
    EgressDenied,
    extra_hosts,
    is_private_ip,
    nftables_policy_script,
    parse_lab_profiles,
    resolve_hosts,
    resolve_ipv4_targets,
    validate_destination,
    validate_destinations,
    validate_resolved_targets,
)


class TestIsPrivateIP:
    @pytest.mark.parametrize("addr", [
        "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
        "169.254.0.1", "0.0.0.0", "255.255.255.255",
        "::1", "fc00::1", "fe80::1", "ff02::1",
    ])
    def test_private_addresses_blocked(self, addr):
        assert is_private_ip(addr) is True

    @pytest.mark.parametrize("addr", [
        "8.8.8.8", "1.1.1.1", "93.184.216.34",
        "2606:4700::1111",
    ])
    def test_public_addresses_allowed(self, addr):
        assert is_private_ip(addr) is False

    def test_invalid_not_private(self):
        assert is_private_ip("not-an-ip") is False


class TestValidateDestination:
    @pytest.mark.parametrize("dest", [
        "example.com", "scanme.nmap.org", "93.184.216.34",
        "sub.domain.example.org",
    ])
    def test_valid_destinations(self, dest):
        assert validate_destination(dest) == dest.lower()

    @pytest.mark.parametrize("dest,reason", [
        ("", "empty"),
        ("*.example.com", "wildcard"),
        ("http://example.com", "URL"),
        ("https://example.com/path", "URL"),
        ("127.0.0.1", "loopback"),
        ("10.0.0.1", "RFC1918"),
        ("192.168.1.1", "RFC1918"),
        ("172.16.0.1", "RFC1918"),
        ("169.254.1.1", "link-local"),
        ("host.localhost", "local TLD"),
        ("printer.local", "local TLD"),
        ("service.internal", "internal TLD"),
    ])
    def test_rejected_destinations(self, dest, reason):
        with pytest.raises(EgressDenied):
            validate_destination(dest)


class TestValidateDestinations:
    def test_empty_list_rejected(self):
        with pytest.raises(EgressDenied):
            validate_destinations([])

    def test_deduplication(self):
        result = validate_destinations(["Example.COM", "example.com", "other.org"])
        assert result == ["example.com", "other.org"]

    def test_too_many(self):
        dests = [f"host{i}.example.com" for i in range(101)]
        with pytest.raises(EgressDenied, match="Too many"):
            validate_destinations(dests)


class TestResolveHosts:
    def test_bare_ip_maps_to_itself(self):
        result = resolve_hosts(["93.184.216.34"])
        assert result == {"93.184.216.34": ["93.184.216.34"]}

    def test_hostname_resolved(self):
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))]
        with patch("security_runner.egress_policy.socket.getaddrinfo", return_value=fake):
            result = resolve_hosts(["example.com"])
        assert result == {"example.com": ["93.184.216.34"]}

    def test_dns_rebind_to_private_blocked(self):
        fake = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0))]
        with patch("security_runner.egress_policy.socket.getaddrinfo", return_value=fake):
            with pytest.raises(EgressDenied, match="DNS rebinding"):
                resolve_hosts(["evil.example.com"])

    def test_mixed_public_private_keeps_public(self):
        fake = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
        ]
        with patch("security_runner.egress_policy.socket.getaddrinfo", return_value=fake):
            result = resolve_hosts(["dual.example.com"])
        assert result == {"dual.example.com": ["93.184.216.34"]}

    def test_unresolvable_raises(self):
        with patch(
            "security_runner.egress_policy.socket.getaddrinfo",
            side_effect=socket.gaierror("no such host"),
        ):
            with pytest.raises(EgressDenied, match="Cannot resolve"):
                resolve_hosts(["nonexistent.invalid"])


class TestExtraHosts:
    def test_hostname_pinned(self):
        pinned = {"example.com": ["93.184.216.34", "93.184.216.35"]}
        result = extra_hosts(pinned)
        assert result == {"example.com": "93.184.216.34"}

    def test_bare_ip_not_pinned(self):
        pinned = {"93.184.216.34": ["93.184.216.34"]}
        result = extra_hosts(pinned)
        assert result == {}


class TestPerJobFirewallPolicy:
    def test_lab_profiles_are_operator_owned_and_strict(self):
        profiles = parse_lab_profiles(
            '{"anvil":{"network":"anvil-internal","cidrs":["10.88.0.0/24"],"ports":[8545]}}'
        )
        assert profiles["anvil"]["network"] == "anvil-internal"
        assert 8545 in profiles["anvil"]["ports"]
        with pytest.raises(EgressDenied):
            parse_lab_profiles(
                '{"anvil":{"network":"anvil-internal","cidrs":["0.0.0.0/0"],"ports":[8545]}}'
            )
        all_tcp = parse_lab_profiles(
            '{"anvil":{"network":"anvil-internal","cidrs":["10.88.0.0/24"],"ports":"all"}}'
        )
        assert all_tcp["anvil"]["ports"] is None

    def test_lab_literal_private_address_is_pinned_inside_registered_cidrs(self):
        import ipaddress

        cidrs = (ipaddress.ip_network("10.88.0.0/24"),)
        pinned, addresses = resolve_ipv4_targets(
            ["10.88.0.2"], profile="lab", lab_cidrs=cidrs, blocked_ips=["10.88.0.1"],
        )
        assert pinned == {"10.88.0.2": ["10.88.0.2"]}
        assert addresses == ["10.88.0.2"]
        assert validate_resolved_targets(
            ["10.88.0.2"], pinned, profile="lab", lab_cidrs=cidrs, blocked_ips=["10.88.0.1"],
        ) == (pinned, addresses)
        with pytest.raises(EgressDenied, match="blocked"):
            resolve_ipv4_targets(
                ["10.88.0.2"], profile="public", lab_cidrs=cidrs,
            )
        with pytest.raises(EgressDenied, match="outside the registered lab"):
            resolve_ipv4_targets(
                ["10.88.1.2"], profile="lab", lab_cidrs=cidrs,
            )

    def test_preview_resolution_is_ipv4_only_and_scoped(self):
        answers = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
        ]
        with patch("security_runner.egress_policy.socket.getaddrinfo", return_value=answers):
            pinned, addresses = resolve_ipv4_targets(["Example.COM"], profile="public")
        assert pinned == {"example.com": ["93.184.216.34"]}
        assert addresses == ["93.184.216.34"]
        validated = validate_resolved_targets(
            ["example.com"], pinned, profile="public",
        )
        assert validated == (pinned, addresses)
        with pytest.raises(EgressDenied, match="do not match"):
            validate_resolved_targets(
                ["other.example"], pinned, profile="public",
            )

    def test_dns_answers_cannot_include_private_or_ipv6_addresses(self):
        mixed = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 0)),
        ]
        with patch("security_runner.egress_policy.socket.getaddrinfo", return_value=mixed):
            with pytest.raises(EgressDenied):
                resolve_ipv4_targets(["example.com"], profile="public")
        with pytest.raises(EgressDenied, match="IPv6"):
            resolve_ipv4_targets(["2606:4700::1111"], profile="public")

    def test_resolution_bounds_addresses_per_host_and_overall(self):
        too_many_for_host = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", (f"93.184.216.{index}", 0))
            for index in range(1, 18)
        ]
        with patch("security_runner.egress_policy.socket.getaddrinfo", return_value=too_many_for_host):
            with pytest.raises(EgressDenied, match="too many IPv4"):
                resolve_ipv4_targets(["example.com"], profile="public")

    def test_firewall_allows_only_listed_ipv4_tcp_ports_and_blocks_control_ports(self):
        script = nftables_policy_script(["93.184.216.34"], [443])
        assert "policy drop" in script
        assert "ip daddr { 93.184.216.34 } tcp dport { 443 }" in script
        assert "udp" not in script
        assert "ip6" not in script
        assert "oifname lo accept" not in script
        for port in (53, 853, 2375, 2376, 6443, 10250):
            with pytest.raises(EgressDenied):
                nftables_policy_script(["93.184.216.34"], [port])
        all_tcp = nftables_policy_script(["10.88.0.2"], [0])
        blocked = ", ".join(str(port) for port in sorted(BLOCKED_TCP_PORTS))
        assert f"ip daddr {{ 10.88.0.2 }} tcp dport != {{ {blocked} }} ct state new accept" in all_tcp
        assert "tcp ct state" not in all_tcp


class TestContainerOptionsEgress:
    """A bridge name must never authorize networked sandbox execution."""

    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch, tmp_path):
        import security_runner.app as runner_app
        monkeypatch.setenv("SESSIONS_ROOT", str(tmp_path))
        monkeypatch.delenv("SECURITY_EGRESS_VERIFIED", raising=False)
        monkeypatch.delenv("SECURITY_CAPTURE_VERIFIED", raising=False)
        monkeypatch.delenv("SECURITY_LAB_PROFILES_JSON", raising=False)
        monkeypatch.delenv("ALLOW_PUBLIC_TARGETS", raising=False)
        monkeypatch.delenv("ALLOW_PRIVATE_TARGETS", raising=False)
        monkeypatch.setattr(runner_app, "_host_sessions_root", lambda: tmp_path)
        self.tmp = tmp_path
        self.runner = runner_app
        runner_app._jobs.clear()
        runner_app._session_counts.clear()
        yield
        runner_app._jobs.clear()
        runner_app._session_counts.clear()

    PINNED = "ghcr.io/example/sandbox@sha256:" + "a" * 64
    SESSION = "f" * 64 + "/work"

    def _job(self, **overrides):
        from security_runner.app import Execution
        base = dict(
            session=self.SESSION, tool="nmap_scan",
            argv=["nmap", "-sV", "93.184.216.34"], timeout=60,
            network_profile="public", destinations=["93.184.216.34"], ports=[443],
        )
        base.update(overrides)
        return Execution(**base)

    def test_offline_still_works_without_egress(self, monkeypatch):
        monkeypatch.delenv("SECURITY_EGRESS_NETWORK", raising=False)
        j = self._job(tool="Read", argv=["sed", "-n", "1p", "--", "a"],
                      network_profile="offline", destinations=[], ports=[])
        opts = self.runner._container_options(j, self.PINNED, self.tmp)
        assert opts["network_mode"] == "none"

    def test_public_rejected_without_egress(self, monkeypatch):
        monkeypatch.delenv("SECURITY_EGRESS_NETWORK", raising=False)
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            self.runner._container_options(self._job(), self.PINNED, self.tmp)
        assert exc.value.status_code == 503

    @pytest.mark.parametrize("profile,destinations", [
        ("public", ["93.184.216.34"]),
        ("public", ["example.com"]),
        ("lab", ["192.168.1.1"]),
    ])
    def test_network_rejected_even_with_bridge(self, monkeypatch, profile, destinations):
        monkeypatch.setenv("SECURITY_EGRESS_NETWORK", "blackonyx_sandbox_egress")
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            self.runner._container_options(
                self._job(network_profile=profile, destinations=destinations),
                self.PINNED, self.tmp,
            )
        assert exc.value.status_code == 503
        assert "verification gate" in str(exc.value.detail)

    def test_offline_remains_offline_even_with_bridge(self, monkeypatch):
        monkeypatch.setenv("SECURITY_EGRESS_NETWORK", "blackonyx_sandbox_egress")
        opts = self.runner._container_options(
            self._job(tool="Read", argv=["sed", "-n", "1p", "--", "a"],
                      network_profile="offline", destinations=[], ports=[]),
            self.PINNED, self.tmp,
        )
        assert opts["network_mode"] == "none"
        assert "extra_hosts" not in opts

    def test_executor_pins_preview_hostnames(self):
        attached = self.runner._attach_guard_network(
            {"image": "x"},
            "abc123",
            {"example.com": ["93.184.216.34", "93.184.216.35"], "1.2.3.4": ["1.2.3.4"]},
        )
        assert attached["network_mode"] == "container:abc123"
        assert attached["extra_hosts"] == {"example.com": "93.184.216.34"}

    def test_execute_rejects_network_before_container_creation(self, monkeypatch):
        from fastapi.testclient import TestClient

        monkeypatch.setenv("SECURITY_EGRESS_NETWORK", "blackonyx_sandbox_egress")
        monkeypatch.setenv("SECURITY_RUNNER_TOKEN", "runner-token")
        monkeypatch.setattr(self.runner, "_validate_image", lambda: self.PINNED)
        monkeypatch.setattr(self.runner, "_resolve_workspace", lambda _session: self.tmp)

        def forbidden(*_args, **_kwargs):
            raise AssertionError("network request reached container creation")

        monkeypatch.setattr(self.runner, "_run_container", forbidden)
        response = TestClient(self.runner.app).post(
            "/execute", json=self._job().model_dump(),
            headers={"Authorization": "Bearer runner-token"},
        )
        assert response.status_code == 503
        assert "verification gate" in response.json()["detail"]
        assert not self.runner._jobs

    def test_capture_gate_refuses_before_opening_docker_client(self, monkeypatch):
        from fastapi import HTTPException
        from security_runner.app import CaptureRequest

        monkeypatch.setenv("SECURITY_RUNNER_TOKEN", "runner-token")
        monkeypatch.delenv("SECURITY_EGRESS_VERIFIED", raising=False)
        monkeypatch.delenv("SECURITY_CAPTURE_VERIFIED", raising=False)
        monkeypatch.setenv("SECURITY_LAB_PROFILES_JSON", "")
        body = CaptureRequest(
            session=self.SESSION, lab_profile_id="anvil", duration=2,
            filter="", job_id="capture-test-01",
        )
        with pytest.raises(HTTPException) as exc:
            self.runner.capture_packets(body, "Bearer runner-token")
        assert exc.value.status_code == 503
        assert not self.runner._jobs

    def test_transaction_signing_key_is_never_passed_to_sandbox(self, monkeypatch):
        from fastapi import HTTPException
        monkeypatch.setenv("CAST_PRIVATE_KEY", "must-not-enter-a-job")
        job = self._job(
            tool="cast_send", argv=["python3", "/usr/share/blackonyx/anvil_send.py"],
            network_profile="lab", destinations=["10.88.0.2"], ports=[8545],
            lab_profile_id="anvil", resolved_targets={"10.88.0.2": ["10.88.0.2"]},
            environment={"CAST_PRIVATE_KEY": "must-not-enter-a-job"},
        )
        with pytest.raises(HTTPException) as exc:
            self.runner._container_options(job, self.PINNED, self.tmp)
        assert exc.value.status_code == 400
        assert exc.value.detail == "Environment is not permitted for this capability"
