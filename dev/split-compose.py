#!/usr/bin/env python3
"""Adapt the actual Compose manifest to the isolated preview AD network."""

import json
import sys


def main():
    (
        network, samba_ip, management_ip, dc_ip, dns_domain, https_port,
        samba_container, management_container, image, private, fslogix,
        groups, state, samba_lib,
    ) = sys.argv[1:]
    compose = json.load(sys.stdin)
    for key, name in zip(
        ("private_data", "fslogix_data", "group_data", "state_data", "samba_lib_data"),
        (private, fslogix, groups, state, samba_lib),
    ):
        compose["volumes"][key] = {"external": True, "name": name}

    compose["networks"] = {"preview": {"external": True, "name": network}}
    for role, address, container, hostname in (
        ("samba", samba_ip, samba_container, "files"),
        ("management", management_ip, management_container, "management"),
    ):
        service = compose["services"][role]
        del service["build"]
        service.update(
            image=image,
            container_name=container,
            hostname=hostname,
            networks={"preview": {"ipv4_address": address}},
            dns=[dc_ip],
            dns_search=[dns_domain],
            ports=[],
        )

    compose["services"]["management"]["ports"] = [f"127.0.0.1:{https_port}:8443"]
    json.dump(compose, sys.stdout)


if __name__ == "__main__":
    main()
