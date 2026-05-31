#!/usr/bin/env bash
#
# Downloads IPLocate.io free IP-to-country and IP-to-ASN MMDB files into this
# directory (CC BY-SA 4.0 — attribute IPLocate in the product; see README).
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out_dir="${script_dir}"

base_url="https://github.com/iplocate/ip-address-databases/raw/refs/heads/main"

curl -fsSL -o "${out_dir}/ip-to-country.mmdb" "${base_url}/ip-to-country/ip-to-country.mmdb"
echo "wrote ${out_dir}/ip-to-country.mmdb"

curl -fsSL -o "${out_dir}/ip-to-asn.mmdb" "${base_url}/ip-to-asn/ip-to-asn.mmdb"
echo "wrote ${out_dir}/ip-to-asn.mmdb"
