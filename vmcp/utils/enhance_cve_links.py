"""Enhance CVE links with direct detail URLs."""
import asyncio
import json
import re
from typing import Any

import httpx


async def validate_cve_detail_url(cve_code: str, client: httpx.AsyncClient) -> str | None:
    """Validate if CVE detail URL exists."""
    detail_url = f"https://nvd.nist.gov/vuln/detail/{cve_code}"
    try:
        response = await client.head(detail_url, follow_redirects=True, timeout=10.0)
        if response.status_code == 200:
            return detail_url
    except Exception:
        pass
    return None


async def get_enhanced_cve_url(cve_code: str, client: httpx.AsyncClient) -> str:
    """Get enhanced CVE URL with validation."""
    # Try detail URL first
    detail_url = await validate_cve_detail_url(cve_code, client)
    if detail_url:
        return detail_url

    # Fallback to search URL
    return f"https://nvd.nist.gov/vuln/search#/nvd/home?keyword={cve_code}&resultType=records"


async def enhance_vulnerability_references(
    vulnerability: dict[str, Any],
    client: httpx.AsyncClient
) -> dict[str, Any]:
    """Enhance CVE references in a vulnerability."""
    if 'references' not in vulnerability:
        return vulnerability

    cve_pattern = re.compile(r'CVE-\d{4}-\d+')

    for reference in vulnerability.get('references', []):
        url = reference.get('url', '')

        # Check if this is a generic CVE URL
        if 'nvd.nist.gov/vuln-metrics/cvss' in url or 'nvd.nist.gov' in url:
            # Extract CVE code from the vulnerability ID or aliases
            cve_code = None

            # Check ID
            if 'id' in vulnerability and cve_pattern.match(vulnerability['id']):
                cve_code = vulnerability['id']
            else:
                # Check aliases
                for alias in vulnerability.get('aliases', []):
                    if cve_pattern.match(alias):
                        cve_code = alias
                        break

            if cve_code:
                enhanced_url = await get_enhanced_cve_url(cve_code, client)
                reference['url'] = enhanced_url

    return vulnerability


async def enhance_vulnerabilities(vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Enhance all vulnerabilities with better CVE links."""
    async with httpx.AsyncClient() as client:
        tasks = [enhance_vulnerability_references(vuln, client) for vuln in vulnerabilities]
        return await asyncio.gather(*tasks)


async def process_results_file(file_path: str) -> None:
    """Process a results file and enhance CVE links."""
    with open(file_path, 'r') as f:
        data = json.load(f)

    # Process each organization/repo
    for org_repo, scanners in data.items():
        for scanner, vulnerabilities in scanners.items():
            if vulnerabilities:
                enhanced = await enhance_vulnerabilities(vulnerabilities)
                data[org_repo][scanner] = enhanced

    # Write back
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)


async def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python enhance_cve_links.py <results_file>")
        sys.exit(1)

    await process_results_file(sys.argv[1])
    print(f"Enhanced CVE links in {sys.argv[1]}")


if __name__ == '__main__':
    asyncio.run(main())
