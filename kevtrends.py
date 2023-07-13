import requests
from datetime import datetime, timedelta
import click
from rich.console import Console
from rich.table import Table

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

@click.command()
@click.option("-id", "--cve", help="Filter by CVE ID")
@click.option("-k", "--keyword", help="Search vendorProject, product, and vulnerabilityName")
@click.option("-v", "--vendor", help="Filter by vendor")
@click.option("-d", "--days", type=int, help="Filter by number of days since vulnerability was added")
@click.pass_context
def query_endpoint(ctx, cve, keyword, vendor, days):
    """
    Fetches vulnerability info from CISA's KEV (Known Exploited Vulnerabilities) Catalog.
    """
    if not any([cve, keyword, vendor, days]):
        click.echo(ctx.get_help())
        ctx.exit()

    
    response = requests.get(URL)
    
    if response.status_code != 200:
        click.echo("Failed to fetch data from the endpoint.")
        ctx.exit()
    
    data = response.json()
    
    # Filtering
    filtered_vulnerabilities = data["vulnerabilities"]
    
    if cve or keyword or vendor or days:
        today = datetime.now().date()
        cutoff_date = today - timedelta(days=days) if days else None
        filtered_vulnerabilities = list(filter(
            lambda vuln: (not cve or vuln["cveID"] == cve) and
                         (not keyword or keyword.lower() in vuln["vendorProject"].lower() or 
                          keyword.lower() in vuln["product"].lower() or 
                          keyword.lower() in vuln["vulnerabilityName"].lower()) and
                         (not vendor or vendor.lower() in vuln["vendorProject"].lower()) and
                         (not cutoff_date or datetime.strptime(vuln["dateAdded"], "%Y-%m-%d").date() >= cutoff_date),
            filtered_vulnerabilities
        ))
    
    # Pritty Print :)
    console = Console()
    table = Table(show_header=True, header_style="bold")
    table.add_column("CVE ID")
    table.add_column("Vendor/Project")
    table.add_column("Product")
    table.add_column("Vulnerability Name")
    table.add_column("Date Added")
    table.add_column("Description")
    
    # Table
    for vuln in filtered_vulnerabilities:
        table.add_row(
            vuln["cveID"],
            vuln["vendorProject"],
            vuln["product"],
            vuln["vulnerabilityName"],
            vuln["dateAdded"],
            vuln["shortDescription"]
        )
    
    # Print the table
    console.print(table)

if __name__ == "__main__":
    query_endpoint()
