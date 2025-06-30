#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
M4LVOK OSINT Tool - V3.0 (All-In-One Edition)
The definitive, all-in-one reconnaissance framework.
"""

import requests
from bs4 import BeautifulSoup
import re
import hashlib
import socket
import random
import time
import json
import argparse
import sys
import io
from urllib.parse import urlparse, urljoin, quote_plus
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from rich.theme import Theme
from rich.text import Text

try:
    from phonenumbers import geocoder, carrier, parse as parse_phone, is_valid_number
    from ipwhois import IPWhois
    from ipwhois.exceptions import IPDefinedError
    import exifread
except ImportError as e:
    print(f"Error: Falta una librería esencial -> {e}. Ejecuta: pip install -r requirements.txt")
    sys.exit(1)

# --- CONFIGURACIÓN ---
CONFIG = { 
    "user_agents": [ "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0" ], 
    "phone_regex": r'(\+?\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}' 
}
STYLES = { "banner": "bold green", "header": "bold magenta", "subheader": "bold yellow", "success": "bold green", "error": "bold red", "warning": "yellow", "info": "cyan", "danger": "blink bold red" }
console = Console(theme=Theme(STYLES))

def display_banner():
    banner_text = """
███╗   ███╗ █████╗ ██╗      ██╗   ██╗ ██╗  ██╗
████╗ ████║██╔══██╗██║      ██║   ██║ ██║ ██╔╝
██╔████╔██║███████║██║      ██║   ██║ █████╔╝ 
██║╚██╔╝██║██╔══██║██║      ██║   ██║ ██╔═██╗ 
██║ ╚═╝ ██║██║  ██║███████╗ ╚██████╔╝ ██║  ██╗
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝  ╚═════╝  ╚═╝  ╚═╝
    """
    version_text = "         [ V 3 . 0 - All-In-One Edition ]"
    console.print(Text(banner_text, style="banner"))
    console.print(Text(version_text, style="banner"), justify="center")
    console.print(Panel("[bold green]The Definitive Telegram OSINT Framework[/bold green]", border_style="green"), justify="center")

class TelegramRecon:
    def __init__(self, username, output_file=None):
        self.username = username.lstrip('@')
        self.target_url = f"https://t.me/{self.username}"
        self.output_file = output_file
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(CONFIG["user_agents"])})
        self.intel = {"recon_timestamp_utc": datetime.utcnow().isoformat()}
        self.soup = None

    def _log(self, message: str, style: str = "info"):
        timestamp = datetime.now().strftime('%H:%M:%S')
        console.print(f"[bold grey50][{timestamp}][/bold grey50] [[{style.upper()}]] {message}", style=style)

    def _make_request(self):
        try:
            self._log(f"Initializing reconnaissance on target: [bold cyan]@{self.username}[/bold cyan]")
            response = self.session.get(self.target_url, timeout=15)
            response.raise_for_status()
            self.soup = BeautifulSoup(response.text, "html.parser")
            self._log("Target profile acquired. HTML structure loaded.", "success")
            return True
        except requests.exceptions.RequestException as e:
            self._log(f"Network failure: {e}", "error")
            return False

    def _extract_basic_intel(self):
        self._log("Extracting primary identifiers (Name, Bio, Photo)...")
        self.intel['username'] = f"@{self.username}"
        name_tag = self.soup.select_one(".tgme_page_title")
        self.intel['display_name'] = name_tag.text.strip() if name_tag else "N/A"
        bio_tag = self.soup.select_one(".tgme_page_description")
        self.intel['bio'] = bio_tag.text.strip() if bio_tag else "N/A"
        photo_tag = self.soup.select_one(".tgme_page_photo_image")
        self.intel['profile_photo_url'] = urljoin(self.target_url, photo_tag['src']) if photo_tag and photo_tag.has_attr('src') else "N/A"
        self._log("Primary identifiers extracted.", "success")

    def _analyze_artifacts(self):
        self._log("Analyzing all digital artifacts...")
        bio_text = self.intel['bio']
        
        self.intel['emails_found'] = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', bio_text)
        links = re.findall(r'https?://[^\s/$.?#].[^\s]*', bio_text)
        self.intel['linked_domains'] = self._process_links(links) if links else []
        phone_numbers_found = re.findall(CONFIG['phone_regex'], bio_text)
        self.intel['phone_intel'] = self._process_phone_numbers(phone_numbers_found) if phone_numbers_found else []
        self.intel['exif_data'] = self._analyze_profile_picture_exif()
        self.intel['reverse_image_search_url'] = self._generate_reverse_image_search_link()
        self.intel['cross_platform_searches'] = self._generate_cross_platform_searches()
        
        content_string = self.intel['display_name'] + bio_text
        self.intel['fingerprints'] = { "md5": hashlib.md5(content_string.encode()).hexdigest(), "sha256": hashlib.sha256(content_string.encode()).hexdigest() }
        self._log("Artifact analysis complete.", "success")

    def _process_links(self, links: list) -> list:
        processed_links = []
        with Progress(console=console) as progress:
            task = progress.add_task("[cyan]Scanning domains w/ deep IP analysis...", total=len(links))
            for link in links:
                domain_intel = {"url": link, "domain": urlparse(link).netloc}
                try:
                    ip = socket.gethostbyname(domain_intel["domain"])
                    domain_intel["ip_address"] = ip
                    try:
                        ip_obj = IPWhois(ip); results = ip_obj.lookup_rdap(depth=1)
                        domain_intel.update({ "country": results.get("network", {}).get("country", "N/A"), "organization": results.get("network", {}).get("name", "N/A"), "asn": f"{results.get('asn', 'N/A')} - {results.get('asn_description', 'N/A')}" })
                    except (IPDefinedError, Exception): domain_intel.update({"country": "N/A", "organization": "N/A", "asn": "N/A"})
                except socket.gaierror: domain_intel.update({"ip_address": "Resolution Failed", "country": "N/A", "organization": "N/A", "asn": "N/A"})
                processed_links.append(domain_intel)
                progress.update(task, advance=1)
        return processed_links

    def _process_phone_numbers(self, numbers: list) -> list:
        processed_numbers = []
        with Progress(console=console) as progress:
            task = progress.add_task("[cyan]Analyzing phone numbers...", total=len(numbers))
            for num_str in numbers:
                try:
                    phone_obj = parse_phone(num_str, None)
                    if is_valid_number(phone_obj):
                        processed_numbers.append({"number_string": num_str, "location": geocoder.description_for_number(phone_obj, "en") or "N/A", "carrier": carrier.name_for_number(phone_obj, "en") or "N/A"})
                except Exception: continue
                progress.update(task, advance=1)
        return processed_numbers

    def _analyze_profile_picture_exif(self) -> dict:
        image_url = self.intel.get('profile_photo_url')
        if not image_url or image_url == "N/A": return {}
        self._log(f"Attempting forensic analysis on profile picture...", "warning")
        try:
            response = self.session.get(image_url, timeout=15, stream=True); response.raise_for_status()
            tags = exifread.process_file(io.BytesIO(response.content), details=False)
            exif_data = {tag: str(value) for tag, value in tags.items() if tag not in ('JPEGThumbnail', 'TIFFThumbnail')}
            if exif_data: self._log("Potentially significant EXIF data found!", "danger")
            return exif_data
        except Exception: return {}

    def _generate_reverse_image_search_link(self) -> str:
        image_url = self.intel.get('profile_photo_url')
        if not image_url or image_url == "N/A": return "N/A"
        return f"https://lens.google.com/uploadbyurl?url={quote_plus(image_url)}"

    # <<<--- FUNCIÓN RESTAURADA: BÚSQUEDA CRUZADA DEL USUARIO ---<<<
    def _generate_cross_platform_searches(self) -> dict:
        """Genera enlaces de búsqueda para encontrar el nombre de usuario en otras plataformas."""
        self._log("Generating cross-platform search links for username.", "info")
        encoded_user = quote_plus(self.username)
        return {
            "Google": f"https://www.google.com/search?q=%22{encoded_user}%22",
            "Twitter / X": f"https://twitter.com/search?q={encoded_user}",
            "GitHub": f"https://github.com/search?q={encoded_user}",
            "Facebook": f"https://www.facebook.com/search/top?q={encoded_user}",
            "LinkedIn": f"https://www.linkedin.com/search/results/all/?keywords={encoded_user}",
            "Documentos (PDF, DOCX)": f"https://www.google.com/search?q=filetype%3Apdf+OR+filetype%3Adocx+%22{encoded_user}%22",
        }

    def _generate_dossier(self):
        console.rule(f"[bold header]DOSSIER: @{self.username}", style="header")
        t_general = Table(box=None, show_header=False); t_general.add_row("[bold]Display Name:[/bold]", self.intel['display_name']); t_general.add_row("[bold]Bio:[/bold]", self.intel['bio']); t_general.add_row("[bold]Photo URL:[/bold]", f"[link={self.intel['profile_photo_url']}]{self.intel['profile_photo_url']}[/link]"); console.print(Panel(t_general, title="[subheader]Primary Intel", border_style="subheader", padding=1))
        t_artifacts = Table(box=None, show_header=False); t_artifacts.add_row("[bold]MD5 Fingerprint:[/bold]", self.intel['fingerprints']['md5']); t_artifacts.add_row("[bold]SHA256 Fingerprint:[/bold]", self.intel['fingerprints']['sha256']); t_artifacts.add_row("[bold]Emails found:[/bold]", str(self.intel['emails_found']) if self.intel['emails_found'] else "None"); console.print(Panel(t_artifacts, title="[subheader]Digital Fingerprints", border_style="subheader", padding=1))
        
        ris_url = self.intel.get('reverse_image_search_url', 'N/A'); ris_panel_content = f"[bold]Google Lens URL:[/bold] [link={ris_url}]Click to search this image across the web[/link]" if ris_url != 'N/A' else "[italic]No profile picture found.[/italic]"; console.print(Panel(ris_panel_content, title="[subheader]Reverse Image Search (Spectre)", border_style="subheader", padding=1))
        
        if self.intel['phone_intel']:
            t_phones = Table(header_style="bold info", show_lines=True); t_phones.add_column("Phone Number Found"); t_phones.add_column("Location"); t_phones.add_column("Carrier")
            for phone in self.intel['phone_intel']: t_phones.add_row(phone['number_string'], phone['location'], phone['carrier'])
            console.print(Panel(t_phones, title="[subheader]Phone Number Intelligence", border_style="subheader", padding=1))
        
        if self.intel['exif_data']:
            t_exif = Table(header_style="bold warning", show_lines=True); t_exif.add_column("EXIF Tag"); t_exif.add_column("Value")
            for tag, value in self.intel['exif_data'].items(): t_exif.add_row(tag, value)
            console.print(Panel(t_exif, title="[subheader]Image Forensic Analysis (EXIF)", border_style="danger", padding=1))
        
        if self.intel['linked_domains']:
            t_links = Table(header_style="bold info", show_lines=True); t_links.add_column("URL", max_width=30); t_links.add_column("Domain"); t_links.add_column("IP Address"); t_links.add_column("Country"); t_links.add_column("Organization", max_width=25); t_links.add_column("ASN")
            for domain in self.intel['linked_domains']: t_links.add_row(domain['url'], domain['domain'], domain['ip_address'], domain['country'], domain['organization'], domain['asn'])
            console.print(Panel(t_links, title="[subheader]Linked Domain & IP Intelligence", border_style="subheader", padding=1))

        # <<<--- NUEVO PANEL DE REPORTE: BÚSQUEDA CRUZADA ---<<<
        if self.intel['cross_platform_searches']:
            t_cross = Table(header_style="bold info", show_lines=True); t_cross.add_column("Platform"); t_cross.add_column("Search URL")
            for platform, url in self.intel['cross_platform_searches'].items(): t_cross.add_row(platform, f"[link={url}]{url}[/link]")
            console.print(Panel(t_cross, title="[subheader]Cross-Platform Search (OSINT Expansion)", border_style="subheader", padding=1))

        console.rule("[bold header]Reconnaissance Complete", style="header")

    def _save_dossier(self):
        if not self.output_file: return
        if not self.output_file.endswith(".json"): self.output_file += ".json"
        self._log(f"Exfiltrating data to [bold cyan]{self.output_file}[/bold cyan]...", "warning")
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(self.intel, f, indent=4, ensure_ascii=False)
            self._log("Data exfiltration successful.", "success")
        except IOError as e: self._log(f"Failed to write to file: {e}", "error")

    def run(self):
        if not self._make_request(): return
        self._extract_basic_intel()
        self._analyze_artifacts()
        self._generate_dossier()
        self._save_dossier()

def main():
    display_banner()
    parser = argparse.ArgumentParser(description="M4LVOK OSINT Tool V3.0 - All-In-One Edition", formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40))
    parser.add_argument("-u", "--username", required=True, help="Target Telegram username (without @)")
    parser.add_argument("-o", "--output", help="Save the full dossier to a JSON file")
    if len(sys.argv) == 1: parser.print_help(); sys.exit(1)
    args = parser.parse_args()
    try:
        recon_mission = TelegramRecon(username=args.username, output_file=args.output)
        recon_mission.run()
    except KeyboardInterrupt: console.print("\n[bold warning]Mission aborted by user. Exiting stealthily...[/bold warning]")
    except Exception as e: console.print(f"[bold error]A critical error occurred: {e}[/bold error]")

if __name__ == "__main__":
    main()