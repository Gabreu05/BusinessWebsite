import os
import shutil
from typing import Dict, List, Tuple

from app import app

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, 'offline_site')
STATIC_SRC = os.path.join(BASE_DIR, 'static')

# Public-facing routes we can safely snapshot without authentication.
ROUTE_EXPORTS: List[Tuple[str, str]] = [
    ('/', 'index.html'),
    ('/listings', 'listings.html'),
    ('/gallery', 'gallery.html'),
    ('/quote', 'quote.html'),
    ('/login', 'login.html'),
    ('/register', 'register.html'),
]

# Map route paths to their offline filenames for rewriting links.
ROUTE_MAP: Dict[str, str] = {route.rstrip('/') or '/': filename for route, filename in ROUTE_EXPORTS}
ROUTE_MAP['/'] = 'index.html'


def ensure_output_dir() -> None:
    """Recreate the offline output directory."""
    shutil.rmtree(OUTPUT_DIR, ignore_errors=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def copy_static_assets() -> None:
    """Copy the entire static directory so relative links work offline."""
    destination = os.path.join(OUTPUT_DIR, 'static')
    shutil.copytree(STATIC_SRC, destination, dirs_exist_ok=True)


def rewrite_static_urls(html: str) -> str:
    """Convert /static references to relative static/ for file:// usage."""
    replacements = [
        ('href="/static/', 'href="static/'),
        ("href='/static/", "href='static/"),
        ('src="/static/', 'src="static/'),
        ("src='/static/", "src='static/"),
        ('url(/static/', 'url(static/'),
    ]
    for needle, replacement in replacements:
        html = html.replace(needle, replacement)
    return html


def rewrite_route_links(html: str) -> str:
    """Update href/action attributes to point at the exported html files."""
    for route, filename in ROUTE_MAP.items():
        for attribute in ('href', 'action'):
            for quote in ('"', "'"):
                target = f'{attribute}={quote}{route}{quote}'
                replacement = f'{attribute}={quote}{filename}{quote}'
                html = html.replace(target, replacement)
    return html


def export_route(path: str, filename: str) -> None:
    """Request a route, rewrite its HTML, and write it to disk."""
    with app.test_client() as client:
        response = client.get(path)
        if response.status_code != 200:
            print(f'Skipping {path}: HTTP {response.status_code}')
            return
        html = response.get_data(as_text=True)
    html = rewrite_static_urls(html)
    html = rewrite_route_links(html)
    target_path = os.path.join(OUTPUT_DIR, filename)
    with open(target_path, 'w', encoding='utf-8') as fh:
        fh.write(html)
    print(f'Exported {path} -> offline_site/{filename}')


def run_export() -> None:
    ensure_output_dir()
    copy_static_assets()
    for route, filename in ROUTE_EXPORTS:
        export_route(route, filename)
    print('Offline snapshot ready in offline_site/.')


if __name__ == '__main__':
    run_export()

