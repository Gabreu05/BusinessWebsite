# BusinessWebsite Offline Snapshot

## Quick start

1. Make sure your virtual environment (or global Python) can run the Flask app (`pip install -r requirements.txt` if needed).
2. From the project root run:

```
python export_static_site.py
```

3. After the script finishes, open `offline_site/index.html` (or any of the other generated files) directly in your browser via File Explorer.

## What the script does

- Requests the public-facing routes (`/`, `/listings`, `/gallery`, `/quote`, `/login`, `/register`) through Flask's test client.
- Rewrites asset paths so `file://` URLs can locate everything without `url_for`.
- Copies the entire `static/` directory into `offline_site/static` so images, CSS, and JS still load.

The offline HTML is read-only—forms, logins, and admin tools still require running the live Flask server. When you need an up-to-date snapshot, re-run the script to regenerate the files.

