# Insta Scanner

A small Python utility that uses Instaloader to collect follower and following data for an Instagram target profile into JSON output files.

## Purpose

This script is intended for authorized security research and account analysis tasks only. Use it responsibly and only on accounts you are authorized to inspect.

## Requirements

- Python 3.9+
- Instaloader

Install dependencies:

```bash
pip install instaloader
```

## Usage

```bash
python insta_collector.PY -u YOUR_USERNAME -p YOUR_PASSWORD -t TARGET_USERNAME
```

You can also supply the credentials via environment variables:

```bash
set INSTA_USERNAME=your_username
set INSTA_PASSWORD=your_password
python insta_collector.PY -t target_username
```

## Notes

Instagram may require a login checkpoint or browser verification before authentication succeeds. If the script exits with a checkpoint error, complete the verification in a browser and retry using a saved session file.

## Output

Results are written into the `instagram_scans` directory by default as timestamped JSON files.
