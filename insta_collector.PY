#!/usr/bin/env python3
"""
Instagram Follower & Following Collector
For authorized penetration testing and security assessments only.
Collects followers/following lists from target Instagram profiles
and saves them as structured JSON files.
"""

import os
import sys
import json
import time
import argparse
import logging
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Dependencies: pip install instaloader
# ---------------------------------------------------------------------------

try:
    import instaloader
except ImportError:
    print("[!] Missing dependency. Install with: pip install instaloader")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_DELAY = 2.0          # Seconds between pagination requests (rate limiting)
MAX_RETRIES = 3              # Max retries on transient errors
SLEEP_ON_ERROR = 5.0         # Seconds to wait after an error

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("insta_collector")

# ---------------------------------------------------------------------------
# Core Collector
# ---------------------------------------------------------------------------


class InstagramCollector:
    """
    Collects followers / following lists for target Instagram profiles
    using an authenticated Instaloader session.
    """

    def __init__(
        self,
        username: str,
        password: str,
        delay: float = DEFAULT_DELAY,
        session_file: str = None,
        manual_checkpoint: bool = False,
        checkpoint_retries: int = 2,
    ):
        self.username = username
        self.password = password
        self.delay = delay
        self.session_file = session_file or f"session-{username}"
        self.manual_checkpoint = manual_checkpoint
        self.checkpoint_retries = max(2, checkpoint_retries)

        self.loader = instaloader.Instaloader(
            download_pictures=False,
            download_videos=False,
            download_video_thumbnails=False,
            compress_json=False,
            save_metadata=False,
            post_metadata_txt_pattern="",
            max_connection_attempts=3,
            request_timeout=30.0,
        )

        self._login()

    # -----------------------------------------------------------------------
    # Authentication
    # -----------------------------------------------------------------------

    @staticmethod
    def _is_checkpoint_error(exc) -> bool:
        """Return True when the exception looks like an Instagram checkpoint/challenge block."""
        message = str(exc).lower()
        return "checkpoint" in message or "challenge" in message or "follow the instructions" in message

    def _login(self):
        """Authenticate via saved session or username/password."""
        session_path = Path(self.session_file)

        if session_path.exists():
            try:
                self.loader.load_session_from_file(self.username, self.session_file)
                log.info("Loaded existing session from '%s'", self.session_file)
                # Verify session is still valid
                try:
                    self.loader.test_login()
                    log.info("Session is valid.")
                    return
                except Exception:
                    log.warning("Session expired, re-authenticating...")
            except Exception as e:
                log.warning("Could not load session: %s", e)

        # Fresh login
        for attempt in range(1, self.checkpoint_retries + 1):
            try:
                self.loader.login(self.username, self.password)
                self.loader.save_session_to_file(self.session_file)
                log.info("Login successful. Session saved to '%s'", self.session_file)
                return
            except instaloader.exceptions.BadCredentialsException:
                log.error("Login failed: invalid credentials.")
                sys.exit(1)
            except instaloader.exceptions.TwoFactorAuthRequiredException:
                log.error(
                    "Two-factor authentication required. "
                    "Disable 2FA or use a session file from a previous login."
                )
                sys.exit(1)
            except instaloader.exceptions.LoginException as exc:
                if self._is_checkpoint_error(exc):
                    if attempt < self.checkpoint_retries:
                        log.warning(
                            "Instagram requires manual verification. Retry %s/%s after completing it in a browser.",
                            attempt,
                            self.checkpoint_retries,
                        )
                        if self.manual_checkpoint:
                            try:
                                input("Complete the verification in your browser and press Enter to retry...")
                            except EOFError:
                                pass
                        continue

                    log.error("Instagram blocked login with a checkpoint/challenge requirement.")
                    log.error("Complete the verification in a browser, then create a session file and retry with --session.")
                    log.error("Example: python -m instaloader --login %s", self.username)
                    sys.exit(2)
                log.error("Login failed: %s", exc)
                sys.exit(1)
            except Exception as e:
                if self._is_checkpoint_error(e):
                    if attempt < self.checkpoint_retries:
                        log.warning(
                            "Instagram requires manual verification. Retry %s/%s after completing it in a browser.",
                            attempt,
                            self.checkpoint_retries,
                        )
                        if self.manual_checkpoint:
                            try:
                                input("Complete the verification in your browser and press Enter to retry...")
                            except EOFError:
                                pass
                        continue

                    log.error("Instagram blocked login with a checkpoint/challenge requirement.")
                    log.error("Complete the verification in a browser, then create a session file and retry with --session.")
                    log.error("Example: python -m instaloader --login %s", self.username)
                    sys.exit(2)
                log.error("Login failed: %s", e)
                sys.exit(1)

    # -----------------------------------------------------------------------
    # Profile Metadata
    # -----------------------------------------------------------------------

    def get_profile(self, target_username: str) -> instaloader.Profile:
        """Fetch Profile object for the target username."""
        try:
            profile = instaloader.Profile.from_username(
                self.loader.context, target_username
            )
            return profile
        except instaloader.exceptions.ProfileNotExistsException:
            log.error("Target profile '%s' does not exist.", target_username)
            sys.exit(1)
        except Exception as e:
            log.error("Failed to fetch profile '%s': %s", target_username, e)
            sys.exit(1)

    # -----------------------------------------------------------------------
    # Collect Followers
    # -----------------------------------------------------------------------

    def collect_followers(self, profile: instaloader.Profile) -> list:
        """
        Collect all followers for the given profile.
        Returns a list of dicts with follower metadata.
        """
        followers = []
        retries = 0

        log.info(
            "Collecting followers for '%s' (~%s total)...",
            profile.username,
            profile.followers,
        )

        try:
            iterator = profile.get_followers()
        except Exception as e:
            log.error("Cannot access followers list: %s", e)
            log.error(
                "Private profiles require the authenticated account "
                "to be a follower of the target."
            )
            return followers

        while True:
            try:
                for follower in iterator:
                    entry = self._user_to_dict(follower)
                    followers.append(entry)

                    if len(followers) % 50 == 0:
                        log.info("  Collected %s followers so far...", len(followers))

                break  # Iterator exhausted

            except instaloader.exceptions.QueryReturnedNotFoundException:
                log.warning("  Pagination cursor expired. Re-fetching iterator...")
                # Re-create iterator from current state
                iterator = profile.get_followers()
                continue

            except Exception as e:
                retries += 1
                if retries > MAX_RETRIES:
                    log.error("  Max retries reached. Collected %s followers.", len(followers))
                    break
                log.warning("  Error (attempt %s/%s): %s", retries, MAX_RETRIES, e)
                time.sleep(SLEEP_ON_ERROR)
                continue

            # Rate limiting between pages
            time.sleep(self.delay)

        log.info("Finished collecting followers: %s entries.", len(followers))
        return followers

    # -----------------------------------------------------------------------
    # Collect Following
    # -----------------------------------------------------------------------

    def collect_following(self, profile: instaloader.Profile) -> list:
        """
        Collect all accounts that the given profile is following (followees).
        Returns a list of dicts.
        """
        followees = []
        retries = 0

        log.info(
            "Collecting followees for '%s' (~%s total)...",
            profile.username,
            profile.followees,
        )

        try:
            iterator = profile.get_followees()
        except Exception as e:
            log.error("Cannot access following list: %s", e)
            return followees

        while True:
            try:
                for followee in iterator:
                    entry = self._user_to_dict(followee)
                    followees.append(entry)

                    if len(followees) % 50 == 0:
                        log.info("  Collected %s followees so far...", len(followees))

                break

            except instaloader.exceptions.QueryReturnedNotFoundException:
                log.warning("  Pagination cursor expired. Re-fetching iterator...")
                iterator = profile.get_followees()
                continue

            except Exception as e:
                retries += 1
                if retries > MAX_RETRIES:
                    log.error("  Max retries reached. Collected %s followees.", len(followees))
                    break
                log.warning("  Error (attempt %s/%s): %s", retries, MAX_RETRIES, e)
                time.sleep(SLEEP_ON_ERROR)
                continue

            time.sleep(self.delay)

        log.info("Finished collecting followees: %s entries.", len(followees))
        return followees

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _user_to_dict(user: instaloader.Profile) -> dict:
        """Convert an Instaloader Profile object to a serializable dict."""
        return {
            "user_id": user.userid,
            "username": user.username,
            "full_name": user.full_name,
            "is_private": user.is_private,
            "is_verified": user.is_verified,
            "is_business": user.is_business_account,
            "profile_pic_url": user.profile_pic_url,
            "biography": user.biography,
            "external_url": user.external_url,
            "follower_count": user.followers,
            "following_count": user.followees,
            "post_count": user.mediacount,
            "collected_at": datetime.utcnow().isoformat() + "Z",
        }

    @staticmethod
    def _profile_summary(profile: instaloader.Profile) -> dict:
        """Return a summary dict for the target profile itself."""
        return {
            "target_username": profile.username,
            "target_user_id": profile.userid,
            "target_full_name": profile.full_name,
            "target_is_private": profile.is_private,
            "target_is_verified": profile.is_verified,
            "target_is_business": profile.is_business_account,
            "target_biography": profile.biography,
            "target_external_url": profile.external_url,
            "target_follower_count": profile.followers,
            "target_following_count": profile.followees,
            "target_post_count": profile.mediacount,
            "target_profile_pic_url": profile.profile_pic_url,
            "scan_date": datetime.utcnow().isoformat() + "Z",
        }

    # -----------------------------------------------------------------------
    # Save Results
    # -----------------------------------------------------------------------

    @staticmethod
    def save_json(data: dict, filepath: str):
        """Write data to a pretty-printed JSON file."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        log.info("Saved: %s (%s bytes)", filepath, path.stat().st_size)

    # -----------------------------------------------------------------------
    # Full Scan
    # -----------------------------------------------------------------------

    def scan(
        self,
        target_username: str,
        output_dir: str = "instagram_scans",
        collect_followers_flag: bool = True,
        collect_following_flag: bool = True,
    ) -> dict:
        """
        Execute a full scan on the target profile.
        Returns the complete result dict and saves JSON files.
        """
        log.info("=" * 60)
        log.info("Scanning target: %s", target_username)
        log.info("Authenticated as: %s", self.username)
        log.info("=" * 60)

        profile = self.get_profile(target_username)

        scan_data = {"metadata": self._profile_summary(profile)}

        # Collect followers
        if collect_followers_flag:
            log.info("\n--- Followers ---")
            followers = self.collect_followers(profile)
            scan_data["followers"] = followers
            scan_data["metadata"]["followers_collected"] = len(followers)
        else:
            scan_data["followers"] = []
            scan_data["metadata"]["followers_collected"] = 0

        # Collect following
        if collect_following_flag:
            log.info("\n--- Following ---")
            following = self.collect_following(profile)
            scan_data["following"] = following
            scan_data["metadata"]["following_collected"] = len(following)
        else:
            scan_data["following"] = []
            scan_data["metadata"]["following_collected"] = 0

        # Add analysis
        scan_data["analysis"] = self._analyze(scan_data)

        # Save
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        basename = f"{target_username}_{timestamp}"
        output_path = Path(output_dir) / f"{basename}.json"
        self.save_json(scan_data, str(output_path))

        log.info("\n" + "=" * 60)
        log.info("Scan complete for '%s'", target_username)
        log.info("  Followers collected: %s", scan_data["metadata"]["followers_collected"])
        log.info("  Following collected: %s", scan_data["metadata"]["following_collected"])
        log.info("  Results saved to: %s", output_path)
        log.info("=" * 60)

        return scan_data

    # -----------------------------------------------------------------------
    # Basic Analysis
    # -----------------------------------------------------------------------

    @staticmethod
    def _analyze(data: dict) -> dict:
        """Generate basic analysis from collected data."""
        followers = data.get("followers", [])
        following = data.get("following", [])

        follower_usernames = {u["username"] for u in followers}
        following_usernames = {u["username"] for u in following}

        not_following_back = list(following_usernames - follower_usernames)
        not_followed_back = list(follower_usernames - following_usernames)
        mutual = list(follower_usernames & following_usernames)

        private_in_followers = [u for u in followers if u["is_private"]]
        private_in_following = [u for u in following if u["is_private"]]
        verified_in_followers = [u for u in followers if u["is_verified"]]
        verified_in_following = [u for u in following if u["is_verified"]]

        return {
            "total_followers": len(followers),
            "total_following": len(following),
            "mutual_count": len(mutual),
            "mutual_usernames": sorted(mutual),
            "not_following_back_count": len(not_following_back),
            "not_following_back_usernames": sorted(not_following_back),
            "not_followed_back_count": len(not_followed_back),
            "not_followed_back_usernames": sorted(not_followed_back),
            "private_in_followers_count": len(private_in_followers),
            "private_in_followers_usernames": [u["username"] for u in private_in_followers],
            "private_in_following_count": len(private_in_following),
            "private_in_following_usernames": [u["username"] for u in private_in_following],
            "verified_in_followers_count": len(verified_in_followers),
            "verified_in_following_count": len(verified_in_following),
            "high_value_targets": sorted(
                [u["username"] for u in following if u["is_verified"] or u["follower_count"] > 10000]
            ),
        }


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Instagram Follower & Following Collector (Authorized Pentesting Only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python insta_collector.py -u YOUR_USER -p YOUR_PASS -t target_user\n"
            "  python insta_collector.py -u YOUR_USER -p YOUR_PASS -t target_user --output /path/to/dir\n"
            "  python insta_collector.py -u YOUR_USER -p YOUR_PASS -t target_user --followers-only\n"
            "  python insta_collector.py -u YOUR_USER -p YOUR_PASS -t target_user --following-only --delay 3.0\n"
        ),
    )

    parser.add_argument(
        "-u",
        "--username",
        default=os.getenv("INSTA_USERNAME"),
        help="Your Instagram username (authenticated account). Falls back to INSTA_USERNAME.",
    )
    parser.add_argument(
        "-p",
        "--password",
        default=os.getenv("INSTA_PASSWORD"),
        help="Your Instagram password. Falls back to INSTA_PASSWORD.",
    )
    parser.add_argument("-t", "--target", required=True, help="Target Instagram username to scan")
    parser.add_argument("-o", "--output", default="instagram_scans", help="Output directory (default: instagram_scans)")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help=f"Delay between requests in seconds (default: {DEFAULT_DELAY})")
    parser.add_argument("--session", default=None, help="Session file path (default: session-USERNAME)")
    parser.add_argument("--followers-only", action="store_true", help="Only collect followers list")
    parser.add_argument("--following-only", action="store_true", help="Only collect following list")
    parser.add_argument(
        "--manual-checkpoint",
        action="store_true",
        help="Pause and wait for you to complete Instagram's browser verification before retrying.",
    )
    parser.add_argument(
        "--checkpoint-retries",
        type=int,
        default=2,
        help="Number of retry attempts after a checkpoint/challenge error (default: 2).",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")

    args = parser.parse_args()

    if not args.username:
        parser.error("Instagram username is required. Provide -u/--username or set INSTA_USERNAME.")
    if not args.password:
        parser.error("Instagram password is required. Provide -p/--password or set INSTA_PASSWORD.")

    if args.quiet:
        log.setLevel(logging.WARNING)

    collector = InstagramCollector(
        username=args.username,
        password=args.password,
        delay=args.delay,
        session_file=args.session,
        manual_checkpoint=args.manual_checkpoint,
        checkpoint_retries=args.checkpoint_retries,
    )

    collector.scan(
        target_username=args.target,
        output_dir=args.output,
        collect_followers_flag=not args.following_only,
        collect_following_flag=not args.followers_only,
    )


if __name__ == "__main__":
    main()