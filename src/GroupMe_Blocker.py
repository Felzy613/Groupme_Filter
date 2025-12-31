import os
import json
import time
import threading
import base64
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional, Set

import requests
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

try:
    from cryptography.fernet import Fernet  # type: ignore
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    # Fallback: dummy Fernet class with proper method signatures
    class Fernet:  # type: ignore
        @staticmethod
        def generate_key() -> bytes:
            return b""
        
        def __init__(self, key: bytes) -> None:
            pass
        
        def encrypt(self, data: bytes) -> bytes:
            return data
        
        def decrypt(self, data: bytes) -> bytes:
            return data

# Application name and version
APP_NAME = "GroupMeBlocker"
APP_VERSION = "2025-11-29-clear-log"
# macOS Application Support directory for your app
APP_SUPPORT_DIR = os.path.expanduser(f"~/Library/Application Support/{APP_NAME}")
os.makedirs(APP_SUPPORT_DIR, exist_ok=True)

# Path where we store the JSON config file
CONFIG_FILE = os.path.join(APP_SUPPORT_DIR, "accounts_config.json")
ENCRYPTION_KEY_FILE = os.path.join(APP_SUPPORT_DIR, "encryption.key")

POLL_INTERVAL_SECONDS = 6  # how often to check groups
PROFILE_CACHE_SECONDS = 120  # how often to refresh /users/me (2 minutes)


# ------------- Encryption Utilities (Optional Security) -------------

def _get_or_create_encryption_key() -> Optional[bytes]:
    """Get or create an encryption key for token storage."""
    if not ENCRYPTION_AVAILABLE:
        return None
    
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, "rb") as f:
            return f.read()
    
    # Create a new key
    key = Fernet.generate_key()
    # Set restrictive permissions (owner read/write only)
    old_umask = os.umask(0o077)
    try:
        with open(ENCRYPTION_KEY_FILE, "wb") as f:
            f.write(key)
    finally:
        os.umask(old_umask)
    
    return key


def encrypt_token(token: str) -> str:
    """Encrypt a token using the stored key."""
    if not ENCRYPTION_AVAILABLE:
        return token  # Return plaintext if encryption not available
    
    key = _get_or_create_encryption_key()
    if not key:
        return token
    
    cipher = Fernet(key)
    encrypted = cipher.encrypt(token.encode())
    return encrypted.decode()


def decrypt_token(encrypted_token: str) -> str:
    """Decrypt a token using the stored key."""
    if not ENCRYPTION_AVAILABLE:
        return encrypted_token  # Return as-is if encryption not available
    
    key = _get_or_create_encryption_key()
    if not key:
        return encrypted_token
    
    try:
        cipher = Fernet(key)
        decrypted = cipher.decrypt(encrypted_token.encode())
        return decrypted.decode()
    except Exception:
        # If decryption fails, return the original (might be plaintext from old version)
        return encrypted_token


# ------------- Data Model -------------


class AccountConfig:
    def __init__(self, label: str, token: str, blocked_group_ids: List[str], mode: str = "blacklist"):
        self.label = label
        # Decrypt token if it's encrypted, otherwise store as-is
        self.token = decrypt_token(token) if token else ""
        self.blocked_group_ids = blocked_group_ids
        # mode can be "blacklist" or "whitelist"
        self.mode = mode or "blacklist"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "token": encrypt_token(self.token),  # Encrypt token before saving
            "blocked_group_ids": self.blocked_group_ids,
            "mode": self.mode,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "AccountConfig":
        return AccountConfig(
            label=d.get("label", "account"),
            token=d.get("token", ""),  # Will be decrypted in __init__
            blocked_group_ids=d.get("blocked_group_ids", []),
            mode=d.get("mode", "blacklist"),
        )


def load_config() -> Tuple[List[AccountConfig], List[str]]:
    """Load accounts + global blocklist.

    Supports:
    - Old format: [ {account}, {account}, ... ]
    - New format: { "global_blocked_group_ids": [...], "accounts": [ ... ] }
    """
    if not os.path.exists(CONFIG_FILE):
        return [], []

    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
    except Exception:
        return [], []

    accounts: List[AccountConfig] = []
    global_blocked: List[str] = []

    if isinstance(data, list):
        # Old format: just a list of accounts
        accounts = [AccountConfig.from_dict(a) for a in data]
        global_blocked = []
    elif isinstance(data, dict):
        global_blocked = data.get("global_blocked_group_ids", []) or []
        acc_data = data.get("accounts", []) or []
        accounts = [AccountConfig.from_dict(a) for a in acc_data]

    return accounts, global_blocked


def save_config(accounts: List[AccountConfig], global_blocked: List[str]) -> None:
    data = {
        "global_blocked_group_ids": global_blocked,
        "accounts": [a.to_dict() for a in accounts],
    }
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, CONFIG_FILE)


# ------------- GroupMe Logic -------------

def extract_group_id(entry: str) -> str:
    """Given a stored blocked-group entry like 'ID' or 'ID | Name', return the raw ID part."""
    if not isinstance(entry, str):
        entry = str(entry)
    return entry.split("|", 1)[0].strip()


class GroupMeAccount:
    def __init__(
        self,
        label: str,
        token: str,
        per_account_blocked_ids: List[str],
        global_blocked_ids: List[str],
        log_fn,
        mode: str = "blacklist",
    ):
        self.label = label
        self.token = token.strip()
        self.per_account_blocked_ids = per_account_blocked_ids or []
        self.global_blocked_ids = global_blocked_ids or []
        self.headers = {"X-Access-Token": self.token}
        self.profile: Optional[Dict[str, Any]] = None
        self.user_id: Optional[str] = None
        self.last_profile_update: float = 0.0
        self.log = log_fn
        # "blacklist" (block listed groups) or "whitelist" (allow only listed groups)
        self.mode = mode or "blacklist"
        # Track known groups so we can detect when user joins new chats
        self.known_groups: Set[str] = set()
        self.has_seen_groups: bool = False

    # --- API helpers ---

    def get_profile(self) -> Dict[str, Any]:
        """Return cached profile, refreshing /users/me at most every PROFILE_CACHE_SECONDS."""
        now = time.time()
        if self.profile is not None and (now - self.last_profile_update) < PROFILE_CACHE_SECONDS:
            return self.profile

        if not self.token:
            raise RuntimeError(f"[{self.label}] No token set for account")

        r = requests.get(
            "https://api.groupme.com/v3/users/me",
            headers=self.headers,
            params={"token": self.token},
        )
        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            # If rate-limited, keep old profile if we have one
            if r.status_code == 429 and self.profile is not None:
                self.log(f"[{self.label}] WARN: Rate limited on /users/me, using cached profile.")
                return self.profile
            raise e

        self.profile = r.json()["response"]
        if self.profile is not None:
            self.user_id = self.profile.get("id")
        self.last_profile_update = now
        return self.profile if self.profile is not None else {}

    def get_groups(self) -> List[Dict[str, Any]]:
        groups: List[Dict[str, Any]] = []
        page = 1
        while True:
            r = requests.get(
                "https://api.groupme.com/v3/groups",
                headers=self.headers,
                params={
                    "token": self.token,
                    "per_page": 100,
                    "page": page,
                    "omit": "memberships",
                },
            )
            r.raise_for_status()
            resp = r.json()["response"]
            if not resp:
                break
            groups.extend(resp)
            page += 1
        return groups

    def _get_membership_id_for_self(self, group_id: str) -> Optional[str]:
        """Fetch the group and find THIS account's membership_id in the members list.

        Per GroupMe docs:
        POST /groups/:group_id/members/:membership_id/remove
        membership_id is the `id` field in the `members` array, not `user_id`.
        """
        if not self.user_id:
            self.get_profile()

        try:
            r = requests.get(
                f"https://api.groupme.com/v3/groups/{group_id}",
                headers=self.headers,
                params={"token": self.token},
            )
            r.raise_for_status()
            g = r.json().get("response") or {}
        except Exception as e:
            self.log(f"[{self.label}] ERROR fetching group {group_id}: {e}")
            return None

        members = g.get("members") or []

        for m in members:
            # Compare user_id as strings to be safe
            if str(m.get("user_id")) == str(self.user_id):
                # This is the membership_id we need
                return m.get("id")

        # If we got here, there is no membership entry for this user.
        return None

    def remove_self_from_group(self, group_id: str, name: Optional[str] = None) -> bool:
        """Remove THIS account from a group using the official membership remove endpoint.

        POST /groups/:group_id/members/:membership_id/remove

        If there is no membership entry, we treat it as "already removed".
        """
        if not self.token:
            return False

        membership_id = self._get_membership_id_for_self(group_id)

        # If there is no membership entry, try forced cleanup before treating as removed.
        if not membership_id:
            self.log(
                f"[{self.label}] INFO: No membership entry found for {name or group_id}; attempting forced cleanup...",
                level="debug",
            )

            # --- NEW: Rename self in the group to force server update ---
            import random
            import string

            random_name = "".join(random.choice(string.ascii_letters) for _ in range(12))

            try:
                requests.post(
                    f"https://api.groupme.com/v3/groups/{group_id}/memberships/update",
                    headers=self.headers,
                    params={"token": self.token},
                    json={"membership": {"nickname": random_name}},
                )
                self.log(
                    f"[{self.label}] INFO: Attempted nickname update to '{random_name}' for forced sync.",
                    level="debug",
                )
            except Exception as e:
                self.log(f"[{self.label}] WARN: Failed to update nickname: {e}", level="debug")

            # --- NEW: Retry to fetch membership ID after nickname update ---
            time.sleep(2)
            membership_id = self._get_membership_id_for_self(group_id)

            if not membership_id:
                self.log(
                    f"[{self.label}] INFO: Still no membership entry after forced cleanup; treating as already removed.",
                    level="debug",
                )
                return True

        url = (
            f"https://api.groupme.com/v3/groups/{group_id}/"
            f"members/{membership_id}/remove"
        )

        try:
            res = requests.post(
                url,
                headers=self.headers,
                params={"token": self.token},
            )
        except Exception as e:
            self.log(
                f"[{self.label}] ERROR: Exception while removing from "
                f"{name or group_id}: {e}",
                level="user",
            )
            return False

        if res.status_code == 200:
            self.log(
                f"[{self.label}] OK: Removed self from {name or group_id}",
                level="user",
            )
            return True
        else:
            self.log(
                f"[{self.label}] ERROR: Failed to remove self from "
                f"{name or group_id} (status={res.status_code}) {res.text}",
                level="user",
            )
            return False

    # --- Core check ---

    def enforce_blocklist_once(self):
        """Check all groups for this account and remove self from any blocked ones.

        Modes:
        - blacklist (default): per-account + global IDs are treated as a blocklist.
        - whitelist: per-account IDs are treated as an allow-list; any other group
          (except those also in the allow-list) is considered blocked. Global IDs
          are always treated as a blocklist override.
        """
        if not self.token:
            return

        global_ids = {extract_group_id(v) for v in self.global_blocked_ids}
        account_ids = {extract_group_id(v) for v in self.per_account_blocked_ids}
        whitelist_mode = (self.mode == "whitelist")

        # If blacklist mode and there are no IDs to check, nothing to enforce
        if not whitelist_mode and not global_ids and not account_ids:
            return

        try:
            profile = self.get_profile()
            name = profile.get("name")
            uid = profile.get("id")
            self.log(f"[{self.label}] Checking as {name} (user_id={uid})")
        except Exception as e:
            self.log(f"[{self.label}] ERROR fetching profile: {e}")
            return

        try:
            groups = self.get_groups()
        except Exception as e:
            self.log(f"[{self.label}] ERROR fetching groups: {e}")
            return

        # Detect newly joined groups and log a notification
        current_ids = {g["id"] for g in groups}
        if not self.has_seen_groups:
            # First run: just record state, don't spam notifications
            self.known_groups = current_ids
            self.has_seen_groups = True
        else:
            new_ids = current_ids - self.known_groups
            if new_ids:
                for g in groups:
                    gid = g["id"]
                    if gid in new_ids:
                        gname = g.get("name")
                        self.log(
                            f"[{self.label}] NEW GROUP: joined {gname!r} (id={gid}).",
                            level="user",
                        )
            self.known_groups = current_ids

        self.log(f"[{self.label}] Currently in {len(groups)} groups.")

        for g in groups:
            gid = g["id"]
            gname = g.get("name")

            blocked = False
            source = []

            # Global blocklist always applies
            if gid in global_ids:
                blocked = True
                source.append("GLOBAL")

            if whitelist_mode:
                if gid not in account_ids:
                    blocked = True
                    source.append("WHITELIST")
            else:
                # blacklist mode: per-account IDs are just additional blocked groups
                if gid in account_ids:
                    blocked = True
                    source.append("ACCOUNT")

            if not blocked:
                continue

            source_str = "/".join(source) or "BLOCKED"

            self.log(
                f"[{self.label}] {source_str}: In blocked group {gname!r} (id={gid}). "
                f"Removing self via membership endpoint...",
                level="user",
            )

            # Retry a few times in case GroupMe is flaky
            success = False
            for _ in range(3):
                if self.remove_self_from_group(gid, gname):
                    success = True
                    break
                time.sleep(2)

            if not success:
                self.log(
                    f"[{self.label}] WARN: Could not remove self from "
                    f"{gname!r} (id={gid}) after retries.",
                    level="user",
                )

    def list_groups_text(self) -> str:
        """Return a text representation of groups for GUI display."""
        try:
            profile = self.get_profile()
            name = profile.get("name")
        except Exception as e:
            return f"[{self.label}] ERROR fetching profile: {e}"

        try:
            groups = self.get_groups()
        except Exception as e:
            return f"[{self.label}] ERROR fetching groups: {e}"

        lines = [f"Account: {self.label} ({name})", ""]
        if not groups:
            lines.append("No groups found.")
            return "\n".join(lines)

        for g in groups:
            gname = g.get("name")
            gid = g["id"]
            lines.append(f"Name: {gname!r}")
            lines.append(f"  ID: {gid}")
            lines.append("-" * 40)
        return "\n".join(lines)


# ------------- GUI -------------


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"GroupMe Multi-Account Blocker — v{APP_VERSION}")

        self.accounts: List[AccountConfig]
        self.global_blocked_ids: List[str]
        self.accounts, self.global_blocked_ids = load_config()
        self.current_index: Optional[int] = None

        self.is_running = False
        self.worker_thread: Optional[threading.Thread] = None

        # Keep persistent GroupMeAccount objects so /users/me is cached
        self.gm_accounts: Dict[str, GroupMeAccount] = {}
        self.log_history: List[Tuple[str, str]] = []
        self.log_mode_var = tk.StringVar(value="debug")
        self.whitelist_var = tk.BooleanVar(value=False)

        self.colors = {
            "bg": "#f5f7fb",          # soft light background
            "card_bg": "#ffffff",     # white cards
            "accent": "#4f46e5",      # indigo accent
            "accent_dark": "#3730a3", # darker indigo
            "text_primary": "#111827",
            "text_muted": "#6b7280",
            "border": "#e5e7eb",
            "shadow": "#cbd5f5",
        }

        self.configure_styles()
        self.build_ui()
        # Keyboard shortcuts for clearing logs
        self.root.bind_all("<Command-Shift-L>", lambda _e: self.clear_logs())
        self.root.bind_all("<Control-Shift-L>", lambda _e: self.clear_logs())
        self.refresh_account_list()
        self.refresh_global_blocklist_ui()

    def configure_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        # Base window styling
        self.root.configure(background=self.colors["bg"])
        self.root.minsize(900, 600)

        default_font = ("Helvetica", 11)
        heading_font = ("Helvetica", 18, "bold")

        style.configure(
            "TLabel",
            background=self.colors["bg"],
            foreground=self.colors["text_primary"],
            font=default_font,
        )
        style.configure(
            "Heading.TLabel",
            background=self.colors["bg"],
            foreground=self.colors["text_primary"],
            font=heading_font,
        )
        style.configure(
            "Muted.TLabel",
            background=self.colors["bg"],
            foreground=self.colors["text_muted"],
            font=default_font,
        )
        # Containers
        style.configure("TFrame", background=self.colors["bg"])
        style.configure("TLabelframe", background=self.colors["bg"])
        style.configure(
            "TLabelframe.Label",
            background=self.colors["bg"],
            foreground=self.colors["text_primary"],
            font=default_font,
        )
        # Card-style frame for main tab content
        style.configure(
            "Card.TFrame",
            background=self.colors["card_bg"],
            borderwidth=1,
            relief="solid",
        )
        # Notebook / tabs
        style.configure("TNotebook", background=self.colors["bg"])
        style.configure(
            "TNotebook.Tab",
            padding=(14, 8),
            font=default_font,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.colors["card_bg"]), ("!selected", self.colors["bg"])],
            foreground=[("selected", self.colors["text_primary"]), ("!selected", self.colors["text_muted"])],
        )
        style.configure(
            "TButton",
            padding=8,
            font=default_font,
        )
        style.configure(
            "Accent.TButton",
            padding=8,
            font=default_font,
            background=self.colors["accent"],
            foreground="#ffffff",
        )
        style.map(
            "Accent.TButton",
            background=[("active", self.colors["accent_dark"])],
        )

    def build_ui(self):
        # Window size
        self.root.geometry("1000x650")

        main = ttk.Frame(self.root, padding=12)
        main.pack(fill=tk.BOTH, expand=True)

        # Header
        header = ttk.Frame(main)
        header.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(
            header,
            text="GroupMe Blocker",
            style="Heading.TLabel",
        ).pack(anchor="w")

        ttk.Label(
            header,
            text="Monitor multiple accounts and keep unwanted chats out of sight.",
            style="Muted.TLabel",
        ).pack(anchor="w")

        # Notebook for main sections
        notebook = ttk.Notebook(main)
        notebook.pack(fill=tk.BOTH, expand=True)

        accounts_tab = ttk.Frame(notebook, style="Card.TFrame", padding=12)
        blocklists_tab = ttk.Frame(notebook, style="Card.TFrame", padding=12)
        activity_tab = ttk.Frame(notebook, style="Card.TFrame", padding=12)

        notebook.add(accounts_tab, text="Accounts")
        notebook.add(blocklists_tab, text="Blocklists")
        notebook.add(activity_tab, text="Activity Log")

        # --- Accounts tab ---

        accounts_tab.columnconfigure(0, weight=1)
        accounts_tab.columnconfigure(1, weight=2)
        accounts_tab.rowconfigure(0, weight=1)

        # Left: account list
        left = ttk.Frame(accounts_tab, padding=(0, 0, 10, 0))
        left.grid(row=0, column=0, sticky="nsew")

        ttk.Label(left, text="Accounts", font=("Helvetica", 12, "bold")).pack(anchor="w")

        list_frame = ttk.Frame(left)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(6, 6))

        self.account_listbox = tk.Listbox(
            list_frame,
            activestyle="none",
            font=("Helvetica", 12),
            bg=self.colors["card_bg"],
            fg=self.colors["text_primary"],
            selectbackground=self.colors["accent"],
            selectforeground="#ffffff",
        )
        self.account_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        account_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.account_listbox.yview)
        account_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.account_listbox.config(yscrollcommand=account_scroll.set)
        self.account_listbox.bind("<<ListboxSelect>>", self.on_account_select)

        btn_row = ttk.Frame(left)
        btn_row.pack(fill=tk.X)

        ttk.Button(btn_row, text="Add", command=self.add_account).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        ttk.Button(btn_row, text="Remove", command=self.remove_account).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 0))

        # Right: account details
        right = ttk.Frame(accounts_tab)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(1, weight=1)

        # Label
        ttk.Label(right, text="Account Label:", font=("Helvetica", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.label_entry = ttk.Entry(right, font=("Helvetica", 12))
        self.label_entry.grid(row=0, column=1, sticky="ew", pady=(0, 6))

        # Token
        ttk.Label(right, text="Access Token:", font=("Helvetica", 12, "bold")).grid(row=1, column=0, sticky="w", pady=(0, 6))
        token_frame = ttk.Frame(right)
        token_frame.grid(row=1, column=1, sticky="ew", pady=(0, 6))
        token_frame.columnconfigure(0, weight=1)
        self.token_entry = ttk.Entry(token_frame, show="*", font=("Helvetica", 12))
        self.token_entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(token_frame, text="Show", command=self.toggle_token_visibility).grid(row=0, column=1, padx=(6, 0))

        # Mode
        mode_frame = ttk.Frame(right)
        mode_frame.grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 8))
        ttk.Label(mode_frame, text="Mode:", font=("Helvetica", 12, "bold")).pack(side=tk.LEFT)
        ttk.Checkbutton(
            mode_frame,
            text="Whitelist mode (leave unchecked for blacklist)",
            variable=self.whitelist_var,
        ).pack(side=tk.LEFT, padx=(8, 0))

        # Run controls
        run_frame = ttk.Frame(right)
        run_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        run_frame.columnconfigure(0, weight=1)
        run_frame.columnconfigure(1, weight=1)
        run_frame.columnconfigure(2, weight=1)

        self.run_button = ttk.Button(run_frame, text="Start Watching", command=self.toggle_running)
        self.run_button.grid(row=0, column=0, sticky="ew", padx=(0, 4))

        ttk.Button(run_frame, text="Show My Groups", command=self.show_groups_for_account).grid(
            row=0, column=1, sticky="ew", padx=4
        )
        ttk.Button(run_frame, text="Save Account", command=self.save_current_account).grid(
            row=0, column=2, sticky="ew", padx=(4, 0)
        )

        ttk.Label(
            right,
            text=f"Background checks run every {POLL_INTERVAL_SECONDS} seconds while watching is enabled.",
            style="Muted.TLabel",
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(4, 0))

        # Spacer row so details don't stretch awkwardly
        right.rowconfigure(5, weight=1)

        # --- Blocklists tab ---

        blocklists_tab.columnconfigure(0, weight=1)
        blocklists_tab.rowconfigure(0, weight=1)
        blocklists_tab.rowconfigure(1, weight=1)

        # Per-account blocklist
        per_frame = ttk.LabelFrame(blocklists_tab, text="Blocked Group IDs (Selected Account)")
        per_frame.grid(row=0, column=0, sticky="nsew", padx=4, pady=(4, 8))
        per_frame.columnconfigure(0, weight=1)
        per_frame.rowconfigure(0, weight=1)

        per_list_container = ttk.Frame(per_frame)
        per_list_container.grid(row=0, column=0, sticky="nsew", pady=(4, 4))

        self.blocked_listbox = tk.Listbox(
            per_list_container,
            activestyle="none",
            font=("Helvetica", 11),
            bg=self.colors["card_bg"],
            fg=self.colors["text_primary"],
            selectbackground=self.colors["accent"],
            selectforeground="#ffffff",
        )
        self.blocked_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        per_scroll = ttk.Scrollbar(per_list_container, orient=tk.VERTICAL, command=self.blocked_listbox.yview)
        per_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.blocked_listbox.config(yscrollcommand=per_scroll.set)
        self.blocked_listbox.bind("<Double-Button-1>", self.edit_blocked_id)

        per_btns = ttk.Frame(per_frame)
        per_btns.grid(row=1, column=0, sticky="ew", pady=(2, 4))
        ttk.Button(per_btns, text="Add", command=self.add_blocked_id).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 4))
        ttk.Button(per_btns, text="Edit", command=self.edit_blocked_id).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=4)
        ttk.Button(per_btns, text="Remove", command=self.remove_blocked_id).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(4, 0))

        # Global blocklist
        global_frame = ttk.LabelFrame(blocklists_tab, text="Global Blocked Group IDs (All Accounts)")
        global_frame.grid(row=1, column=0, sticky="nsew", padx=4, pady=(0, 4))
        global_frame.columnconfigure(0, weight=1)
        global_frame.rowconfigure(0, weight=1)

        global_list_container = ttk.Frame(global_frame)
        global_list_container.grid(row=0, column=0, sticky="nsew", pady=(4, 4))

        self.global_blocked_listbox = tk.Listbox(
            global_list_container,
            activestyle="none",
            font=("Helvetica", 11),
            bg=self.colors["card_bg"],
            fg=self.colors["text_primary"],
            selectbackground=self.colors["accent"],
            selectforeground="#ffffff",
        )
        self.global_blocked_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        global_scroll = ttk.Scrollbar(global_list_container, orient=tk.VERTICAL, command=self.global_blocked_listbox.yview)
        global_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.global_blocked_listbox.config(yscrollcommand=global_scroll.set)
        self.global_blocked_listbox.bind("<Double-Button-1>", self.edit_global_blocked_id)

        global_btns = ttk.Frame(global_frame)
        global_btns.grid(row=1, column=0, sticky="ew", pady=(2, 4))
        ttk.Button(global_btns, text="Add", command=self.add_global_blocked_id).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 4))
        ttk.Button(global_btns, text="Edit", command=self.edit_global_blocked_id).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=4)
        ttk.Button(global_btns, text="Remove", command=self.remove_global_blocked_id).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(4, 0))

        # --- Activity Log tab ---

        activity_tab.columnconfigure(0, weight=1)
        activity_tab.rowconfigure(1, weight=1)
        activity_tab.rowconfigure(2, weight=0)

        log_controls = ttk.Frame(activity_tab)
        log_controls.grid(row=0, column=0, sticky="w", pady=(6, 4), padx=4)

        ttk.Label(log_controls, text="Log Mode:", font=("Helvetica", 12, "bold")).pack(side=tk.LEFT)
        ttk.Radiobutton(
            log_controls,
            text="User",
            variable=self.log_mode_var,
            value="user",
            command=self.on_log_mode_change,
        ).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Radiobutton(
            log_controls,
            text="Debug",
            variable=self.log_mode_var,
            value="debug",
            command=self.on_log_mode_change,
        ).pack(side=tk.LEFT, padx=(8, 0))

        log_frame = ttk.Frame(activity_tab)
        log_frame.grid(row=1, column=0, sticky="nsew", padx=4, pady=(0, 4))

        self.log_text = tk.Text(
            log_frame,
            state=tk.DISABLED,
            wrap="word",
            font=("Helvetica", 11),
            bg=self.colors["card_bg"],
            fg=self.colors["text_primary"],
            highlightthickness=0,
            borderwidth=0,
        )
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=log_scroll.set)

        # Bottom log actions (extra-visible)
        log_actions = ttk.Frame(activity_tab)
        log_actions.grid(row=2, column=0, sticky="ew", padx=4, pady=(6, 0))
        ttk.Button(log_actions, text="Clear Log", command=self.clear_logs).pack(side=tk.RIGHT)

    # ---- Logging ----

    def log(self, msg: str, level: str = "debug"):
        # Prefix all log entries with a 12-hour time stamp, e.g. [3:07:15 PM]
        ts = datetime.now().strftime("%I:%M:%S %p").lstrip("0")
        entry = f"[{ts}] {msg}"
        self.log_history.append((entry, level))
        if not self._should_display_log(level):
            return
        self._append_log_line(entry)

    def _append_log_line(self, msg: str):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _should_display_log(self, level: str) -> bool:
        mode = self.log_mode_var.get() if hasattr(self, "log_mode_var") else "debug"
        if mode == "debug":
            return True
        return level == "user"

    def refresh_log_display(self):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        for msg, level in self.log_history:
            if self._should_display_log(level):
                self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def on_log_mode_change(self):
        self.refresh_log_display()

    def clear_logs(self):
        """Clear the on-screen log window and the stored log history."""
        self.log_history.clear()
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    # ---- Account List Handling ----

    def refresh_account_list(self):
        """Redraw the list of accounts, preserving the current selection."""
        self.account_listbox.delete(0, tk.END)
        for a in self.accounts:
            self.account_listbox.insert(tk.END, a.label)

        if self.accounts:
            # Clamp current_index and preserve selection
            if self.current_index is None or self.current_index >= len(self.accounts):
                self.current_index = 0
            self.account_listbox.selection_clear(0, tk.END)
            self.account_listbox.selection_set(self.current_index)
            self.load_account_into_form(self.current_index)
        else:
            self.current_index = None
            self.clear_form()

    def on_account_select(self, event=None):
        sel = self.account_listbox.curselection()
        if not sel:
            # Don't clear current_index just because focus moved
            return
        idx = sel[0]
        self.current_index = idx
        self.load_account_into_form(idx)

    def load_account_into_form(self, idx: int):
        if idx < 0 or idx >= len(self.accounts):
            return
        acc = self.accounts[idx]
        self.label_entry.delete(0, tk.END)
        self.label_entry.insert(0, acc.label)

        self.token_entry.delete(0, tk.END)
        self.token_entry.insert(0, acc.token)

        # Mode (blacklist/whitelist)
        self.whitelist_var.set(getattr(acc, "mode", "blacklist") == "whitelist")

        self.blocked_listbox.delete(0, tk.END)
        for gid in acc.blocked_group_ids:
            self.blocked_listbox.insert(tk.END, gid)

    def clear_form(self):
        self.label_entry.delete(0, tk.END)
        self.token_entry.delete(0, tk.END)
        self.whitelist_var.set(False)
        self.blocked_listbox.delete(0, tk.END)

    def add_account(self):
        label = simpledialog.askstring("New Account", "Label for this account:")
        if not label:
            return
        acc = AccountConfig(label=label, token="", blocked_group_ids=[], mode="blacklist")
        self.accounts.append(acc)
        save_config(self.accounts, self.global_blocked_ids)
        self.current_index = len(self.accounts) - 1
        self.refresh_account_list()
        self.log(f"Added account '{label}'.")

    def remove_account(self):
        if self.current_index is None:
            return
        acc = self.accounts[self.current_index]
        if messagebox.askyesno("Remove Account", f"Remove account '{acc.label}'?"):
            self.accounts.pop(self.current_index)
            save_config(self.accounts, self.global_blocked_ids)
            if self.accounts:
                self.current_index = min(self.current_index, len(self.accounts) - 1)
            else:
                self.current_index = None
            self.refresh_account_list()
            self.log(f"Removed account '{acc.label}'.")

    def save_current_account(self):
        if self.current_index is None:
            messagebox.showinfo("No Account", "Select an account first.")
            return
        acc = self.accounts[self.current_index]
        new_label = self.label_entry.get().strip()
        if new_label:
            acc.label = new_label
        acc.token = self.token_entry.get().strip()
        acc.mode = "whitelist" if self.whitelist_var.get() else "blacklist"

        blocked_ids = []
        for i in range(self.blocked_listbox.size()):
            val = self.blocked_listbox.get(i)
            if val and val.strip():
                blocked_ids.append(val)
        acc.blocked_group_ids = blocked_ids

        self.accounts[self.current_index] = acc
        save_config(self.accounts, self.global_blocked_ids)
        self.refresh_account_list()
        self.log(f"Saved account '{acc.label}'.")

    # ---- Per-account Blocked IDs ----

    def add_blocked_id(self):
        if self.current_index is None:
            messagebox.showinfo("No Account", "Select an account first.")
            return
        gid = simpledialog.askstring(
            "Blocked Group ID",
            "Enter GroupMe group ID to block for this account:",
        )
        if not gid:
            return
        gid = gid.strip()
        if not gid:
            return

        name = simpledialog.askstring(
            "Group Name",
            "Enter a display name for this blocked group (optional):",
        )
        if name:
            name = name.strip()
        display = f"{gid} | {name}" if name else gid

        self.blocked_listbox.insert(tk.END, display)
        self.save_current_account()
        self.log(f"Added blocked group '{display}' for this account.")

    def remove_blocked_id(self):
        if self.current_index is None:
            messagebox.showinfo("No Account", "Select an account first.")
            return
        sel = self.blocked_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        gid = self.blocked_listbox.get(idx)
        self.blocked_listbox.delete(idx)
        self.save_current_account()
        self.log(f"Removed blocked group ID '{gid}' from this account.")

    def edit_blocked_id(self, event=None):
        if self.current_index is None:
            messagebox.showinfo("No Account", "Select an account first.")
            return
        sel = self.blocked_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        current = self.blocked_listbox.get(idx)
        updated = simpledialog.askstring(
            "Edit Blocked Group",
            "Update the blocked group entry:",
            initialvalue=current,
        )
        if not updated:
            return
        updated = updated.strip()
        if not updated:
            return
        self.blocked_listbox.delete(idx)
        self.blocked_listbox.insert(idx, updated)
        self.save_current_account()
        self.log(f"Updated blocked group to '{updated}' for this account.")

    # ---- Global Blocked IDs ----

    def refresh_global_blocklist_ui(self):
        if not hasattr(self, "global_blocked_listbox"):
            return
        self.global_blocked_listbox.delete(0, tk.END)
        for gid in self.global_blocked_ids:
            self.global_blocked_listbox.insert(tk.END, gid)

    def add_global_blocked_id(self):
        gid = simpledialog.askstring(
            "Global Blocked Group ID",
            "Enter GroupMe group ID to block for ALL accounts:",
        )
        if not gid:
            return
        gid = gid.strip()
        if not gid:
            return

        name = simpledialog.askstring(
            "Group Name",
            "Enter a display name for this blocked group (optional):",
        )
        if name:
            name = name.strip()
        display = f"{gid} | {name}" if name else gid

        if display:
            self.global_blocked_ids.append(display)
            save_config(self.accounts, self.global_blocked_ids)
            self.refresh_global_blocklist_ui()
            self.log(f"Added GLOBAL blocked group '{display}'.")

    def remove_global_blocked_id(self):
        sel = self.global_blocked_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        gid = self.global_blocked_listbox.get(idx)
        self.global_blocked_listbox.delete(idx)
        self.global_blocked_ids = [g for g in self.global_blocked_ids if g != gid]
        save_config(self.accounts, self.global_blocked_ids)
        self.log(f"Removed GLOBAL blocked group ID '{gid}'.")

    def edit_global_blocked_id(self, event=None):
        sel = self.global_blocked_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        current = self.global_blocked_listbox.get(idx)
        updated = simpledialog.askstring(
            "Edit Global Blocked Group",
            "Update this global blocked entry:",
            initialvalue=current,
        )
        if not updated:
            return
        updated = updated.strip()
        if not updated:
            return
        self.global_blocked_listbox.delete(idx)
        self.global_blocked_listbox.insert(idx, updated)
        self.global_blocked_ids = list(self.global_blocked_listbox.get(0, tk.END))
        save_config(self.accounts, self.global_blocked_ids)
        self.log(f"Updated GLOBAL blocked group to '{updated}'.")

    # ---- Token visibility ----

    def toggle_token_visibility(self):
        show = self.token_entry.cget("show")
        if show == "*":
            self.token_entry.config(show="")
        else:
            self.token_entry.config(show="*")

    # ---- Show groups for selected account ----

    def show_groups_for_account(self):
        if self.current_index is None:
            messagebox.showinfo("No Account", "Select an account first.")
            return
        acc = self.accounts[self.current_index]
        token = self.token_entry.get().strip()
        if not token:
            messagebox.showwarning(
                "No Token", "Enter an access token for this account first."
            )
            return

        def log_noop(_, level="debug"):
            pass

        gm_acc = GroupMeAccount(
            acc.label,
            token,
            acc.blocked_group_ids,
            self.global_blocked_ids,
            log_noop,
            getattr(acc, "mode", "blacklist"),
        )
        text = gm_acc.list_groups_text()

        win = tk.Toplevel(self.root)
        win.title(f"Groups for {acc.label}")
        txt = tk.Text(
            win,
            width=80,
            height=25,
            bg=self.colors["card_bg"],
            fg=self.colors["text_primary"],
            highlightthickness=0,
            borderwidth=0,
        )
        txt.pack(fill=tk.BOTH, expand=True)
        txt.insert(tk.END, text)
        txt.config(state=tk.DISABLED)

    # ---- Watching / background worker ----

    def toggle_running(self):
        if self.is_running:
            self.is_running = False
            self.run_button.config(text="Start Watching")
            self.log("Stopping watcher...")
        else:
            # Ensure accounts + global are saved and loaded fresh
            if self.current_index is not None:
                self.save_current_account()
            self.accounts, self.global_blocked_ids = load_config()
            self.refresh_account_list()
            self.refresh_global_blocklist_ui()

            self.is_running = True
            self.run_button.config(text="Stop Watching")
            self.log("Starting watcher...")
            self.start_worker_thread()

    def start_worker_thread(self):
        if self.worker_thread and self.worker_thread.is_alive():
            return

        self.worker_thread = threading.Thread(target=self.worker_loop, daemon=True)
        self.worker_thread.start()

    def worker_loop(self):
        while self.is_running:
            # Reload accounts + global blocklist so GUI edits apply
            accounts_current, global_ids = load_config()
            self.global_blocked_ids = global_ids

            # Rebuild or update persistent GroupMeAccount objects
            new_gm_accounts: Dict[str, GroupMeAccount] = {}
            for acc in accounts_current:
                label = acc.label
                existing = self.gm_accounts.get(label)
                if existing is not None:
                    gm_acc = existing
                    gm_acc.token = acc.token.strip()
                    gm_acc.headers = {"X-Access-Token": gm_acc.token}
                    gm_acc.per_account_blocked_ids = acc.blocked_group_ids
                    gm_acc.global_blocked_ids = self.global_blocked_ids
                    gm_acc.mode = getattr(acc, "mode", "blacklist")
                else:
                    gm_acc = GroupMeAccount(
                        acc.label,
                        acc.token,
                        acc.blocked_group_ids,
                        self.global_blocked_ids,
                        self.log,
                        getattr(acc, "mode", "blacklist"),
                    )
                new_gm_accounts[label] = gm_acc

            self.gm_accounts = new_gm_accounts

            # Run enforcement for each account
            for gm_acc in self.gm_accounts.values():
                if not gm_acc.token.strip():
                    continue
                gm_acc.enforce_blocklist_once()

            time.sleep(POLL_INTERVAL_SECONDS)


def main():
    root = tk.Tk()
    app = App(root)
    app.log(f"UI build: {APP_VERSION}")
    app.log(
        "NOTE: Access tokens and blocklists are stored in accounts_config.json "
        "under ~/Library/Application Support/GroupMeBlocker in plain text. Keep this file private."
    )
    root.mainloop()


if __name__ == "__main__":
    main()
