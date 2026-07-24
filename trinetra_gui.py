#!/usr/bin/env python3
"""Secure launcher for Trinetra.

The application implementation lives in ``trinetra_core.py``. This launcher adds
OS-backed credential persistence for the Nessus URL and API keys while keeping
the original ``python trinetra_gui.py`` command unchanged.
"""

from __future__ import annotations

import json
from typing import Any, Dict

import trinetra_core as core

try:
    import keyring
    from keyring.errors import KeyringError, PasswordDeleteError
except Exception:  # pragma: no cover - handled at runtime with a clear message
    keyring = None

    class KeyringError(Exception):
        pass

    class PasswordDeleteError(KeyringError):
        pass


KEYRING_SERVICE = "Trinetra Nessus API"
KEYRING_ACCOUNT = "saved-connection"


class SecureCredentialStore:
    """Persist Nessus connection settings in the operating system keyring."""

    @staticmethod
    def _require_backend() -> None:
        if keyring is None:
            raise RuntimeError(
                "Secure credential storage requires the 'keyring' package. "
                "Install it with: python -m pip install keyring"
            )
        try:
            backend = keyring.get_keyring()
            priority = float(getattr(backend, "priority", 0) or 0)
        except Exception as exc:
            raise RuntimeError(f"Unable to initialize the operating system credential vault: {exc}") from exc
        if priority <= 0:
            raise RuntimeError(
                "No secure operating system credential-vault backend is available. "
                "Windows uses Credential Manager; macOS uses Keychain; Linux requires a supported keyring backend."
            )

    def load(self) -> Dict[str, Any]:
        self._require_backend()
        try:
            value = keyring.get_password(KEYRING_SERVICE, KEYRING_ACCOUNT)
        except KeyringError as exc:
            raise RuntimeError(f"Unable to read saved Nessus settings securely: {exc}") from exc
        if not value:
            return {}
        try:
            payload = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Saved Nessus settings are invalid and could not be loaded.") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Saved Nessus settings have an invalid format.")
        return payload

    def save(self, base_url: str, access_key: str, secret_key: str, verify_tls: bool) -> None:
        self._require_backend()
        payload = json.dumps(
            {
                "base_url": base_url.strip(),
                "access_key": access_key.strip(),
                "secret_key": secret_key.strip(),
                "verify_tls": bool(verify_tls),
            },
            separators=(",", ":"),
        )
        try:
            keyring.set_password(KEYRING_SERVICE, KEYRING_ACCOUNT, payload)
        except KeyringError as exc:
            raise RuntimeError(f"Unable to save Nessus settings securely: {exc}") from exc

    def clear(self) -> None:
        if keyring is None:
            return
        try:
            self._require_backend()
            keyring.delete_password(KEYRING_SERVICE, KEYRING_ACCOUNT)
        except PasswordDeleteError:
            pass
        except KeyringError as exc:
            raise RuntimeError(f"Unable to remove saved Nessus settings: {exc}") from exc


SECURE_STORE = SecureCredentialStore()
_PATCHED = False


def _patch_local_auth_reset() -> None:
    original_reset = core.LocalAuthManager.reset

    def reset_with_saved_credentials(self) -> None:
        # Clear the OS-vault entry before deleting the local login configuration.
        SECURE_STORE.clear()
        original_reset(self)

    core.LocalAuthManager.reset = reset_with_saved_credentials


def _patch_reset_dialog() -> None:
    def reset_login(self) -> None:
        confirmed = core.messagebox.askyesno(
            "Reset Trinetra Account",
            "Reset the local Trinetra account on this workstation?\n\n"
            "This permanently removes the saved Nessus URL, Access Key, and Secret Key "
            "from the operating system credential vault. You will then create a new username and password.",
            parent=self.window,
        )
        if not confirmed:
            return
        try:
            self.auth.reset()
            self.setup_mode = True
            self.username_var.set("")
            self.password_var.set("")
            self.confirm_var.set("")
            if self.logo_after_id:
                try:
                    self.window.after_cancel(self.logo_after_id)
                except Exception:
                    pass
                self.logo_after_id = None
            self.build()
            self.center()
            self.show()
            self.message_var.set("Account and saved Nessus credentials were reset. Create a new Trinetra login.")
        except Exception as exc:
            self.message_var.set(f"Reset failed: {exc}")

    core.LoginDialog.reset_login = reset_login


def _patch_dashboard() -> None:
    original_init = core.NessusAuthDashboardGUI.__init__

    def secure_init(self, root) -> None:
        original_init(self, root)
        try:
            payload = SECURE_STORE.load()
            if payload:
                self.base_url_var.set(str(payload.get("base_url") or "https://127.0.0.1:8834"))
                self.access_key_var.set(str(payload.get("access_key") or ""))
                self.secret_key_var.set(str(payload.get("secret_key") or ""))
                self.verify_tls.set(bool(payload.get("verify_tls", False)))
                self.log("Saved Nessus connection settings loaded from the operating system credential vault.")
        except Exception as exc:
            self.log(f"Secure credential storage unavailable: {exc}")

    def save_connection_settings(self) -> None:
        SECURE_STORE.save(
            self.base_url_var.get(),
            self.access_key_var.get(),
            self.secret_key_var.get(),
            self.verify_tls.get(),
        )
        self.thread_log("Nessus URL and API keys saved securely in the operating system credential vault.")

    def secure_load_scans_worker(self) -> None:
        try:
            self.thread_log("Connecting to Nessus and loading folders...")
            self.set_progress(10)
            client = self.make_client()
            scans, folders = client.list_scan_inventory()
            self.set_progress(70)
            self.scans = scans
            self.scan_folders = folders
            try:
                save_connection_settings(self)
            except Exception as storage_exc:
                self.thread_log(f"WARNING: Nessus connection succeeded, but settings were not saved: {storage_exc}")
                self.root.after(
                    0,
                    lambda message=str(storage_exc): core.messagebox.showwarning(
                        "Secure Storage Unavailable",
                        "The Nessus connection succeeded, but Trinetra could not save the URL and API keys securely.\n\n"
                        f"{message}",
                    ),
                )
            self.root.after(0, self.populate_folder_selector)
            self.thread_log(f"Loaded {len(folders)} folders and {len(scans)} scans.")
            self.set_progress(100)
        except Exception as exc:
            self.show_error("Load Scans Failed", str(exc))
            self.thread_log(core.traceback.format_exc())
            self.set_progress(0)

    core.NessusAuthDashboardGUI.__init__ = secure_init
    core.NessusAuthDashboardGUI._save_connection_settings = save_connection_settings
    core.NessusAuthDashboardGUI._load_scans_worker = secure_load_scans_worker


def install_secure_persistence() -> None:
    global _PATCHED
    if _PATCHED:
        return
    _patch_local_auth_reset()
    _patch_reset_dialog()
    _patch_dashboard()
    _PATCHED = True


install_secure_persistence()


# Re-export public names so existing imports from trinetra_gui continue to work.
for _name in dir(core):
    if not _name.startswith("_") and _name not in globals():
        globals()[_name] = getattr(core, _name)


if __name__ == "__main__":
    core.main()
