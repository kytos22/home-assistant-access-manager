import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import unicodedata
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlparse
from pathlib import Path

from aiohttp import ClientSession, ClientTimeout, WSMsgType, web
from cryptography.fernet import Fernet, InvalidToken


PORT = 8099
DATA_DIR = Path("/data")
DB_PATH = DATA_DIR / "fingerprint_admin.db"
HA_API = "http://supervisor/core/api"
HA_WS = "ws://supervisor/core/websocket"
TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
APP_VERSION = os.environ.get("ACCESS_MANAGER_VERSION") or "development"
READER_FIRMWARE_VERSION = "0.6.0"
READER_FIRMWARE_REPOSITORY = (
    "https://github.com/kytos22/esphome-fingerprint-access-reader"
)
OPTIONS_PATH = DATA_DIR / "options.json"
INDEX_PATH = Path(__file__).with_name("index.html")

LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
}


def configured_options(path=OPTIONS_PATH):
    try:
        options = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return options if isinstance(options, dict) else {}

def configured_esphome_url():
    value = str(configured_options().get("esphome_dashboard_url", "")).strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):

        return ""
    return value.rstrip("/")

def configured_log_level(path=OPTIONS_PATH):
    options = configured_options(path)
    value = str(options.get("log_level", "info")).strip().lower()
    return value if value in LOG_LEVELS else "info"


LOG_LEVEL = configured_log_level()

LABELS = {
    "slot": ("ID huella a registrar",),
    "enroll": ("Registrar huella",),
    "cancel": ("Cancelar registro",),
    "delete": ("Borrar huella seleccionada",),
    "access_event": ("Evento huella",),
    "management_event": ("Evento gestion huella", "Evento gestión huella"),
    "name_registry": ("Gestion nombres huella", "Gestión nombres huella"),
    "fingerprint_count": ("Huellas guardadas",),
    "reader_status": ("Estado lector",),
    "reader_capacity": ("Capacidad lector",),
    "last_finger_id": ("Ultimo ID huella", "Último ID huella"),
    "last_confidence": ("Ultima confianza", "Última confianza"),
    "device_status": ("Estado conexion", "Estado conexión"),
    "assigned_door": ("Access Manager door ID",),
    "display_event": ("Access Manager display event",),
    "firmware_version": ("Fingerprint reader firmware version",),
    "display_language": ("Display language",),
}

DOMAINS = {
    "slot": "number",
    "enroll": "button",
    "cancel": "button",
    "delete": "button",
    "access_event": "sensor",
    "management_event": "sensor",
    "name_registry": "text",
    "fingerprint_count": "sensor",
    "reader_status": "sensor",
    "reader_capacity": "sensor",
    "last_finger_id": "sensor",
    "last_confidence": "sensor",
    "device_status": "binary_sensor",
    "assigned_door": "text",
    "display_event": "text",
    "firmware_version": "sensor",
    "display_language": "select",
}

FINGER_LABELS = {
    "left_thumb": "Left thumb",
    "left_index": "Left index",
    "left_middle": "Left middle",
    "left_ring": "Left ring",
    "left_pinky": "Left little finger",
    "right_thumb": "Right thumb",
    "right_index": "Right index",
    "right_middle": "Right middle",
    "right_ring": "Right ring",
    "right_pinky": "Right little finger",
}

logging.basicConfig(
    level=LOG_LEVELS[LOG_LEVEL],
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
LOGGER = logging.getLogger("fingerprint_admin")
DELETE_RETRY_SECONDS = 30
DOOR_ACTIONS = {
    "lock": ("open", "unlock", "lock"),
    "switch": ("turn_on",),
    "button": ("press",),
    "input_button": ("press",),
    "cover": ("open_cover",),
}
LOCK_OPEN_FEATURE = 1
READER_REQUESTED_ACTIONS = {"default", "open", "unlock", "lock"}
LOCAL_UNAUTHENTICATED_ACTIONS = {"lock"}
AUTOMATION_ID_PREFIX = "access_manager_"
AUTOMATION_ALIAS_PREFIX = "[Access Manager]"
AUTOMATION_DESCRIPTION_MARKER = "Managed by Access Manager."
AUTO_LOCK_DELAYS = (5, 10, 15, 20, 30, 60)
DOOR_OPEN_DELAYS = (1, 2, 5, 10, 15, 20, 30, 60)
DENIED_ATTEMPT_THRESHOLDS = (1, 2, 3, 5, 10)
DENIED_ATTEMPT_WINDOWS = (1, 2, 5, 10, 15, 30)
KEYPAD_PACKET_SETTLE_SECONDS = 0.1
KEYPAD_PACKET_MAX_SPAN_SECONDS = 2.0
DOOR_COMMAND_CORRELATION_SECONDS = 10.0
DISPLAY_EVENT_KINDS = {"door_opened", "credential_captured", "keypad_denied"}
DISPLAY_OPENING_ACTIONS = {"open", "unlock", "turn_on", "press", "open_cover"}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalized(value):
    text = unicodedata.normalize("NFKD", str(value or ""))
    return "".join(char for char in text if not unicodedata.combining(char)).lower().strip()


def esphome_reader_config(payload):
    profile = str(payload.get("profile", "reader_only")).strip().lower()
    if profile not in {"reader_only", "display"}:
        raise ValueError("Unsupported reader profile")
    install_mode = str(payload.get("install_mode", "new")).strip().lower()
    if install_mode not in {"new", "existing"}:
        raise ValueError("Unsupported installation mode")
    device_name = str(payload.get("device_name", "")).strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,30}[a-z0-9]", device_name):
        raise ValueError("Device name must contain 2-32 lowercase letters, numbers or hyphens")
    friendly_name = str(payload.get("friendly_name", "")).strip()[:50]
    if not friendly_name or any(char in friendly_name for char in "\r\n"):
        raise ValueError("Invalid friendly name")

    substitutions = {
        "device_name": device_name,
        "friendly_name": friendly_name,
    }
    if profile == "display":
        display_language = str(payload.get("display_language", "English")).strip()
        if display_language not in {"English", "Español"}:
            raise ValueError("Unsupported display language")
        substitutions["display_language"] = display_language

    package_file = "access-reader.yaml" if profile == "display" else "reader-only.yaml"
    if profile == "reader_only":
        board = str(payload.get("board", "esp32dev")).strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", board):
            raise ValueError("Invalid ESPHome board ID")
        substitutions["board"] = board
        for key, default in (
            ("fingerprint_tx_pin", "GPIO17"),
            ("fingerprint_rx_pin", "GPIO16"),
        ):
            pin = str(payload.get(key, default)).strip().upper()
            if not re.fullmatch(r"(?:GPIO)?[0-9]{1,2}", pin):
                raise ValueError(f"Invalid {key.replace('_', ' ')}")
            substitutions[key] = pin
        if substitutions["fingerprint_tx_pin"] == substitutions["fingerprint_rx_pin"]:
            raise ValueError("UART TX and RX pins must be different")

    lines = [
        "# Generated by Access Manager.",
        "# ESPHome downloads the complete release-pinned firmware package below.",
    ]
    if install_mode == "existing":
        lines.extend(
            [
                "# Existing device update: keep device_name and all existing secret",
                "# values unchanged or Home Assistant API/OTA access may need repair.",
            ]
        )
    else:
        lines.extend(
            [
                "# New device: import this file into ESPHome Device Builder, validate it,",
                "# and use Install. The first flash normally requires a USB connection.",
            ]
        )
    lines.extend(["", "substitutions:"])
    for key, value in substitutions.items():
        lines.append(f"  {key}: {json.dumps(value, ensure_ascii=False)}")
    lines.extend(
        [
            "",
            "packages:",
            "  fingerprint_access_reader:",
            f"    url: {READER_FIRMWARE_REPOSITORY}",
            f"    ref: v{READER_FIRMWARE_VERSION}",
            "    files:",
            f"      - {package_file}",
            "    refresh: 1d",
            "",
            "# Required keys in the ESPHome secrets.yaml file:",
            "# wifi_ssid, wifi_password, api_encryption_key, ota_password",
            "# Access Manager never requests, receives, or stores their values.",
            "",
        ]
    )
    return "\n".join(lines)


class Registry:
    def __init__(self, path):
        self._credential_cipher = None
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            PRAGMA foreign_keys=ON;
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS users (
                reader_id TEXT NOT NULL DEFAULT 'display1',
                slot INTEGER NOT NULL CHECK(slot BETWEEN 1 AND 240),
                name TEXT NOT NULL,
                finger TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                enrolled_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(reader_id, slot)
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                slot INTEGER,
                confidence INTEGER,
                detail TEXT,
                door_id TEXT,
                entity_id TEXT,
                source TEXT,
                previous_state TEXT,
                new_state TEXT
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS deletion_queue (
                reader_id TEXT NOT NULL DEFAULT 'display1',
                slot INTEGER NOT NULL CHECK(slot BETWEEN 1 AND 240),
                state TEXT NOT NULL DEFAULT 'queued',
                attempts INTEGER NOT NULL DEFAULT 0,
                baseline_count INTEGER,
                expected_count INTEGER,
                last_error TEXT,
                requested_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(reader_id, slot)
            );
            CREATE TABLE IF NOT EXISTS people (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                normalized_name TEXT NOT NULL UNIQUE,
                ha_person_entity_id TEXT UNIQUE,
                ha_link_status TEXT NOT NULL DEFAULT 'unlinked',
                ha_auto_link_disabled INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active',
                deletion_requested_at TEXT,
                archived_at TEXT,
                deletion_total INTEGER NOT NULL DEFAULT 0,
                deletion_completed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS doors (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                entity_id TEXT,
                door_sensor_entity TEXT NOT NULL DEFAULT '',
                open_action TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS readers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                reader_type TEXT NOT NULL,
                door_id TEXT REFERENCES doors(id),
                enabled INTEGER NOT NULL DEFAULT 1,
                config_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS keypad_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                person_id INTEGER NOT NULL REFERENCES people(id),
                reader_id TEXT NOT NULL REFERENCES readers(id),
                secret_hash TEXT NOT NULL,
                hash_version INTEGER NOT NULL DEFAULT 2,
                secret_ciphertext TEXT,
                code_hint TEXT NOT NULL,
                keypad_action TEXT NOT NULL,
                normalized_action TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(reader_id, secret_hash)
            );
            CREATE TABLE IF NOT EXISTS shared_keypad_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                reader_id TEXT NOT NULL REFERENCES readers(id),
                secret_hash TEXT NOT NULL,
                hash_version INTEGER NOT NULL DEFAULT 2,
                secret_ciphertext TEXT NOT NULL,
                code_hint TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(reader_id, secret_hash)
            );
            CREATE TABLE IF NOT EXISTS managed_automations (
                id TEXT PRIMARY KEY,
                automation_type TEXT NOT NULL,
                door_id TEXT NOT NULL REFERENCES doors(id),
                ha_config_id TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                config_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(automation_type, door_id)
            );
            CREATE TABLE IF NOT EXISTS mobile_nfc_tags (
                tag_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                door_id TEXT NOT NULL REFERENCES doors(id),
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mobile_nfc_permissions (
                person_id INTEGER NOT NULL REFERENCES people(id),
                door_id TEXT NOT NULL REFERENCES doors(id),
                enabled INTEGER NOT NULL DEFAULT 0,
                suspended INTEGER NOT NULL DEFAULT 0,
                ha_person_entity_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(person_id, door_id)
            );
            CREATE TABLE IF NOT EXISTS mobile_nfc_event_ids (
                event_id TEXT PRIMARY KEY,
                occurred_at TEXT NOT NULL
            );
            """
        )
        users_schema = self.connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'"
        ).fetchone()[0]
        users_columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(users)").fetchall()
        }
        if "finger" not in users_columns:
            self.connection.execute(
                "ALTER TABLE users ADD COLUMN finger TEXT NOT NULL DEFAULT ''"
            )
        if "reader_id" not in users_columns:
            self.connection.executescript(
                """
                CREATE TABLE users_multi_reader (
                    reader_id TEXT NOT NULL DEFAULT 'display1',
                    slot INTEGER NOT NULL CHECK(slot BETWEEN 1 AND 240),
                    name TEXT NOT NULL,
                    finger TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'active',
                    enrolled_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    person_id INTEGER,
                    PRIMARY KEY(reader_id, slot)
                );
                INSERT INTO users_multi_reader(
                    reader_id, slot, name, finger, status, enrolled_at, updated_at, person_id
                )
                SELECT 'display1', slot, name, finger, status, enrolled_at, updated_at,
                       NULL
                FROM users;
                DROP TABLE users;
                ALTER TABLE users_multi_reader RENAME TO users;
                """
            )
        users_columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(users)").fetchall()
        }
        if "person_id" not in users_columns:
            self.connection.execute("ALTER TABLE users ADD COLUMN person_id INTEGER")
        deletion_columns = {
            row[1] for row in self.connection.execute(
                "PRAGMA table_info(deletion_queue)"
            ).fetchall()
        }
        if "reader_id" not in deletion_columns:
            self.connection.executescript(
                """
                CREATE TABLE deletion_queue_multi_reader (
                    reader_id TEXT NOT NULL DEFAULT 'display1',
                    slot INTEGER NOT NULL CHECK(slot BETWEEN 1 AND 240),
                    state TEXT NOT NULL DEFAULT 'queued',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    baseline_count INTEGER,
                    expected_count INTEGER,
                    last_error TEXT,
                    requested_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(reader_id, slot)
                );
                INSERT INTO deletion_queue_multi_reader(
                    reader_id, slot, state, attempts, baseline_count, expected_count,
                    last_error, requested_at, updated_at
                )
                SELECT 'display1', slot, state, attempts, baseline_count, expected_count,
                       last_error, requested_at, updated_at
                FROM deletion_queue;
                DROP TABLE deletion_queue;
                ALTER TABLE deletion_queue_multi_reader RENAME TO deletion_queue;
                """
            )
        deletion_schema = self.connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'table' AND name = 'deletion_queue'
            """
        ).fetchone()[0]
        if "BETWEEN 1 AND 50" in deletion_schema:
            self.connection.executescript(
                """
                CREATE TABLE deletion_queue_wide (
                    reader_id TEXT NOT NULL DEFAULT 'display1',
                    slot INTEGER NOT NULL CHECK(slot BETWEEN 1 AND 240),
                    state TEXT NOT NULL DEFAULT 'queued',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    baseline_count INTEGER,
                    expected_count INTEGER,
                    last_error TEXT,
                    requested_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(reader_id, slot)
                );
                INSERT INTO deletion_queue_wide(
                    reader_id, slot, state, attempts, baseline_count,
                    expected_count, last_error, requested_at, updated_at
                )
                SELECT reader_id, slot, state, attempts, baseline_count,
                       expected_count, last_error, requested_at, updated_at
                FROM deletion_queue;
                DROP TABLE deletion_queue;
                ALTER TABLE deletion_queue_wide RENAME TO deletion_queue;
                """
            )
        door_columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(doors)").fetchall()
        }
        if "open_action" not in door_columns:
            self.connection.execute(
                "ALTER TABLE doors ADD COLUMN open_action TEXT NOT NULL DEFAULT ''"
            )
        if "door_sensor_entity" not in door_columns:
            self.connection.execute(
                "ALTER TABLE doors ADD COLUMN door_sensor_entity TEXT NOT NULL DEFAULT ''"
            )
            automation_rows = self.connection.execute(
                """
                SELECT door_id, config_json
                FROM managed_automations
                WHERE automation_type IN ('door_open', 'auto_lock')
                ORDER BY CASE automation_type WHEN 'door_open' THEN 0 ELSE 1 END
                """
            ).fetchall()
            migrated_doors = set()
            for row in automation_rows:
                if row["door_id"] in migrated_doors:
                    continue
                try:
                    config = json.loads(row["config_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    continue
                sensor_entity = str(config.get("door_sensor_entity", "")).strip()
                if not sensor_entity:
                    continue
                self.connection.execute(
                    "UPDATE doors SET door_sensor_entity = ? WHERE id = ?",
                    (sensor_entity, row["door_id"]),
                )
                migrated_doors.add(row["door_id"])
        event_columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(events)").fetchall()
        }
        for column in (
            "door_id", "entity_id", "source", "previous_state", "new_state"
        ):
            if column not in event_columns:
                self.connection.execute(f"ALTER TABLE events ADD COLUMN {column} TEXT")
        people_columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(people)").fetchall()
        }
        if "ha_person_entity_id" not in people_columns:
            self.connection.execute(
                "ALTER TABLE people ADD COLUMN ha_person_entity_id TEXT"
            )
            self.connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_people_ha_person ON people(ha_person_entity_id)"
            )
        people_columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(people)").fetchall()
        }
        people_migrations = {
            "ha_link_status": "TEXT NOT NULL DEFAULT 'unlinked'",
            "ha_auto_link_disabled": "INTEGER NOT NULL DEFAULT 0",
            "deletion_requested_at": "TEXT",
            "archived_at": "TEXT",
            "deletion_total": "INTEGER NOT NULL DEFAULT 0",
            "deletion_completed": "INTEGER NOT NULL DEFAULT 0",
        }
        for column, definition in people_migrations.items():
            if column not in people_columns:
                self.connection.execute(
                    f"ALTER TABLE people ADD COLUMN {column} {definition}"
                )
        self.connection.execute(
            """
            UPDATE people SET ha_link_status = CASE
                WHEN ha_person_entity_id IS NULL THEN 'unlinked'
                ELSE 'unknown'
            END
            WHERE ha_link_status NOT IN ('linked', 'missing', 'unknown', 'unlinked')
               OR (ha_person_entity_id IS NOT NULL AND ha_link_status = 'unlinked')
            """
        )
        mobile_permission_columns = {
            row[1] for row in self.connection.execute(
                "PRAGMA table_info(mobile_nfc_permissions)"
            ).fetchall()
        }
        if "suspended" not in mobile_permission_columns:
            self.connection.execute(
                "ALTER TABLE mobile_nfc_permissions "
                "ADD COLUMN suspended INTEGER NOT NULL DEFAULT 0"
            )
        if "ha_person_entity_id" not in mobile_permission_columns:
            self.connection.execute(
                "ALTER TABLE mobile_nfc_permissions ADD COLUMN ha_person_entity_id TEXT"
            )
            self.connection.execute(
                """
                UPDATE mobile_nfc_permissions
                SET ha_person_entity_id = (
                    SELECT people.ha_person_entity_id FROM people
                    WHERE people.id = mobile_nfc_permissions.person_id
                )
                WHERE enabled = 1
                """
            )
        keypad_credential_columns = {
            row[1] for row in self.connection.execute(
                "PRAGMA table_info(keypad_credentials)"
            ).fetchall()
        }
        migrated_plaintext_credentials = False
        if "hash_version" not in keypad_credential_columns:
            # Version 1 credentials included the keypad action in the HMAC.
            # Keep that scope so existing installations remain usable.
            self.connection.execute(
                "ALTER TABLE keypad_credentials "
                "ADD COLUMN hash_version INTEGER NOT NULL DEFAULT 1"
            )
        if "secret_ciphertext" not in keypad_credential_columns:
            self.connection.execute(
                "ALTER TABLE keypad_credentials ADD COLUMN secret_ciphertext TEXT"
            )
        if "secret_value" in keypad_credential_columns:
            # Migrate databases created by the pre-release plaintext draft.
            self.connection.execute("PRAGMA secure_delete = ON")
            rows = self.connection.execute(
                "SELECT id, secret_value FROM keypad_credentials "
                "WHERE secret_value IS NOT NULL AND secret_value != ''"
            ).fetchall()
            for row in rows:
                self.connection.execute(
                    "UPDATE keypad_credentials SET secret_ciphertext = ? WHERE id = ?",
                    (self.encrypt_keypad_secret(row["secret_value"]), row["id"]),
                )
            self.connection.execute(
                "UPDATE keypad_credentials SET secret_value = NULL"
            )
            migrated_plaintext_credentials = bool(rows)
        self.connection.execute(
            """
            INSERT INTO settings(key, value) VALUES ('initial_seed_complete', '1')
            ON CONFLICT(key) DO NOTHING
            """
        )
        self.connection.execute(
            """
            INSERT INTO settings(key, value) VALUES ('privacy_mode', '1')
            ON CONFLICT(key) DO NOTHING
            """
        )
        self.connection.execute(
            """
            INSERT INTO settings(key, value)
            SELECT 'last_access_event:display1', value FROM settings
            WHERE key = 'last_access_event'
            ON CONFLICT(key) DO NOTHING
            """
        )
        self.connection.execute(
            """
            INSERT INTO settings(key, value)
            SELECT 'last_management_event:display1', value FROM settings
            WHERE key = 'last_management_event'
            ON CONFLICT(key) DO NOTHING
            """
        )
        self.connection.execute(
            "UPDATE deletion_queue SET state = 'queued' WHERE state = 'sent'"
        )
        self.connection.commit()
        if migrated_plaintext_credentials:
            # Remove both old database pages and WAL frames that could retain
            # values from the pre-release plaintext draft.
            self.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.connection.execute("VACUUM")
        self.bootstrap_access_model()
        self.recover_person_deletions()
        self.purge_events()

    def bootstrap_access_model(self):
        with self.connection:
            rows = self.connection.execute(
                "SELECT reader_id, slot, name, person_id FROM users ORDER BY reader_id, slot"
            ).fetchall()
            for row in rows:
                person_id = row["person_id"] or self.ensure_person(row["name"], commit=False)
                self.connection.execute(
                    "UPDATE users SET person_id = ? WHERE reader_id = ? AND slot = ?",
                    (person_id, row["reader_id"], row["slot"]),
                )
            self.connection.execute(
                """
                UPDATE doors SET open_action = CASE
                    WHEN entity_id LIKE 'lock.%' THEN 'open'
                    WHEN entity_id LIKE 'switch.%' THEN 'turn_on'
                    WHEN entity_id LIKE 'button.%' OR entity_id LIKE 'input_button.%' THEN 'press'
                    WHEN entity_id LIKE 'cover.%' THEN 'open_cover'
                    ELSE open_action
                END
                WHERE open_action = ''
                """
            )
            # Existing private installations used automatic entity discovery for
            # the original reader. Mark only that legacy/incomplete configuration;
            # clean installations always store explicit entity mappings.
            legacy = self.connection.execute(
                """
                SELECT id, config_json FROM readers
                WHERE id = 'display1' AND reader_type = 'fingerprint'
                """
            ).fetchone()
            if legacy:
                try:
                    legacy_config = json.loads(legacy["config_json"] or "{}")
                except json.JSONDecodeError:
                    legacy_config = {}
                if not legacy_config.get("slot_entity"):
                    legacy_config["legacy_autodiscovery"] = True
                    self.connection.execute(
                        "UPDATE readers SET config_json = ?, updated_at = ? WHERE id = ?",
                        (json.dumps(legacy_config), now_iso(), legacy["id"]),
                    )

    def ensure_person(self, name, commit=True):
        clean_name = str(name or "").strip()
        wanted = normalized(clean_name)
        if not wanted:
            raise ValueError("Name cannot be empty")
        row = self.connection.execute(
            "SELECT id FROM people WHERE normalized_name = ?", (wanted,)
        ).fetchone()
        if row:
            return row["id"]
        timestamp = now_iso()
        cursor = self.connection.execute(
            """
            INSERT INTO people(name, normalized_name, status, created_at, updated_at)
            VALUES (?, ?, 'active', ?, ?)
            """,
            (clean_name, wanted, timestamp, timestamp),
        )
        if commit:
            self.connection.commit()
        return cursor.lastrowid

    def users(self, reader_id=None):
        if reader_id:
            rows = self.connection.execute(
                "SELECT * FROM users WHERE reader_id = ? ORDER BY slot", (reader_id,)
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM users ORDER BY reader_id, slot"
            ).fetchall()
        return [dict(row) for row in rows]

    def user(self, slot, reader_id="display1"):
        row = self.connection.execute(
            "SELECT * FROM users WHERE reader_id = ? AND slot = ?",
            (reader_id, slot),
        ).fetchone()
        return dict(row) if row else None

    def put_user(self, slot, name, finger="", status="active", reader_id="display1"):
        timestamp = now_iso()
        person_id = self.ensure_person(name)
        if not self.person_access_allowed(person_id):
            raise ValueError("Identity is not active")
        self.connection.execute(
            """
            INSERT INTO users(
                reader_id, slot, name, finger, status, enrolled_at, updated_at, person_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(reader_id, slot) DO UPDATE SET
                name = excluded.name,
                finger = excluded.finger,
                status = excluded.status,
                updated_at = excluded.updated_at,
                person_id = excluded.person_id
            """,
            (reader_id, slot, name, finger, status, timestamp, timestamp, person_id),
        )
        self.connection.commit()

    def activate(self, slot, reader_id="display1"):
        timestamp = now_iso()
        cursor = self.connection.execute(
            """
            UPDATE users SET status = 'active', updated_at = ?
            WHERE reader_id = ? AND slot = ?
            """,
            (timestamp, reader_id, slot),
        )
        if cursor.rowcount == 0:
            self.put_user(slot, f"ID {slot}", "", "active", reader_id)
        else:
            self.connection.commit()

    def remove_user(self, slot, reader_id="display1"):
        self.connection.execute(
            "DELETE FROM users WHERE reader_id = ? AND slot = ?", (reader_id, slot)
        )
        self.connection.commit()

    def queue_delete(self, slot, reader_id="display1"):
        timestamp = now_iso()
        with self.connection:
            self.connection.execute(
                """
                UPDATE users SET status = 'deleting', updated_at = ?
                WHERE reader_id = ? AND slot = ?
                """,
                (timestamp, reader_id, slot),
            )
            self.connection.execute(
                """
                INSERT INTO deletion_queue(
                    reader_id, slot, state, attempts, requested_at, updated_at
                ) VALUES (?, ?, 'queued', 0, ?, ?)
                ON CONFLICT(reader_id, slot) DO UPDATE SET
                    state = CASE
                        WHEN deletion_queue.state = 'sent' THEN deletion_queue.state
                        ELSE 'queued'
                    END,
                    last_error = NULL,
                    updated_at = excluded.updated_at
                """,
                (reader_id, slot, timestamp, timestamp),
            )

    def deletion(self, slot, reader_id="display1"):
        row = self.connection.execute(
            "SELECT * FROM deletion_queue WHERE reader_id = ? AND slot = ?",
            (reader_id, slot),
        ).fetchone()
        return dict(row) if row else None

    def deletions(self):
        rows = self.connection.execute(
            "SELECT * FROM deletion_queue ORDER BY requested_at, reader_id, slot"
        ).fetchall()
        return [dict(row) for row in rows]

    def mark_delete_attempt(self, slot, baseline_count, reader_id="display1"):
        timestamp = now_iso()
        expected_count = max(0, baseline_count - 1)
        self.connection.execute(
            """
            UPDATE deletion_queue SET
                state = 'sent',
                attempts = attempts + 1,
                baseline_count = COALESCE(baseline_count, ?),
                expected_count = COALESCE(expected_count, ?),
                last_error = NULL,
                updated_at = ?
            WHERE reader_id = ? AND slot = ?
            """,
            (baseline_count, expected_count, timestamp, reader_id, slot),
        )
        self.connection.commit()

    def mark_delete_retry(self, slot, error, reader_id="display1"):
        self.connection.execute(
            """
            UPDATE deletion_queue SET state = 'retry', last_error = ?, updated_at = ?
            WHERE reader_id = ? AND slot = ?
            """,
            (str(error)[:240], now_iso(), reader_id, slot),
        )
        self.connection.commit()

    def complete_delete(self, slot, reader_id="display1"):
        deletion = self.deletion(slot, reader_id)
        if not deletion:
            return None
        user = self.user(slot, reader_id)
        person_id = user.get("person_id") if user else None
        with self.connection:
            self.connection.execute(
                "DELETE FROM deletion_queue WHERE reader_id = ? AND slot = ?",
                (reader_id, slot),
            )
            self.connection.execute(
                "DELETE FROM users WHERE reader_id = ? AND slot = ?",
                (reader_id, slot),
            )
            if person_id:
                self.connection.execute(
                    """
                    UPDATE people SET deletion_completed =
                        MIN(deletion_total, deletion_completed + 1),
                        updated_at = ?
                    WHERE id = ? AND status = 'deletion_pending'
                    """,
                    (now_iso(), person_id),
                )
        archived = self.try_archive_person(person_id) if person_id else False
        return (user | {"person_archived": archived}) if user else None

    def recover_person_deletions(self):
        """Restore every durable person deletion after an add-on restart."""
        rows = self.connection.execute(
            "SELECT id, name FROM people WHERE status = 'deletion_pending'"
        ).fetchall()
        archived = []
        for person in rows:
            fingerprints = self.connection.execute(
                "SELECT reader_id, slot FROM users WHERE person_id = ?",
                (person["id"],),
            ).fetchall()
            timestamp = now_iso()
            with self.connection:
                self.connection.execute(
                    "UPDATE keypad_credentials SET status = 'revoked', updated_at = ? "
                    "WHERE person_id = ? AND status != 'revoked'",
                    (timestamp, person["id"]),
                )
                self.connection.execute(
                    "UPDATE mobile_nfc_permissions SET enabled = 0, suspended = 1, "
                    "updated_at = ? WHERE person_id = ?",
                    (timestamp, person["id"]),
                )
                for fingerprint in fingerprints:
                    self.connection.execute(
                        "UPDATE users SET status = 'deleting', updated_at = ? "
                        "WHERE reader_id = ? AND slot = ?",
                        (timestamp, fingerprint["reader_id"], fingerprint["slot"]),
                    )
                    self.connection.execute(
                        """
                        INSERT INTO deletion_queue(
                            reader_id, slot, state, attempts, requested_at, updated_at
                        ) VALUES (?, ?, 'queued', 0, ?, ?)
                        ON CONFLICT(reader_id, slot) DO UPDATE SET
                            state = CASE WHEN deletion_queue.state = 'sent'
                                         THEN 'queued' ELSE deletion_queue.state END,
                            updated_at = excluded.updated_at
                        """,
                        (
                            fingerprint["reader_id"], fingerprint["slot"],
                            timestamp, timestamp,
                        ),
                    )
            if not fingerprints and self.try_archive_person(person["id"]):
                archived.append(person["name"])
        for name in archived:
            self.add_event(
                "person_archived",
                detail=f"{name} · restart recovery",
                source="access_manager",
            )

    def rename_user(self, slot, name, finger, reader_id="display1"):
        user = self.user(slot, reader_id)
        if not user:
            return
        timestamp = now_iso()
        person_id = user.get("person_id") or self.ensure_person(user["name"])
        with self.connection:
            self.connection.execute(
                """
                UPDATE people SET name = ?, normalized_name = ?, updated_at = ?
                WHERE id = ?
                """,
                (name, normalized(name), timestamp, person_id),
            )
            self.connection.execute(
                "UPDATE users SET name = ?, updated_at = ? WHERE person_id = ?",
                (name, timestamp, person_id),
            )
            self.connection.execute(
                """
                UPDATE users SET finger = ?, updated_at = ?
                WHERE reader_id = ? AND slot = ?
                """,
                (finger, timestamp, reader_id, slot),
            )

    def finger_in_use(self, name, finger, reader_id="display1", exclude_slot=None):
        wanted_name = normalized(name)
        for user in self.users(reader_id):
            if exclude_slot is not None and user["slot"] == exclude_slot:
                continue
            if normalized(user["name"]) == wanted_name and user["finger"] == finger:
                return user
        return None

    def person(self, person_id):
        row = self.connection.execute(
            "SELECT * FROM people WHERE id = ?", (person_id,)
        ).fetchone()
        return dict(row) if row else None

    def person_by_name(self, name):
        row = self.connection.execute(
            "SELECT * FROM people WHERE normalized_name = ?", (normalized(name),)
        ).fetchone()
        return dict(row) if row else None

    def people(self):
        people = [
            dict(row) for row in self.connection.execute(
                "SELECT * FROM people WHERE status IN ('active', 'deletion_pending') "
                "ORDER BY name COLLATE NOCASE"
            ).fetchall()
        ]
        fingerprints = self.users()
        keypad_credentials = self.keypad_credentials()
        for person in people:
            person["ha_auto_link_disabled"] = bool(
                person.get("ha_auto_link_disabled")
            )
            person["ha_link_state"] = person.get("ha_link_status", "unknown")
            if person["status"] == "deletion_pending":
                total = int(person.get("deletion_total") or 0)
                done = int(person.get("deletion_completed") or 0)
                person["deletion"] = {
                    "total": total,
                    "done": done,
                    "pending": max(0, total - done),
                    "blocked_readers": [],
                }
            person["credentials"] = []
            for fingerprint in fingerprints:
                if fingerprint.get("person_id") != person["id"]:
                    continue
                person["credentials"].append(
                    {
                        "id": f"fingerprint:{fingerprint['reader_id']}:{fingerprint['slot']}",
                        "type": "fingerprint",
                        "reader_id": fingerprint["reader_id"],
                        "slot": fingerprint["slot"],
                        "finger": fingerprint["finger"],
                        "label": FINGER_LABELS.get(
                            fingerprint["finger"], fingerprint["finger"] or "Dedo sin asignar"
                        ),
                        "status": fingerprint["status"],
                    }
                )
            for credential in keypad_credentials:
                if credential["person_id"] != person["id"]:
                    continue
                legacy_action_scope = int(credential.get("hash_version", 1)) == 1
                ciphertext = credential.get("secret_ciphertext")
                display_value = None
                if ciphertext and not self.privacy_mode():
                    try:
                        display_value = self.decrypt_keypad_secret(ciphertext)
                    except ValueError:
                        display_value = None
                person["credentials"].append(
                    {
                        "id": f"keypad:{credential['id']}",
                        "type": "keypad",
                        "reader_id": credential["reader_id"],
                        "code_hint": credential["code_hint"],
                        "display_value": display_value,
                        "revealable": bool(ciphertext),
                        "label": credential["code_hint"],
                        "keypad_action": credential["keypad_action"],
                        "normalized_action": credential["normalized_action"],
                        "legacy_action_scope": legacy_action_scope,
                        "status": credential["status"],
                    }
                )
        return people

    def create_person(self, name):
        wanted = normalized(name)
        if not wanted:
            raise ValueError("Enter a name")
        existing = self.connection.execute(
            "SELECT id FROM people WHERE normalized_name = ?", (wanted,)
        ).fetchone()
        if existing:
            raise ValueError("A person with that name already exists")
        return self.ensure_person(name)

    def link_ha_person(self, person_id, entity_id):
        person = self.person(person_id)
        if not person:
            raise ValueError("Person not found")
        if person["status"] != "active":
            raise ValueError("Only an active identity can be linked")
        entity_id = str(entity_id).strip()
        if not entity_id.startswith("person."):
            raise ValueError("Invalid Home Assistant Person entity")
        previous = person.get("ha_person_entity_id")
        suspended = 0
        try:
            with self.connection:
                if previous != entity_id:
                    cursor = self.connection.execute(
                        """
                        UPDATE mobile_nfc_permissions
                        SET suspended = CASE WHEN enabled = 1 THEN 1 ELSE suspended END,
                            updated_at = ?
                        WHERE person_id = ? AND enabled = 1
                        """,
                        (now_iso(), person_id),
                    )
                    suspended = cursor.rowcount
                self.connection.execute(
                    """
                    UPDATE people SET ha_person_entity_id = ?,
                        ha_link_status = 'linked', ha_auto_link_disabled = 0,
                        updated_at = ? WHERE id = ?
                    """,
                    (entity_id, now_iso(), person_id),
                )
        except sqlite3.IntegrityError as error:
            raise ValueError(
                "That Home Assistant Person is already linked"
            ) from error
        return {
            "previous_entity_id": previous,
            "ha_person_entity_id": entity_id,
            "suspended_permissions": suspended,
        }

    def unlink_ha_person(self, person_id):
        person = self.person(person_id)
        if not person:
            raise ValueError("Person not found")
        if person["status"] != "active":
            raise ValueError("Only an active identity can be unlinked")
        previous = person.get("ha_person_entity_id")
        with self.connection:
            cursor = self.connection.execute(
                """
                UPDATE mobile_nfc_permissions
                SET suspended = CASE WHEN enabled = 1 THEN 1 ELSE suspended END,
                    updated_at = ?
                WHERE person_id = ? AND enabled = 1
                """,
                (now_iso(), person_id),
            )
            self.connection.execute(
                """
                UPDATE people SET ha_person_entity_id = NULL,
                    ha_link_status = 'unlinked', ha_auto_link_disabled = 1,
                    updated_at = ? WHERE id = ?
                """,
                (now_iso(), person_id),
            )
        return {
            "previous_entity_id": previous,
            "suspended_permissions": cursor.rowcount,
        }

    @staticmethod
    def normalized_ha_people(ha_people):
        result = []
        for item in ha_people or []:
            if not isinstance(item, dict):
                continue
            entity_id = str(item.get("entity_id") or "").strip()
            if not entity_id and item.get("id"):
                entity_id = f"person.{item['id']}"
            if not entity_id.startswith("person."):
                continue
            result.append({
                "entity_id": entity_id,
                "name": str(item.get("name") or entity_id.split(".", 1)[1]),
            })
        return result

    def reconcile_ha_people(self, ha_people, api_ready):
        """Reconcile only against a validated, fresh person/list response."""
        rows = self.connection.execute(
            "SELECT * FROM people WHERE status != 'archived'"
        ).fetchall()
        if not api_ready:
            with self.connection:
                for row in rows:
                    state = (
                        "unknown" if row["ha_person_entity_id"] else "unlinked"
                    )
                    self.connection.execute(
                        "UPDATE people SET ha_link_status = ? WHERE id = ?",
                        (state, row["id"]),
                    )
            return
        items = self.normalized_ha_people(ha_people)
        available = {item["entity_id"]: item for item in items}
        exact = {}
        for entity_id, item in available.items():
            exact.setdefault(normalized(item["name"]), []).append(entity_id)
        timestamp = now_iso()
        with self.connection:
            for row in rows:
                entity_id = row["ha_person_entity_id"]
                if (
                    row["status"] == "active"
                    and not entity_id
                    and not row["ha_auto_link_disabled"]
                ):
                    candidates = exact.get(normalized(row["name"]), [])
                    if len(candidates) == 1:
                        entity_id = candidates[0]
                        try:
                            self.connection.execute(
                                """
                                UPDATE people SET ha_person_entity_id = ?,
                                    updated_at = ? WHERE id = ?
                                """,
                                (entity_id, timestamp, row["id"]),
                            )
                        except sqlite3.IntegrityError:
                            entity_id = None
                state = (
                    "unlinked" if not entity_id
                    else "linked" if entity_id in available
                    else "missing"
                )
                self.connection.execute(
                    "UPDATE people SET ha_link_status = ? WHERE id = ?",
                    (state, row["id"]),
                )

    def auto_link_ha_people(self, ha_people):
        self.reconcile_ha_people(ha_people, True)

    def person_access_allowed(self, person_or_id):
        person = (
            person_or_id if isinstance(person_or_id, dict)
            else self.person(person_or_id)
        )
        return bool(person and person["status"] == "active")

    def mobile_nfc_eligible(self, person_id):
        person = self.person(person_id)
        return bool(
            person
            and person["status"] == "active"
            and person.get("ha_person_entity_id")
            and person.get("ha_link_status") == "linked"
        )

    def person_deletion_preview(self, person_id):
        person = self.person(person_id)
        if not person:
            raise ValueError("Person not found")
        fingerprints = [
            dict(row) for row in self.connection.execute(
                """
                SELECT users.reader_id, users.slot, users.finger, users.status,
                       readers.name AS reader_name, readers.enabled AS reader_enabled
                FROM users
                LEFT JOIN readers ON readers.id = users.reader_id
                WHERE users.person_id = ?
                ORDER BY users.reader_id, users.slot
                """,
                (person_id,),
            ).fetchall()
        ]
        for item in fingerprints:
            item["reader_enabled"] = bool(item.get("reader_enabled"))
            item["deletion"] = self.deletion(
                item["slot"], item["reader_id"]
            )
        keypads = [
            dict(row) for row in self.connection.execute(
                """
                SELECT keypad_credentials.id, keypad_credentials.reader_id,
                       keypad_credentials.code_hint, keypad_credentials.status,
                       readers.name AS reader_name
                FROM keypad_credentials
                LEFT JOIN readers
                    ON readers.id = keypad_credentials.reader_id
                WHERE keypad_credentials.person_id = ?
                ORDER BY keypad_credentials.reader_id, keypad_credentials.id
                """,
                (person_id,),
            ).fetchall()
        ]
        mobile = [
            dict(row) | {
                "enabled": bool(row["enabled"]),
                "suspended": bool(row["suspended"]),
            }
            for row in self.connection.execute(
                """
                SELECT mobile_nfc_permissions.*, doors.name AS door_name
                FROM mobile_nfc_permissions
                LEFT JOIN doors
                    ON doors.id = mobile_nfc_permissions.door_id
                WHERE mobile_nfc_permissions.person_id = ?
                ORDER BY mobile_nfc_permissions.door_id
                """,
                (person_id,),
            ).fetchall()
        ]
        blocked_readers = sorted({
            item["reader_id"] for item in fingerprints
            if not item["reader_enabled"]
            or (
                item.get("deletion")
                and item["deletion"].get("state") == "retry"
            )
        })
        return {
            "person": person,
            "fingerprints": fingerprints,
            "keypad_credentials": keypads,
            "mobile_nfc_permissions": mobile,
            "blocked_readers": blocked_readers,
            "counts": {
                "fingerprints": len(fingerprints),
                "keypad_credentials": len(keypads),
                "mobile_nfc_permissions": len(mobile),
            },
        }

    def begin_person_deletion(self, person_id):
        person = self.person(person_id)
        if not person:
            raise ValueError("Person not found")
        if person["status"] == "archived":
            return self.person_deletion_preview(person_id) | {
                "archived": True
            }
        if person["status"] == "deletion_pending":
            return self.person_deletion_preview(person_id) | {
                "archived": False
            }
        if person["status"] != "active":
            raise ValueError("Identity cannot be deleted")
        preview = self.person_deletion_preview(person_id)
        timestamp = now_iso()
        keypad_count = preview["counts"]["keypad_credentials"]
        mobile_count = preview["counts"]["mobile_nfc_permissions"]
        with self.connection:
            self.connection.execute(
                """
                UPDATE people SET status = 'deletion_pending',
                    deletion_requested_at = ?, deletion_total = ?,
                    deletion_completed = 0, updated_at = ?
                WHERE id = ?
                """,
                (
                    timestamp, len(preview["fingerprints"]),
                    timestamp, person_id,
                ),
            )
            self.connection.execute(
                """
                UPDATE keypad_credentials
                SET status = 'revoked', updated_at = ?
                WHERE person_id = ? AND status != 'revoked'
                """,
                (timestamp, person_id),
            )
            self.connection.execute(
                """
                UPDATE mobile_nfc_permissions
                SET enabled = 0, suspended = 1, updated_at = ?
                WHERE person_id = ?
                """,
                (timestamp, person_id),
            )
            for item in preview["fingerprints"]:
                self.connection.execute(
                    """
                    UPDATE users SET status = 'deleting', updated_at = ?
                    WHERE reader_id = ? AND slot = ?
                    """,
                    (timestamp, item["reader_id"], item["slot"]),
                )
                self.connection.execute(
                    """
                    INSERT INTO deletion_queue(
                        reader_id, slot, state, attempts,
                        requested_at, updated_at
                    )
                    VALUES (?, ?, 'queued', 0, ?, ?)
                    ON CONFLICT(reader_id, slot) DO UPDATE SET
                        state = CASE
                            WHEN deletion_queue.state = 'sent'
                            THEN deletion_queue.state ELSE 'queued'
                        END,
                        last_error = NULL,
                        updated_at = excluded.updated_at
                    """,
                    (
                        item["reader_id"], item["slot"],
                        timestamp, timestamp,
                    ),
                )
        self.add_event(
            "person_deletion_requested",
            detail=(
                f"{person['name']} · "
                f"{len(preview['fingerprints'])} fingerprints"
            ),
            source="access_manager",
        )
        if keypad_count:
            self.add_event(
                "person_keypad_credentials_revoked",
                detail=f"{person['name']} · {keypad_count}",
                source="access_manager",
            )
        if mobile_count:
            self.add_event(
                "person_mobile_nfc_permissions_revoked",
                detail=f"{person['name']} · {mobile_count}",
                source="access_manager",
            )
        archived = self.try_archive_person(person_id)
        return preview | {
            "person": self.person(person_id),
            "archived": archived,
        }

    def try_archive_person(self, person_id):
        if not person_id:
            return False
        person = self.person(person_id)
        if not person or person["status"] != "deletion_pending":
            return False
        remaining = self.connection.execute(
            "SELECT COUNT(*) FROM users WHERE person_id = ?",
            (person_id,),
        ).fetchone()[0]
        if remaining:
            return False
        timestamp = now_iso()
        with self.connection:
            self.connection.execute(
                "DELETE FROM keypad_credentials WHERE person_id = ?",
                (person_id,),
            )
            self.connection.execute(
                "DELETE FROM mobile_nfc_permissions WHERE person_id = ?",
                (person_id,),
            )
            cursor = self.connection.execute(
                """
                UPDATE people SET status = 'archived', archived_at = ?,
                    deletion_completed = deletion_total,
                    ha_person_entity_id = NULL,
                    ha_link_status = 'unlinked',
                    ha_auto_link_disabled = 1, updated_at = ?
                WHERE id = ? AND status = 'deletion_pending'
                """,
                (timestamp, timestamp, person_id),
            )
        return cursor.rowcount > 0

    def rename_person(self, person_id, name):
        person = self.person(person_id)
        if not person or not normalized(name):
            raise ValueError("Invalid person or name")
        if person["status"] != "active":
            raise ValueError("Only an active identity can be renamed")
        timestamp = now_iso()
        with self.connection:
            self.connection.execute(
                """
                UPDATE people SET name = ?, normalized_name = ?, updated_at = ? WHERE id = ?
                """,
                (str(name).strip(), normalized(name), timestamp, person_id),
            )
            self.connection.execute(
                "UPDATE users SET name = ?, updated_at = ? WHERE person_id = ?",
                (str(name).strip(), timestamp, person_id),
            )

    def doors(self):
        doors = []
        for row in self.connection.execute(
            "SELECT * FROM doors ORDER BY name COLLATE NOCASE"
        ).fetchall():
            door = dict(row)
            door["default_action"] = door["open_action"]
            doors.append(door)
        return doors

    def mobile_nfc_tags(self):
        rows = self.connection.execute(
            "SELECT * FROM mobile_nfc_tags ORDER BY name COLLATE NOCASE, tag_id"
        ).fetchall()
        return [dict(row) | {"enabled": bool(row["enabled"])} for row in rows]

    def mobile_nfc_tag(self, tag_id):
        row = self.connection.execute(
            "SELECT * FROM mobile_nfc_tags WHERE tag_id = ?", (str(tag_id),)
        ).fetchone()
        return (dict(row) | {"enabled": bool(row["enabled"])}) if row else None

    def save_mobile_nfc_tag(self, tag_id, name, door_id, enabled=True):
        tag_id = str(tag_id).strip()
        name = str(name).strip()
        if not tag_id or len(tag_id) > 128 or not name or len(name) > 80:
            raise ValueError("Invalid Home Assistant tag")
        if not any(door["id"] == door_id for door in self.doors()):
            raise ValueError("Door not found")
        timestamp = now_iso()
        self.connection.execute(
            """
            INSERT INTO mobile_nfc_tags(tag_id, name, door_id, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(tag_id) DO UPDATE SET
                name = excluded.name,
                door_id = excluded.door_id,
                enabled = excluded.enabled,
                updated_at = excluded.updated_at
            """,
            (tag_id, name, door_id, int(bool(enabled)), timestamp, timestamp),
        )
        self.connection.commit()

    def delete_mobile_nfc_tag(self, tag_id):
        cursor = self.connection.execute(
            "DELETE FROM mobile_nfc_tags WHERE tag_id = ?", (str(tag_id),)
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def mobile_nfc_permissions(self, include_inactive=False):
        where = (
            "" if include_inactive
            else "WHERE enabled = 1 AND suspended = 0"
        )
        rows = self.connection.execute(
            f"""
            SELECT * FROM mobile_nfc_permissions
            {where}
            ORDER BY person_id, door_id
            """
        ).fetchall()
        return [
            dict(row) | {
                "enabled": bool(row["enabled"]),
                "suspended": bool(row["suspended"]),
                "requires_confirmation": bool(
                    row["enabled"] and row["suspended"]
                ),
            }
            for row in rows
        ]

    def mobile_nfc_allowed(self, person_id, door_id):
        row = self.connection.execute(
            """
            SELECT permissions.enabled
            FROM mobile_nfc_permissions AS permissions
            JOIN people ON people.id = permissions.person_id
            WHERE permissions.person_id = ? AND permissions.door_id = ?
              AND permissions.enabled = 1
              AND permissions.suspended = 0
              AND permissions.ha_person_entity_id =
                  people.ha_person_entity_id
              AND people.status = 'active'
              AND people.ha_link_status = 'linked'
            """,
            (person_id, door_id),
        ).fetchone()
        return bool(row and row["enabled"])

    def set_mobile_nfc_permission(self, person_id, door_id, enabled):
        person = self.person(person_id)
        if not person:
            raise ValueError("Person not found")
        if enabled and not self.mobile_nfc_eligible(person_id):
            raise ValueError(
                "Link the user to a confirmed Home Assistant Person first"
            )
        if not any(door["id"] == door_id for door in self.doors()):
            raise ValueError("Door not found")
        timestamp = now_iso()
        self.connection.execute(
            """
            INSERT INTO mobile_nfc_permissions(
                person_id, door_id, enabled, suspended,
                ha_person_entity_id, created_at, updated_at
            ) VALUES (?, ?, ?, 0, ?, ?, ?)
            ON CONFLICT(person_id, door_id) DO UPDATE SET
                enabled = excluded.enabled,
                suspended = 0,
                ha_person_entity_id = excluded.ha_person_entity_id,
                updated_at = excluded.updated_at
            """,
            (
                person_id, door_id, int(bool(enabled)),
                person.get("ha_person_entity_id"), timestamp, timestamp,
            ),
        )
        self.connection.commit()

    def claim_mobile_nfc_event(self, event_id):
        event_id = str(event_id or "").strip()
        if not event_id:
            return True
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO mobile_nfc_event_ids(event_id, occurred_at) VALUES (?, ?)",
                    (event_id, now_iso()),
                )
                self.connection.execute(
                    """
                    DELETE FROM mobile_nfc_event_ids
                    WHERE event_id NOT IN (
                        SELECT event_id FROM mobile_nfc_event_ids
                        ORDER BY occurred_at DESC LIMIT 1000
                    )
                    """
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def doors_for_activity_entity(self, entity_id):
        rows = self.connection.execute(
            """
            SELECT * FROM doors
            WHERE entity_id = ? OR door_sensor_entity = ?
            ORDER BY name COLLATE NOCASE
            """,
            (entity_id, entity_id),
        ).fetchall()
        doors = []
        for row in rows:
            door = dict(row)
            door["default_action"] = door["open_action"]
            doors.append(door)
        return doors

    def readers(self):
        readers = []
        rows = self.connection.execute(
            "SELECT * FROM readers ORDER BY name COLLATE NOCASE"
        ).fetchall()
        for row in rows:
            reader = dict(row)
            try:
                reader["config"] = json.loads(reader.pop("config_json"))
            except (TypeError, json.JSONDecodeError):
                reader["config"] = {}
            reader["enabled"] = bool(reader["enabled"])
            readers.append(reader)
        return readers

    def reader(self, reader_id):
        return next((reader for reader in self.readers() if reader["id"] == reader_id), None)

    def create_door(
        self, door_id, name, entity_id, open_action, door_sensor_entity=""
    ):
        timestamp = now_iso()
        self.connection.execute(
            """
            INSERT INTO doors(
                id, name, entity_id, door_sensor_entity, open_action,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                door_id, name, entity_id, door_sensor_entity, open_action,
                timestamp, timestamp,
            ),
        )
        self.connection.commit()

    def update_door(
        self, door_id, name, entity_id, open_action, door_sensor_entity=None
    ):
        cursor = self.connection.execute(
            """
            UPDATE doors SET name = ?, entity_id = ?,
                   door_sensor_entity = COALESCE(?, door_sensor_entity),
                   open_action = ?, updated_at = ?
            WHERE id = ?
            """,
            (name, entity_id, door_sensor_entity, open_action, now_iso(), door_id),
        )
        self.connection.commit()
        if cursor.rowcount == 0:
            raise ValueError("Door not found")

    def set_door_sensor(self, door_id, door_sensor_entity):
        self.connection.execute(
            "UPDATE doors SET door_sensor_entity = ?, updated_at = ? WHERE id = ?",
            (door_sensor_entity, now_iso(), door_id),
        )
        self.connection.commit()

    def managed_automations(self):
        items = []
        rows = self.connection.execute(
            "SELECT * FROM managed_automations ORDER BY id"
        ).fetchall()
        for row in rows:
            item = dict(row)
            try:
                item["config"] = json.loads(item.pop("config_json"))
            except (TypeError, json.JSONDecodeError):
                item["config"] = {}
            item["enabled"] = bool(item["enabled"])
            items.append(item)
        return items

    def managed_automation(self, automation_id):
        return next(
            (item for item in self.managed_automations() if item["id"] == automation_id),
            None,
        )

    def upsert_managed_automation(
        self, automation_id, automation_type, door_id, ha_config_id, enabled, config,
    ):
        timestamp = now_iso()
        self.connection.execute(
            """
            INSERT INTO managed_automations(
                id, automation_type, door_id, ha_config_id, enabled, config_json,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                automation_type = excluded.automation_type,
                door_id = excluded.door_id,
                ha_config_id = excluded.ha_config_id,
                enabled = excluded.enabled,
                config_json = excluded.config_json,
                updated_at = excluded.updated_at
            """,
            (
                automation_id, automation_type, door_id, ha_config_id,
                1 if enabled else 0, json.dumps(config), timestamp, timestamp,
            ),
        )
        self.connection.commit()

    def delete_managed_automation(self, automation_id):
        cursor = self.connection.execute(
            "DELETE FROM managed_automations WHERE id = ?", (automation_id,)
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def update_reader(self, reader_id, name, door_id, enabled=True, config=None):
        if not self.reader(reader_id):
            raise ValueError("Reader not found")
        if door_id and not any(door["id"] == door_id for door in self.doors()):
            raise ValueError("Door not found")
        if config is None:
            self.connection.execute(
                """
                UPDATE readers SET name = ?, door_id = ?, enabled = ?, updated_at = ?
                WHERE id = ?
                """,
                (name, door_id or None, 1 if enabled else 0, now_iso(), reader_id),
            )
        else:
            self.connection.execute(
                """
                UPDATE readers SET name = ?, door_id = ?, enabled = ?,
                    config_json = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    name, door_id or None, 1 if enabled else 0,
                    json.dumps(config), now_iso(), reader_id,
                ),
            )
        self.connection.commit()

    def create_reader(self, reader_id, name, reader_type, door_id, config, enabled=True):
        if reader_type not in {"fingerprint", "keypad"}:
            raise ValueError("Invalid reader type")
        if door_id and not any(door["id"] == door_id for door in self.doors()):
            raise ValueError("Door not found")
        timestamp = now_iso()
        self.connection.execute(
            """
            INSERT INTO readers(
                id, name, reader_type, door_id, enabled, config_json,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                reader_id, name, reader_type, door_id or None,
                1 if enabled else 0, json.dumps(config), timestamp, timestamp,
            ),
        )
        self.connection.commit()

    def credential_key(self):
        key = self.setting("credential_hmac_key")
        if not key:
            key = secrets.token_hex(32)
            self.set_setting("credential_hmac_key", key)
        return bytes.fromhex(key)

    def credential_cipher(self):
        if self._credential_cipher is not None:
            return self._credential_cipher
        key_path = DATA_DIR / "credential_encryption.key"
        try:
            key = key_path.read_bytes().strip()
        except FileNotFoundError:
            generated = Fernet.generate_key()
            try:
                descriptor = os.open(
                    key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
            except FileExistsError:
                key = key_path.read_bytes().strip()
            else:
                try:
                    os.write(descriptor, generated + b"\n")
                finally:
                    os.close(descriptor)
                key = generated
        try:
            os.chmod(key_path, 0o600)
            self._credential_cipher = Fernet(key)
        except (OSError, ValueError) as error:
            raise RuntimeError("Credential encryption key is invalid") from error
        return self._credential_cipher

    def encrypt_keypad_secret(self, code):
        value = self.clean_keypad_secret(code)
        return self.credential_cipher().encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt_keypad_secret(self, ciphertext):
        if not ciphertext:
            raise ValueError("This credential must be registered again before it can be viewed")
        try:
            return self.credential_cipher().decrypt(
                str(ciphertext).encode("ascii")
            ).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError, ValueError) as error:
            raise ValueError("The encrypted credential could not be read") from error

    def reveal_keypad_credential(self, credential_id):
        row = self.connection.execute(
            "SELECT secret_ciphertext FROM keypad_credentials "
            "WHERE id = ? AND status = 'active'",
            (credential_id,),
        ).fetchone()
        if not row:
            raise LookupError("Credential not found")
        return self.decrypt_keypad_secret(row["secret_ciphertext"])

    def reveal_shared_keypad_credential(self, credential_id):
        row = self.connection.execute(
            "SELECT secret_ciphertext FROM shared_keypad_credentials "
            "WHERE id = ? AND status = 'active'",
            (credential_id,),
        ).fetchone()
        if not row:
            raise LookupError("Shared credential not found")
        return self.decrypt_keypad_secret(row["secret_ciphertext"])

    def privacy_mode(self):
        return self.setting("privacy_mode") != "0"

    def set_privacy_mode(self, enabled):
        self.set_setting("privacy_mode", "1" if enabled else "0")

    @staticmethod
    def clean_keypad_secret(code):
        value = "" if code is None else str(code).strip()
        if (
            not value
            or value.lower() in {"unknown", "unavailable"}
            or len(value) > 128
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise ValueError("Enter a valid code or tag up to 128 characters")
        return value

    def credential_hash(self, reader_id, code):
        value = self.clean_keypad_secret(code)
        message = f"v2\0{reader_id}\0{value}".encode("utf-8")
        return hmac.new(self.credential_key(), message, hashlib.sha256).hexdigest()

    def legacy_credential_hash(self, reader_id, code, keypad_action):
        value = self.clean_keypad_secret(code)
        message = f"{reader_id}\0{value}\0{keypad_action}".encode("utf-8")
        return hmac.new(self.credential_key(), message, hashlib.sha256).hexdigest()

    @staticmethod
    def code_hint(code):
        value = "" if code is None else str(code).strip()
        if value.startswith("+"):
            return f"Tag •••{value[-3:]}"
        return f"Code ••{value[-2:]}" if value else "Code"

    def keypad_credentials(self):
        return [
            dict(row) for row in self.connection.execute(
                """
                SELECT * FROM keypad_credentials WHERE status = 'active'
                ORDER BY reader_id, id
                """
            ).fetchall()
        ]

    def shared_keypad_credentials(self):
        credentials = []
        rows = self.connection.execute(
            """
            SELECT * FROM shared_keypad_credentials WHERE status = 'active'
            ORDER BY label COLLATE NOCASE, reader_id, id
            """
        ).fetchall()
        for row in rows:
            credential = dict(row)
            ciphertext = credential.pop("secret_ciphertext", None)
            credential.pop("secret_hash", None)
            credential["revealable"] = bool(ciphertext)
            credential["display_value"] = None
            if ciphertext and not self.privacy_mode():
                try:
                    credential["display_value"] = self.decrypt_keypad_secret(ciphertext)
                except ValueError:
                    pass
            credentials.append(credential)
        return credentials

    def keypad_digest_in_use(self, reader_id, digest):
        personal = self.connection.execute(
            """
            SELECT 1 FROM keypad_credentials
            WHERE reader_id = ? AND secret_hash = ? AND status = 'active'
            """,
            (reader_id, digest),
        ).fetchone()
        shared = self.connection.execute(
            """
            SELECT 1 FROM shared_keypad_credentials
            WHERE reader_id = ? AND secret_hash = ? AND status = 'active'
            """,
            (reader_id, digest),
        ).fetchone()
        return bool(personal or shared)

    def add_keypad_credential(self, person_id, reader_id, code):
        person = self.person(person_id)
        if not person:
            raise ValueError("Person not found")
        if person["status"] != "active":
            raise ValueError("Identity is not active")
        reader = self.reader(reader_id)
        if not reader or reader["reader_type"] != "keypad":
            raise ValueError("Keypad not found")
        value = self.clean_keypad_secret(code)
        digest = self.credential_hash(reader_id, value)
        if self.keypad_digest_in_use(reader_id, digest):
            raise ValueError("That code or tag is already linked to this keypad")
        timestamp = now_iso()
        try:
            cursor = self.connection.execute(
                """
                INSERT INTO keypad_credentials(
                    person_id, reader_id, secret_hash, hash_version, secret_ciphertext,
                    code_hint, keypad_action, normalized_action, status,
                    created_at, updated_at
                ) VALUES (?, ?, ?, 2, ?, ?, '', '', 'active', ?, ?)
                """,
                (
                    person_id, reader_id, digest,
                    self.encrypt_keypad_secret(value),
                    self.code_hint(value),
                    timestamp, timestamp,
                ),
            )
            self.connection.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError as error:
            raise ValueError("That code or tag is already linked to this keypad") from error

    def add_shared_keypad_credential(self, label, reader_id, code):
        label = str(label or "").strip()
        if not label or len(label) > 80 or any(char in label for char in "\r\n"):
            raise ValueError("Enter a shared credential label up to 80 characters")
        reader = self.reader(reader_id)
        if not reader or reader["reader_type"] != "keypad":
            raise ValueError("Keypad not found")
        value = self.clean_keypad_secret(code)
        digest = self.credential_hash(reader_id, value)
        if self.keypad_digest_in_use(reader_id, digest):
            raise ValueError("That code or tag is already linked to this keypad")
        timestamp = now_iso()
        try:
            cursor = self.connection.execute(
                """
                INSERT INTO shared_keypad_credentials(
                    label, reader_id, secret_hash, hash_version,
                    secret_ciphertext, code_hint, status, created_at, updated_at
                ) VALUES (?, ?, ?, 2, ?, ?, 'active', ?, ?)
                """,
                (
                    label, reader_id, digest, self.encrypt_keypad_secret(value),
                    self.code_hint(value), timestamp, timestamp,
                ),
            )
            self.connection.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError as error:
            raise ValueError("That code or tag is already linked to this keypad") from error

    def find_keypad_credential(self, reader_id, code, keypad_action):
        digest = self.credential_hash(reader_id, code)
        row = self.connection.execute(
            """
            SELECT * FROM keypad_credentials
            WHERE reader_id = ? AND secret_hash = ? AND hash_version = 2
              AND status = 'active'
            """,
            (reader_id, digest),
        ).fetchone()
        if row:
            return dict(row) | {"owner_type": "person"}
        shared = self.connection.execute(
            """
            SELECT * FROM shared_keypad_credentials
            WHERE reader_id = ? AND secret_hash = ? AND hash_version = 2
              AND status = 'active'
            """,
            (reader_id, digest),
        ).fetchone()
        if shared:
            return dict(shared) | {"owner_type": "shared"}
        legacy_digest = self.legacy_credential_hash(
            reader_id, code, keypad_action
        )
        row = self.connection.execute(
            """
            SELECT * FROM keypad_credentials
            WHERE reader_id = ? AND secret_hash = ? AND hash_version = 1
              AND status = 'active'
            """,
            (reader_id, legacy_digest),
        ).fetchone()
        return (dict(row) | {"owner_type": "person"}) if row else None

    def delete_keypad_credential(self, credential_id):
        cursor = self.connection.execute(
            "DELETE FROM keypad_credentials WHERE id = ?", (credential_id,)
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def delete_shared_keypad_credential(self, credential_id):
        cursor = self.connection.execute(
            "DELETE FROM shared_keypad_credentials WHERE id = ?", (credential_id,)
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def add_event(
        self, event_type, slot=None, confidence=None, detail=None, *, door_id=None,
        entity_id=None, source=None, previous_state=None, new_state=None,
    ):
        self.connection.execute(
            """
            INSERT INTO events(
                occurred_at, event_type, slot, confidence, detail, door_id,
                entity_id, source, previous_state, new_state
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now_iso(), event_type, slot, confidence, detail, door_id,
                entity_id, source, previous_state, new_state,
            ),
        )
        self.purge_events(commit=False)
        self.connection.commit()

    def events(self, limit=200):
        rows = self.connection.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]

    def log_retention_days(self):
        try:
            value = int(self.setting("log_retention_days") or 30)
        except (TypeError, ValueError):
            value = 30
        return value if value in {1, 7, 14, 30, 90, 180, 365} else 30

    def set_log_retention_days(self, days):
        days = int(days)
        if days not in {1, 7, 14, 30, 90, 180, 365}:
            raise ValueError("Unsupported log retention period")
        self.set_setting("log_retention_days", str(days))
        self.purge_events()

    def purge_events(self, commit=True):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.log_retention_days())).isoformat(
            timespec="seconds"
        )
        self.connection.execute("DELETE FROM events WHERE occurred_at < ?", (cutoff,))
        self.connection.execute(
            "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 10000)"
        )
        if commit:
            self.connection.commit()

    def setting(self, key):
        row = self.connection.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_setting(self, key, value):
        self.connection.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        self.connection.commit()


class HomeAssistant:
    def __init__(self, registry):
        self.registry = registry
        self.session = None
        self.states = {}
        self.entities = {}
        self.connected = False
        self.management_message = ""
        self.names_synced = False
        self.state_change_handler = None
        self.tag_scan_handler = None
        self.people_api_ready = False
        self.people_storage = []
        self.people_storage_refreshed_at = 0.0
        self.people_storage_refreshed_iso = None
        self.people_refresh_attempted_at = 0.0
        self.people_refresh_task = None
        self.tags_api_ready = False
        self.tags_storage = []
        self.tags_storage_refreshed_at = None
        self.tag_refresh_task = None
        self.tag_scan_tasks = set()
        self.recent_door_commands = {}

    async def start(self):
        if not TOKEN:
            raise RuntimeError("SUPERVISOR_TOKEN is unavailable")
        self.session = ClientSession(
            headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
            timeout=ClientTimeout(total=15),
        )
        try:
            await self.refresh_states()
            await self.replay_current_events()
            await self.sync_all_names()
            await self.sync_all_reader_doors()
            await self.refresh_people_storage_safely()
            try:
                await self.refresh_tags_storage()
                self.tags_api_ready = True
                LOGGER.info("Home Assistant Tag registry is available")
            except Exception as error:
                self.tags_api_ready = False
                LOGGER.warning("Home Assistant Tag registry is unavailable: %s", error)
        except Exception as error:
            self.connected = False
            LOGGER.warning("Home Assistant is not available yet: %s", error)

    async def close(self):
        if self.people_refresh_task:
            self.people_refresh_task.cancel()
            await asyncio.gather(
                self.people_refresh_task, return_exceptions=True
            )
            self.people_refresh_task = None
        if self.tag_refresh_task:
            self.tag_refresh_task.cancel()
            await asyncio.gather(self.tag_refresh_task, return_exceptions=True)
            self.tag_refresh_task = None
        for task in self.tag_scan_tasks:
            task.cancel()
        if self.tag_scan_tasks:
            await asyncio.gather(*self.tag_scan_tasks, return_exceptions=True)
        self.tag_scan_tasks.clear()
        if self.session:
            await self.session.close()

    async def request(self, method, path, payload=None, allow_not_found=False):
        async with self.session.request(method, f"{HA_API}{path}", json=payload) as response:
            body = await response.text()
            if allow_not_found and response.status == 404:
                return None
            if response.status >= 400:
                raise RuntimeError(f"Home Assistant returned {response.status}: {body[:300]}")
            if not body:
                return None
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                return body

    async def refresh_states(self):
        items = await self.request("GET", "/states")
        self.states = {item["entity_id"]: item for item in items}
        self.resolve_entities()
        self.connected = True

    async def replay_current_events(self):
        for reader in self.registry.readers():
            if reader["reader_type"] != "fingerprint" or not reader["enabled"]:
                continue
            access_id = self.reader_entity(reader["id"], "access_event", required=False)
            management_id = self.reader_entity(reader["id"], "management_event", required=False)
            if access_id and access_id in self.states:
                # Prime the deduplication value without executing a stale access
                # event after an add-on restart.
                current_access = self.states[access_id].get("state", "")
                if current_access:
                    self.registry.set_setting(
                        f"last_access_event:{reader['id']}", current_access
                    )
            if management_id and management_id in self.states:
                await self.process_management_event(
                    self.states[management_id].get("state", ""), reader["id"]
                )

    def resolve_entities(self):
        resolved = {}
        for key, labels in LABELS.items():
            domain = DOMAINS[key]
            candidates = []
            for entity_id, state in self.states.items():
                if not entity_id.startswith(f"{domain}."):
                    continue
                friendly = normalized(state.get("attributes", {}).get("friendly_name"))
                object_id = normalized(entity_id.split(".", 1)[1].replace("_", " "))
                for label in labels:
                    wanted = normalized(label)
                    if friendly.endswith(wanted) or object_id.endswith(wanted):
                        candidates.append(entity_id)
                        break
            if candidates:
                candidates.sort(key=lambda value: ("display1" not in value, len(value)))
                resolved[key] = candidates[0]
        self.entities = resolved

    async def call_service(self, domain, service, payload):
        return await self.request("POST", f"/services/{domain}/{service}", payload)

    async def automation_config(self, config_id):
        return await self.request(
            "GET", f"/config/automation/config/{config_id}",
            allow_not_found=True,
        )

    async def save_automation_config(self, config_id, config):
        return await self.request(
            "POST", f"/config/automation/config/{config_id}", config
        )

    async def delete_automation_config(self, config_id):
        return await self.request(
            "DELETE", f"/config/automation/config/{config_id}"
        )

    def automation_entity_id(self, config_id):
        for entity_id, state in self.states.items():
            if not entity_id.startswith("automation."):
                continue
            if str(state.get("attributes", {}).get("id", "")) == str(config_id):
                return entity_id
        return None

    def door_actions(self, entity_id):
        domain = str(entity_id).split(".", 1)[0]
        actions = list(DOOR_ACTIONS.get(domain, ()))
        if domain != "lock" or "open" not in actions:
            return actions
        state = self.states.get(entity_id, {})
        attributes = state.get("attributes", {})
        try:
            supported_features = int(attributes.get("supported_features", 0))
        except (TypeError, ValueError):
            supported_features = 0
        if not supported_features & LOCK_OPEN_FEATURE:
            actions.remove("open")
        return actions

    async def execute_door_action(self, door, action):
        entity_id = door.get("entity_id") if door else None
        if not entity_id or entity_id not in self.states:
            raise RuntimeError("The configured door entity is unavailable")
        allowed = self.door_actions(entity_id)
        if action not in allowed:
            raise RuntimeError(
                f"Action {action or '(empty)'} is not supported by {entity_id}"
            )
        domain = entity_id.split(".", 1)[0]
        expected_states = {
            "open": {"open", "unlocked"},
            "unlock": {"open", "unlocked"},
            "lock": {"locked"},
        }.get(action, set())
        if expected_states:
            self.recent_door_commands[entity_id] = {
                "expected_states": expected_states,
                "created_at": asyncio.get_running_loop().time(),
            }
        try:
            await self.call_service(domain, action, {"entity_id": entity_id})
        except Exception:
            self.recent_door_commands.pop(entity_id, None)
            raise

    def door_change_source(self, entity_id, new_state):
        now = asyncio.get_running_loop().time()
        expired = [
            pending_entity
            for pending_entity, command in self.recent_door_commands.items()
            if now - command["created_at"] > DOOR_COMMAND_CORRELATION_SECONDS
        ]
        for pending_entity in expired:
            self.recent_door_commands.pop(pending_entity, None)
        command = self.recent_door_commands.get(entity_id)
        if command and new_state in command["expected_states"]:
            self.recent_door_commands.pop(entity_id, None)
            return "access_manager"
        return "external"

    async def emit_door_action_event(
        self, door, action, source, event_id, reader=None, local_only=False,
    ):
        reader_id = reader.get("id") if reader else None
        payload = {
            "event_id": str(event_id),
            "door_id": door.get("id") if door else None,
            "door_entity_id": door.get("entity_id") if door else None,
            "reader_id": reader_id,
            "reader_type": reader.get("reader_type") if reader else None,
            "source": source,
            "action": str(action or "").strip().lower(),
            "action_executed": False,
            "action_error": None,
        }
        try:
            if not door:
                raise RuntimeError("The reader has no door assigned")
            if local_only and payload["action"] not in LOCAL_UNAUTHENTICATED_ACTIONS:
                raise RuntimeError("Unauthenticated local controls may only lock a door")
            await self.execute_door_action(door, payload["action"])
            payload["action_executed"] = True
            event_type = (
                "local_lock_succeeded" if source == "display" else "door_test_succeeded"
            )
            detail = f"{door['name']} · {payload['action']}"
            if reader:
                detail += f" · {reader['name']}"
            self.registry.add_event(event_type, detail=detail)
        except Exception as error:
            payload["action_error"] = str(error)[:240]
            event_type = (
                "local_lock_failed" if source == "display" else "door_test_failed"
            )
            door_name = door.get("name") if door else "Unassigned door"
            detail = f"{door_name} · {payload['action']} · {error}"
            if reader:
                detail += f" · {reader['name']}"
            self.registry.add_event(event_type, detail=detail)
            LOGGER.error(
                "Door action failed: source=%s door=%s reader=%s action=%s error=%s",
                source, payload["door_id"], reader_id, payload["action"], error,
            )
        await self.fire_event("access_manager_door_action", payload)
        if payload["action_executed"] and payload["action"] in DISPLAY_OPENING_ACTIONS:
            await self.emit_display_event(
                payload["door_id"], "door_opened", payload["event_id"],
                reader["name"] if reader else door["name"],
            )
        return payload

    async def fire_event(self, event_type, payload):
        return await self.request("POST", f"/events/{event_type}", payload)

    async def websocket_command(self, command):
        async with self.session.ws_connect(HA_WS, heartbeat=30) as socket:
            message = await socket.receive_json()
            if message.get("type") != "auth_required":
                raise RuntimeError("Unexpected WebSocket response")
            await socket.send_json({"type": "auth", "access_token": TOKEN})
            message = await socket.receive_json()
            if message.get("type") != "auth_ok":
                raise RuntimeError("Home Assistant rejected WebSocket authentication")
            await socket.send_json({"id": 1, **command})
            while True:
                message = await socket.receive_json()
                if message.get("id") != 1:
                    continue
                if not message.get("success"):
                    error = message.get("error", {}).get("message", "Error WebSocket")
                    raise RuntimeError(error)
                return message.get("result")

    def ha_people(self):
        people = []
        for entity_id, state in self.states.items():
            if not entity_id.startswith("person."):
                continue
            people.append(
                {
                    "entity_id": entity_id,
                    "name": state.get("attributes", {}).get("friendly_name")
                    or entity_id.split(".", 1)[1],
                    "state": state.get("state"),
                    "picture": state.get("attributes", {}).get("entity_picture"),
                }
            )
        return sorted(people, key=lambda item: normalized(item["name"]))

    def ha_tags(self):
        tags = {}
        for item in self.tags_storage:
            tag_id = str(item.get("id", item.get("tag_id", ""))).strip()
            if not tag_id:
                continue
            tags[tag_id] = {
                "tag_id": tag_id,
                "name": str(item.get("name") or tag_id),
                "entity_id": None,
            }
        for entity_id, state in self.states.items():
            if not entity_id.startswith("tag."):
                continue
            attributes = state.get("attributes", {})
            tag_id = str(attributes.get("tag_id", "")).strip()
            if not tag_id:
                continue
            tags.setdefault(tag_id, {
                "tag_id": tag_id,
                "name": attributes.get("friendly_name") or entity_id.split(".", 1)[1],
                "entity_id": entity_id,
            })
        return sorted(tags.values(), key=lambda item: normalized(item["name"]))

    async def refresh_tags_storage(self):
        result = await self.websocket_command({"type": "tag/list"})
        if not isinstance(result, list):
            raise RuntimeError("Home Assistant returned an invalid Tag registry response")
        self.tags_storage = [item for item in result if isinstance(item, dict)]
        self.tags_storage_refreshed_at = asyncio.get_running_loop().time()
        self.tags_api_ready = True
        return self.tags_storage

    async def refresh_tags_storage_safely(self):
        try:
            await self.refresh_tags_storage()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.tags_api_ready = False
            LOGGER.warning("Could not refresh Home Assistant Tags: %s", error)
        finally:
            self.tag_refresh_task = None

    def schedule_tags_refresh(self):
        now = asyncio.get_running_loop().time()
        if (
            self.tag_refresh_task
            or (
                self.tags_storage_refreshed_at is not None
                and now - self.tags_storage_refreshed_at < 60
            )
        ):
            return
        # Set the timestamp before starting so a failing API cannot be retried
        # on every panel poll.
        self.tags_storage_refreshed_at = now
        self.tag_refresh_task = asyncio.create_task(
            self.refresh_tags_storage_safely()
        )

    async def refresh_people_storage(self):
        result = await self.websocket_command({"type": "person/list"})
        if isinstance(result, dict):
            items = []
            for key in ("storage", "config"):
                group = result.get(key, [])
                if not isinstance(group, list):
                    raise RuntimeError(
                        "Home Assistant returned an invalid People response"
                    )
                items.extend(group)
        elif isinstance(result, list):
            items = result
        else:
            items = None
        if not isinstance(items, list):
            raise RuntimeError(
                "Home Assistant returned an invalid People response"
            )
        self.people_storage = [
            item for item in items if isinstance(item, dict)
        ]
        self.people_storage_refreshed_at = (
            asyncio.get_running_loop().time()
        )
        self.people_storage_refreshed_iso = now_iso()
        self.people_api_ready = True
        return self.people_storage

    def storage_people(self):
        result = []
        for item in self.people_storage:
            person_id = str(item.get("id", "")).strip()
            if not person_id:
                continue
            entity_id = f"person.{person_id}"
            state = self.states.get(entity_id, {})
            result.append({
                "entity_id": entity_id,
                "name": str(
                    item.get("name")
                    or state.get("attributes", {}).get("friendly_name")
                    or person_id
                ),
                "state": state.get("state"),
                "picture": (
                    item.get("picture")
                    or state.get("attributes", {}).get("entity_picture")
                ),
            })
        return sorted(
            result, key=lambda item: normalized(item["name"])
        )

    async def refresh_people_storage_safely(self):
        self.people_refresh_attempted_at = (
            asyncio.get_running_loop().time()
        )
        try:
            await self.refresh_people_storage()
            self.people_api_ready = True
            self.registry.reconcile_ha_people(
                self.storage_people(), True
            )
            LOGGER.info(
                "Home Assistant People integration is available"
            )
            return True
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.people_api_ready = False
            self.registry.reconcile_ha_people([], False)
            LOGGER.warning(
                "Home Assistant People API is unavailable: %s", error
            )
            return False
        finally:
            self.people_refresh_task = None

    async def ensure_people_storage_fresh(self, max_age=60):
        now = asyncio.get_running_loop().time()
        if (
            self.people_api_ready
            and self.people_storage_refreshed_at
            and now - self.people_storage_refreshed_at < max_age
        ):
            return True
        if self.people_refresh_task:
            return await asyncio.shield(self.people_refresh_task)
        if (
            self.people_refresh_attempted_at
            and now - self.people_refresh_attempted_at < 10
        ):
            self.registry.reconcile_ha_people([], False)
            return False
        self.people_refresh_task = asyncio.create_task(
            self.refresh_people_storage_safely()
        )
        return await asyncio.shield(self.people_refresh_task)

    async def access_person_for_user_id(self, user_id):
        user_id = str(user_id or "").strip()
        if not user_id:
            return None
        now = asyncio.get_running_loop().time()
        item = next(
            (candidate for candidate in self.people_storage if candidate.get("user_id") == user_id),
            None,
        )
        refresh_after = 60
        if now - self.people_storage_refreshed_at >= refresh_after:
            await self.refresh_people_storage_safely()
            item = next(
                (candidate for candidate in self.people_storage if candidate.get("user_id") == user_id),
                None,
            )
        if not item or not item.get("id"):
            return None
        entity_id = f"person.{item['id']}"
        person = next(
            (
                person for person in self.registry.people()
                if person.get("ha_person_entity_id") == entity_id
            ),
            None,
        )
        return (
            person
            if (
                person
                and person.get("status") == "active"
                and person.get("ha_link_status") == "linked"
            )
            else None
        )

    async def dispatch_tag_scan(self, event):
        if not self.tag_scan_handler:
            return
        try:
            await self.tag_scan_handler(event)
        except asyncio.CancelledError:
            raise
        except Exception:
            LOGGER.exception("Unexpected error while processing a mobile NFC scan")

    def schedule_tag_scan(self, event):
        task = asyncio.create_task(self.dispatch_tag_scan(event))
        self.tag_scan_tasks.add(task)
        task.add_done_callback(self.tag_scan_tasks.discard)

    def door_entities(self):
        result = []
        for entity_id, state in self.states.items():
            domain = entity_id.split(".", 1)[0]
            actions = self.door_actions(entity_id)
            if not actions:
                continue
            result.append(
                {
                    "entity_id": entity_id,
                    "name": state.get("attributes", {}).get("friendly_name") or entity_id,
                    "domain": domain,
                    "state": state.get("state"),
                    "actions": list(actions),
                }
            )
        return sorted(result, key=lambda item: normalized(item["name"]))

    def is_door_sensor(self, entity_id):
        state = self.states.get(entity_id)
        return bool(
            state
            and str(entity_id).startswith("binary_sensor.")
            and str(state.get("attributes", {}).get("device_class", "")).lower()
            == "door"
        )

    def door_sensor_entities(self):
        result = []
        for entity_id, state in self.states.items():
            if not self.is_door_sensor(entity_id):
                continue
            result.append(
                {
                    "entity_id": entity_id,
                    "name": state.get("attributes", {}).get("friendly_name") or entity_id,
                    "state": state.get("state"),
                }
            )
        return sorted(result, key=lambda item: normalized(item["name"]))

    def notification_entities(self):
        result = []
        for entity_id, state in self.states.items():
            if not str(entity_id).startswith("notify."):
                continue
            result.append(
                {
                    "entity_id": entity_id,
                    "name": state.get("attributes", {}).get("friendly_name") or entity_id,
                    "state": state.get("state"),
                }
            )
        return sorted(result, key=lambda item: normalized(item["name"]))

    def is_notification_entity(self, entity_id):
        return not entity_id or (
            str(entity_id).startswith("notify.") and entity_id in self.states
        )

    def manageable_entities(self):
        allowed = {"number", "button", "text", "sensor", "binary_sensor"}
        result = []
        for entity_id, state in self.states.items():
            domain = entity_id.split(".", 1)[0]
            if domain not in allowed:
                continue
            result.append(
                {
                    "entity_id": entity_id,
                    "name": state.get("attributes", {}).get("friendly_name") or entity_id,
                    "domain": domain,
                    "state": state.get("state"),
                }
            )
        return sorted(result, key=lambda item: normalized(item["name"]))

    async def create_ha_person(self, name):
        result = await self.websocket_command(
            {
                "type": "person/create",
                "name": name,
                "device_trackers": [],
            }
        )
        person_id = result.get("id") if isinstance(result, dict) else None
        if not person_id:
            raise RuntimeError("Home Assistant did not return the Person ID")
        await self.refresh_states()
        await self.refresh_people_storage_safely()
        return f"person.{person_id}"

    async def update_ha_person(self, entity_id, name):
        person_id = str(entity_id).split(".", 1)[-1]
        result = await self.websocket_command({"type": "person/list"})
        items = result.get("storage", []) if isinstance(result, dict) else []
        item = next((candidate for candidate in items if candidate.get("id") == person_id), None)
        if not item:
            raise RuntimeError("The Home Assistant Person cannot be edited")
        command = {
            "type": "person/update",
            "person_id": person_id,
            "name": name,
            "user_id": item.get("user_id"),
            "device_trackers": item.get("device_trackers", []),
            "picture": item.get("picture"),
        }
        await self.websocket_command(command)
        await self.refresh_states()
        await self.refresh_people_storage_safely()

    async def emit_credential_event(
        self, reader_id, person, credential_type, credential_id, action,
        source_event, authorized=True, credential_label=None,
    ):
        reader = self.registry.reader(reader_id)
        if person and not self.registry.person_access_allowed(person):
            authorized = False
        if not reader or not reader.get("enabled") or not reader.get("door_id"):
            LOGGER.warning("Reader %s has no active door assigned", reader_id)
            return
        payload = {
            "event_id": f"{reader_id}:{source_event}",
            "door_id": reader["door_id"],
            "reader_id": reader_id,
            "reader_type": reader["reader_type"],
            "person_id": person["id"] if person else None,
            "person_name": person["name"] if person else None,
            "ha_person_entity_id": person.get("ha_person_entity_id") if person else None,
            "credential_type": credential_type,
            "credential_id": str(credential_id),
            "credential_label": str(credential_label) if credential_label else None,
            "action": action,
            "authorized": bool(authorized),
        }
        door = next(
            (item for item in self.registry.doors() if item["id"] == reader["door_id"]),
            None,
        )
        requested_action = str(action or "default").strip().lower()
        default_action = door.get("default_action") if door else None
        resolved_action = (
            default_action if requested_action in {"", "default"} else requested_action
        )
        payload["requested_action"] = requested_action or "default"
        payload["action"] = resolved_action
        payload["door_entity_id"] = door.get("entity_id") if door else None
        payload["door_default_action"] = default_action
        payload["door_open_action"] = default_action
        payload["action_executed"] = False
        payload["action_error"] = None
        if authorized and door:
            try:
                await self.execute_door_action(door, resolved_action)
                payload["action_executed"] = True
                self.registry.add_event(
                    "door_action_executed",
                    detail=f"{door['name']} · {resolved_action}",
                )
            except Exception as error:
                payload["action_error"] = str(error)[:240]
                self.registry.add_event(
                    "door_action_failed",
                    detail=f"{door['name']} · {resolved_action} · {error}",
                )
                LOGGER.error(
                    "Door action failed: door=%s entity=%s action=%s error=%s",
                    door["id"], door.get("entity_id"), resolved_action, error,
                )
        await self.fire_event("access_manager_credential", payload)
        if payload["action_executed"] and resolved_action in DISPLAY_OPENING_ACTIONS:
            await self.emit_display_event(
                payload["door_id"], "door_opened", payload["event_id"],
                payload["person_name"] or payload["credential_label"] or reader["name"],
            )
        elif not payload["authorized"] and credential_type == "keypad":
            await self.emit_display_event(
                payload["door_id"], "keypad_denied", payload["event_id"],
                reader["name"],
            )
        LOGGER.info(
            "Access event emitted: door=%s reader=%s owner=%s action=%s executed=%s",
            payload["door_id"], reader_id,
            payload["person_name"] or payload["credential_label"],
            resolved_action, payload["action_executed"],
        )
        return payload

    def reader_entity(self, reader_id, key, required=True):
        reader = self.registry.reader(reader_id)
        if not reader or reader["reader_type"] != "fingerprint":
            if required:
                raise RuntimeError("Fingerprint reader not found")
            return None
        if reader.get("config", {}).get("legacy_autodiscovery"):
            entity_id = self.entities.get(key)
        else:
            config_key = {
                "slot": "slot_entity",
                "enroll": "enroll_entity",
                "cancel": "cancel_entity",
                "delete": "delete_entity",
                "name_registry": "name_registry_entity",
                "access_event": "access_event_entity",
                "management_event": "management_event_entity",
                "assigned_door": "assigned_door_entity",
                "display_event": "display_event_entity",
                "fingerprint_count": "fingerprint_count_entity",
                "reader_capacity": "reader_capacity_entity",
                "reader_status": "reader_status_entity",
                "device_status": "device_status_entity",
            }.get(key, f"{key}_entity")
            entity_id = reader.get("config", {}).get(config_key)
        if required and not entity_id:
            raise RuntimeError(f"Missing {key} entity for reader {reader_id}")
        return entity_id

    def reader_ready(self, reader_id):
        return all(
            self.reader_entity(reader_id, key, required=False) in self.states
            for key in ("slot", "enroll", "cancel", "delete", "name_registry")
        )

    async def set_slot(self, slot, reader_id="display1"):
        entity_id = self.reader_entity(reader_id, "slot")
        domain = entity_id.split(".", 1)[0]
        await self.call_service(domain, "set_value", {"entity_id": entity_id, "value": slot})

    async def press(self, key, reader_id="display1"):
        entity_id = self.reader_entity(reader_id, key)
        domain = entity_id.split(".", 1)[0]
        await self.call_service(domain, "press", {"entity_id": entity_id})

    @staticmethod
    def clean_name(name):
        value = (
            str(name)
            .replace("|", " ")
            .replace("\r", " ")
            .replace("\n", " ")
            .replace("\t", " ")
            .strip()[:24]
        )
        encoded = value.encode("utf-8")[:48]
        while encoded:
            try:
                return encoded.decode("utf-8")
            except UnicodeDecodeError:
                encoded = encoded[:-1]
        return ""

    async def sync_name(self, slot, name, finger="", reader_id="display1"):
        entity_id = self.reader_entity(reader_id, "name_registry")
        clean_name = self.clean_name(name)
        if not clean_name:
            raise RuntimeError("Name cannot be empty")
        await self.call_service(
            entity_id.split(".", 1)[0],
            "set_value",
            {
                "entity_id": entity_id,
                "value": f"set|{int(slot)}|{clean_name}|{finger}",
            },
        )

    @staticmethod
    def clean_display_field(value, max_bytes=48):
        text = (
            str(value or "")
            .replace("|", " ")
            .replace("\n", " ")
            .replace("\r", " ")
            .replace("\t", " ")
            .strip()
        )
        encoded = text.encode("utf-8")[:max_bytes]
        while encoded:
            try:
                return encoded.decode("utf-8")
            except UnicodeDecodeError:
                encoded = encoded[:-1]
        return ""

    async def sync_reader_door(self, reader_id):
        reader = self.registry.reader(reader_id)
        if not reader or reader["reader_type"] != "fingerprint":
            return False
        entity_id = self.reader_entity(reader_id, "assigned_door", required=False)
        if not entity_id or entity_id not in self.states:
            return False
        door_id = self.clean_display_field(reader.get("door_id"), max_bytes=64)
        if str(self.states[entity_id].get("state", "")) == door_id:
            return True
        try:
            await self.call_service(
                entity_id.split(".", 1)[0], "set_value",
                {"entity_id": entity_id, "value": door_id},
            )
            self.states[entity_id]["state"] = door_id
            return True
        except Exception as error:
            LOGGER.warning(
                "Could not synchronize door %s to display reader %s: %s",
                door_id or "(none)", reader_id, error,
            )
            return False

    async def sync_all_reader_doors(self):
        for reader in self.registry.readers():
            if reader["reader_type"] == "fingerprint":
                await self.sync_reader_door(reader["id"])

    async def emit_display_event(self, door_id, kind, event_id, detail=""):
        if kind not in DISPLAY_EVENT_KINDS or not door_id:
            return 0
        clean_event_id = self.clean_display_field(event_id, max_bytes=48)
        clean_door_id = self.clean_display_field(door_id, max_bytes=64)
        clean_detail = self.clean_display_field(detail, max_bytes=48)
        if not clean_event_id or not clean_door_id:
            return 0
        value = f"v1|{clean_event_id}|{clean_door_id}|{kind}|{clean_detail}"
        delivered = 0
        for reader in self.registry.readers():
            if (
                reader["reader_type"] != "fingerprint"
                or not reader["enabled"]
                or reader.get("door_id") != door_id
            ):
                continue
            display_entity = self.reader_entity(
                reader["id"], "display_event", required=False
            )
            if not display_entity or display_entity not in self.states:
                continue
            if not await self.sync_reader_door(reader["id"]):
                continue
            try:
                await self.call_service(
                    display_entity.split(".", 1)[0], "set_value",
                    {"entity_id": display_entity, "value": value},
                )
                delivered += 1
            except Exception as error:
                LOGGER.warning(
                    "Could not send display event %s to reader %s: %s",
                    kind, reader["id"], error,
                )
        return delivered

    async def sync_all_names(self):
        if self.names_synced:
            return
        for user in self.registry.users():
            entity_id = self.reader_entity(user["reader_id"], "name_registry", required=False)
            if (
                entity_id in self.states
                and user["status"] == "active"
                and 1 <= user["slot"] <= 50
            ):
                await self.sync_name(
                    user["slot"], user["name"], user["finger"], user["reader_id"]
                )
        self.names_synced = True
        LOGGER.info("Active names synchronized to ESP local memory")

    def device_online(self, reader_id="display1"):
        entity_id = self.reader_entity(reader_id, "device_status", required=False)
        state = self.states.get(entity_id, {}) if entity_id else {}
        if entity_id:
            return self.connected and state.get("state") == "on"
        access_id = self.reader_entity(reader_id, "access_event", required=False)
        return self.connected and access_id in self.states and self.states[access_id].get("state") != "unavailable"

    def fingerprint_count(self, reader_id="display1"):
        entity_id = self.reader_entity(reader_id, "fingerprint_count", required=False)
        state = self.states.get(entity_id, {}) if entity_id else {}
        try:
            return int(round(float(state.get("state"))))
        except (TypeError, ValueError):
            return None

    async def websocket_loop(self):
        while True:
            try:
                await self.refresh_states()
                await self.replay_current_events()
                await self.sync_all_names()
                await self.sync_all_reader_doors()
                async with self.session.ws_connect(HA_WS, heartbeat=30) as socket:
                    message = await socket.receive_json()
                    if message.get("type") != "auth_required":
                        raise RuntimeError("Unexpected WebSocket response")
                    await socket.send_json({"type": "auth", "access_token": TOKEN})
                    message = await socket.receive_json()
                    if message.get("type") != "auth_ok":
                        raise RuntimeError("Home Assistant rejected WebSocket authentication")
                    await socket.send_json({"id": 1, "type": "subscribe_events", "event_type": "state_changed"})
                    await socket.send_json({"id": 2, "type": "subscribe_events", "event_type": "tag_scanned"})
                    self.connected = True
                    LOGGER.info("Connected to Home Assistant WebSocket")
                    async for message in socket:
                        if message.type != WSMsgType.TEXT:
                            continue
                        payload = json.loads(message.data)
                        if payload.get("type") != "event":
                            continue
                        event = payload.get("event", {})
                        if payload.get("id") == 2 or event.get("event_type") == "tag_scanned":
                            if self.tag_scan_handler:
                                self.schedule_tag_scan(event)
                            continue
                        data = event.get("data", {})
                        entity_id = data.get("entity_id")
                        old_state = data.get("old_state")
                        state = data.get("new_state")
                        if not entity_id or not state:
                            continue
                        self.states[entity_id] = state
                        if entity_id not in self.entities.values():
                            self.resolve_entities()
                        for reader in self.registry.readers():
                            if reader["reader_type"] != "fingerprint" or not reader["enabled"]:
                                continue
                            if entity_id == self.reader_entity(
                                reader["id"], "access_event", required=False
                            ):
                                await self.process_access_event(
                                    state.get("state", ""), reader["id"]
                                )
                            elif entity_id == self.reader_entity(
                                reader["id"], "management_event", required=False
                            ):
                                await self.process_management_event(
                                    state.get("state", ""), reader["id"]
                                )
                        if self.state_change_handler:
                            asyncio.create_task(
                                self.state_change_handler(entity_id, state, old_state)
                            )
            except asyncio.CancelledError:
                raise
            except Exception as error:
                self.connected = False
                LOGGER.warning("Home Assistant connection interrupted: %s", error)
                await asyncio.sleep(5)

    @staticmethod
    def parse_event(raw):
        parts = str(raw).split("|")
        if len(parts) < 2:
            return None
        result = {"kind": parts[0], "sequence": parts[1], "raw": raw}
        try:
            result["slot"] = int(parts[2]) if len(parts) > 2 else None
        except ValueError:
            result["slot"] = None
        try:
            result["value"] = int(parts[3]) if len(parts) > 3 else None
        except ValueError:
            result["value"] = None
        if result["kind"] == "local_action":
            requested_action = parts[2].strip().lower() if len(parts) > 2 else "invalid"
        else:
            requested_action = parts[4].strip().lower() if len(parts) > 4 else "default"
        result["action"] = (
            requested_action if requested_action in READER_REQUESTED_ACTIONS else "invalid"
        )
        return result

    async def process_access_event(self, raw, reader_id="display1"):
        setting_key = f"last_access_event:{reader_id}"
        if not raw or self.registry.setting(setting_key) == raw:
            return
        event = self.parse_event(raw)
        if not event:
            return
        # Claim the monotonic reader event before any side effect. If firing the
        # HA audit event fails after the lock service succeeds, reconnecting must
        # not execute the same physical action a second time.
        self.registry.set_setting(setting_key, raw)
        kind = event["kind"]
        slot = event["slot"]
        confidence = event["value"]
        if kind == "local_action":
            reader = self.registry.reader(reader_id)
            door = next(
                (
                    item for item in self.registry.doors()
                    if reader and item["id"] == reader.get("door_id")
                ),
                None,
            )
            await self.emit_door_action_event(
                door, event["action"], "display",
                f"{reader_id}:{event['sequence']}", reader=reader, local_only=True,
            )
        elif kind == "matched":
            user = self.registry.user(slot, reader_id)
            name = user["name"] if user else f"Unregistered ID {slot}"
            reader = self.registry.reader(reader_id)
            detail = f"{name} · {reader['name'] if reader else reader_id}"
            if user and user.get("person_id"):
                person = self.registry.person(user["person_id"])
                authorized = bool(
                    person and person.get("status") == "active"
                )
                self.registry.add_event(
                    "access_granted" if authorized else "access_denied",
                    slot, confidence, detail,
                )
                await self.emit_credential_event(
                    reader_id, person, "fingerprint", slot, event["action"],
                    event["sequence"], authorized=authorized,
                )
            else:
                self.registry.add_event(
                    "access_denied", slot, confidence, detail
                )
        elif kind in {"unmatched", "invalid", "misplaced"}:
            self.registry.add_event(f"scan_{kind}", slot, confidence)

    async def process_management_event(self, raw, reader_id="display1"):
        setting_key = f"last_management_event:{reader_id}"
        if not raw or self.registry.setting(setting_key) == raw:
            return
        event = self.parse_event(raw)
        if not event:
            return
        kind = event["kind"]
        slot = event["slot"]
        value = event["value"]
        messages = {
            "enroll_scan": f"Scan {value}/2 for ID {slot}",
            "enroll_done": f"Fingerprint enrolled at ID {slot}",
            "enroll_failed": f"Could not enroll ID {slot}",
            "enroll_cancelled": f"Enrollment cancelled for ID {slot}",
            "delete_requested": f"Deletion sent for ID {slot}",
            "delete_done": f"Fingerprint ID {slot} deleted and confirmed",
            "delete_failed": f"Could not delete ID {slot}; it will be retried",
        }
        self.management_message = messages.get(kind, raw)
        if kind == "enroll_done" and slot:
            self.registry.activate(slot, reader_id)
            user = self.registry.user(slot, reader_id)
            if user:
                try:
                    await self.sync_name(
                        slot, user["name"], user["finger"], reader_id
                    )
                except Exception as error:
                    LOGGER.warning("Could not store the name in the ESP: %s", error)
            self.registry.add_event("enrollment_done", slot)
        elif kind in {"enroll_failed", "enroll_cancelled"} and slot:
            user = self.registry.user(slot, reader_id)
            if user and user["status"] == "pending":
                self.registry.remove_user(slot, reader_id)
            self.registry.add_event(kind, slot)
        elif kind == "enroll_scan":
            self.registry.add_event("enrollment_scan", slot, detail=f"Scan {value}")
        elif kind == "delete_requested":
            self.registry.add_event("delete_requested", slot)
        elif kind == "delete_done" and slot:
            user = self.registry.complete_delete(slot, reader_id)
            if user:
                self.registry.add_event("user_deleted", slot, detail=user["name"])
                if user.get("person_archived"):
                    self.registry.add_event(
                        "person_archived",
                        detail=user["name"],
                        source="access_manager",
                    )
                LOGGER.info("ESP confirmed deletion for ID %d", slot)
        elif kind == "delete_failed" and slot:
            if self.registry.deletion(slot, reader_id):
                self.registry.mark_delete_retry(
                    slot, "The reader did not confirm deletion", reader_id
                )
                self.registry.add_event("delete_failed", slot)
                LOGGER.warning("Reader rejected deletion for ID %d", slot)
        self.registry.set_setting(setting_key, raw)


class FingerprintAdmin:
    def __init__(self):
        self.registry = Registry(DB_PATH)
        self.ha = HomeAssistant(self.registry)
        self.ha.state_change_handler = self.handle_state_change
        self.ha.tag_scan_handler = self.handle_mobile_tag_scan
        self.websocket_task = None
        self.deletion_task = None
        self.deletion_lock = asyncio.Lock()
        self.capture_sessions = {}
        self.keypad_learning_sessions = {}
        self.last_keypad_actions = {}
        self.keypad_packet_tasks = {}
        self.keypad_packet_buffers = {}
        self.recent_mobile_tag_scans = {}

        self.firmware_jobs = {}
        self.firmware_tasks = set()
        self.firmware_lock = asyncio.Lock()
    async def handle_mobile_tag_scan(self, event):
        data = event.get("data", {}) if isinstance(event, dict) else {}
        context = event.get("context", {}) if isinstance(event, dict) else {}
        tag_id = str(data.get("tag_id", "")).strip()
        event_id = str(context.get("id", "")).strip()
        user_id = str(context.get("user_id", "")).strip()
        scanner_device_id = str(data.get("device_id", "")).strip()
        if not tag_id:
            return
        mapping = self.registry.mobile_nfc_tag(tag_id)
        if not mapping or not mapping.get("enabled"):
            return
        # Claim the authenticated Home Assistant event before any side effect.
        if not self.registry.claim_mobile_nfc_event(event_id):
            return
        door = next(
            (item for item in self.registry.doors() if item["id"] == mapping["door_id"]),
            None,
        )
        person = await self.ha.access_person_for_user_id(user_id)
        authorized = bool(
            door and person and scanner_device_id
            and self.registry.mobile_nfc_allowed(person["id"], mapping["door_id"])
        )
        source_id = event_id or f"{tag_id}:{now_iso()}"
        payload = {
            "event_id": f"mobile_nfc:{source_id}",
            "door_id": mapping["door_id"],
            "door_entity_id": door.get("entity_id") if door else None,
            "reader_id": "home_assistant_mobile_app",
            "reader_type": "mobile_nfc",
            "person_id": person["id"] if person else None,
            "person_name": person["name"] if person else None,
            "ha_person_entity_id": person.get("ha_person_entity_id") if person else None,
            "credential_type": "mobile_nfc",
            "credential_id": tag_id,
            "tag_name": mapping["name"],
            "scanner_device_id": scanner_device_id or None,
            "source": "home_assistant_mobile_app",
            "authorized": authorized,
            "requested_action": "default",
            "action": door.get("default_action") if door else None,
            "door_default_action": door.get("default_action") if door else None,
            "door_open_action": door.get("default_action") if door else None,
            "action_executed": False,
            "action_error": None,
        }
        if authorized:
            scan_key = (tag_id, user_id)
            now = asyncio.get_running_loop().time()
            previous = self.recent_mobile_tag_scans.get(scan_key)
            self.recent_mobile_tag_scans = {
                key: value for key, value in self.recent_mobile_tag_scans.items()
                if now - value < 10
            }
            if previous is not None and now - previous < 5:
                payload["authorized"] = False
                payload["action_error"] = "Duplicate mobile NFC scan"
            else:
                self.recent_mobile_tag_scans[scan_key] = now
                try:
                    await self.ha.execute_door_action(door, payload["action"])
                    payload["action_executed"] = True
                except Exception as error:
                    payload["action_error"] = str(error)[:240]
        reason = (
            "granted" if payload["action_executed"] else
            "duplicate" if payload["action_error"] == "Duplicate mobile NFC scan" else
            "unidentified_user" if not person else
            "invalid_source" if not scanner_device_id else
            "not_authorized" if not authorized else "action_failed"
        )
        payload["authorization_reason"] = reason
        self.registry.add_event(
            "mobile_nfc_granted" if payload["action_executed"] else "mobile_nfc_denied",
            detail=f"{mapping['name']} · {person['name'] if person else 'Unknown user'} · {reason}",
            door_id=mapping["door_id"],
            entity_id=door.get("entity_id") if door else None,
            source="home_assistant_mobile_app",
        )
        await self.ha.fire_event("access_manager_credential", payload)
        if payload["action_executed"] and payload["action"] in DISPLAY_OPENING_ACTIONS:
            await self.ha.emit_display_event(
                mapping["door_id"], "door_opened", payload["event_id"], person["name"]
            )
        LOGGER.info(
            "Mobile NFC event: door=%s person=%s authorized=%s executed=%s reason=%s",
            mapping["door_id"], person["name"] if person else None,
            payload["authorized"], payload["action_executed"], reason,
        )

    async def startup(self, _app):
        await self.ha.start()
        self.websocket_task = asyncio.create_task(self.ha.websocket_loop())
        self.deletion_task = asyncio.create_task(self.deletion_loop())

    async def cleanup(self, _app):
        tasks = [task for task in (self.websocket_task, self.deletion_task) if task]
        tasks.extend(self.keypad_packet_tasks.values())
        tasks.extend(self.firmware_tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await self.ha.close()

    def active_captures(self):
        now = asyncio.get_running_loop().time()
        expired = [
            reader_id for reader_id, session in self.capture_sessions.items()
            if session["expires_at"] <= now
        ]
        for reader_id in expired:
            self.capture_sessions.pop(reader_id, None)
        return [
            {
                "reader_id": reader_id,
                "owner_type": session.get("owner_type", "person"),
                "person_id": session.get("person_id"),
                "person_name": session.get("person_name"),
                "shared_label": session.get("shared_label"),
                "seconds_left": max(0, int(session["expires_at"] - now)),
            }
            for reader_id, session in self.capture_sessions.items()
        ]

    def active_keypad_learning(self):
        now = asyncio.get_running_loop().time()
        expired = [
            reader_id for reader_id, session in self.keypad_learning_sessions.items()
            if session["expires_at"] <= now
        ]
        for reader_id in expired:
            self.keypad_learning_sessions.pop(reader_id, None)
        return [
            {
                "reader_id": reader_id,
                "raw_action": session.get("raw_action"),
                "seconds_left": max(0, int(session["expires_at"] - now)),
            }
            for reader_id, session in self.keypad_learning_sessions.items()
        ]

    async def handle_state_change(self, entity_id, state, old_state=None):
        self.record_door_activity(entity_id, state, old_state)
        for reader in self.registry.readers():
            if not reader["enabled"] or reader["reader_type"] != "keypad":
                continue
            config = reader.get("config", {})
            packet_entities = {
                config.get("transaction_entity"),
                config.get("code_entity"),
                config.get("action_entity"),
            }
            if entity_id not in packet_entities:
                continue
            if entity_id == config.get("action_entity"):
                raw_action = str((state or {}).get("state", ""))
                learning = self.keypad_learning_sessions.get(reader["id"])
                if (
                    learning
                    and learning["expires_at"] > asyncio.get_running_loop().time()
                    and self.valid_keypad_value(raw_action)
                ):
                    self.record_learned_keypad_action(reader, raw_action, learning)
                    continue
            packet_field = next(
                (
                    field
                    for field, configured_entity in (
                        ("transaction", config.get("transaction_entity")),
                        ("code", config.get("code_entity")),
                        ("action", config.get("action_entity")),
                    )
                    if entity_id == configured_entity
                ),
                None,
            )
            value = str((state or {}).get("state", ""))
            if packet_field is None or not self.valid_keypad_value(value):
                # Zigbee2MQTT clears these short-lived entities after publishing
                # an attempt. Keep the valid event snapshot instead of replacing
                # it with the subsequent empty/unknown state.
                continue
            packet = self.keypad_packet_buffers.setdefault(
                reader["id"], {"values": {}, "observed": {}}
            )
            packet["values"][packet_field] = value
            packet["observed"][packet_field] = asyncio.get_running_loop().time()
            previous = self.keypad_packet_tasks.pop(reader["id"], None)
            if previous and not previous.done():
                previous.cancel()
            self.keypad_packet_tasks[reader["id"]] = asyncio.create_task(
                self.consume_keypad_packet(reader["id"])
            )

    def record_door_activity(self, entity_id, state, old_state):
        if not str(entity_id).startswith(("lock.", "binary_sensor.")):
            return
        doors = self.registry.doors_for_activity_entity(entity_id)
        if not doors:
            return
        new_value = str((state or {}).get("state", "")).strip().lower()
        old_value = str((old_state or {}).get("state", "")).strip().lower()
        source = self.ha.door_change_source(entity_id, new_value)
        if not old_value or old_value in {"unknown", "unavailable"}:
            return
        for door in doors:
            event_type = None
            if (
                entity_id == door.get("entity_id")
                and str(entity_id).startswith("lock.")
                and new_value in {"open", "unlocked"}
                and old_value not in {"open", "unlocked"}
            ):
                event_type = "door_lock_opened"
            elif (
                entity_id == door.get("entity_id")
                and str(entity_id).startswith("lock.")
                and new_value == "locked"
                and old_value != "locked"
            ):
                event_type = "door_lock_closed"
            elif (
                entity_id == door.get("door_sensor_entity")
                and old_value == "off"
                and new_value == "on"
            ):
                event_type = "door_physically_opened"
            elif (
                entity_id == door.get("door_sensor_entity")
                and old_value == "on"
                and new_value == "off"
            ):
                event_type = "door_physically_closed"
            if not event_type:
                continue
            self.registry.add_event(
                event_type,
                detail=(
                    f"{door['name']} · {source} · {old_value} → {new_value}"
                ),
                door_id=door["id"],
                entity_id=entity_id,
                source=source,
                previous_state=old_value,
                new_state=new_value,
            )

    def record_learned_keypad_action(self, reader, raw_action, learning):
        learning["raw_action"] = str(raw_action)
        self.ha.management_message = (
            f"Detected keypad button {raw_action} on {reader['name']}"
        )
        self.registry.add_event(
            "keypad_button_detected", detail=f"{reader['name']} · {raw_action}"
        )

    @staticmethod
    def valid_keypad_value(value):
        return str(value or "") not in {"", "unknown", "unavailable"}

    async def consume_keypad_packet(self, reader_id):
        try:
            # Zigbee/MQTT integrations publish transaction, code and action in
            # one attempt, but Home Assistant exposes them as separate and very
            # short-lived state changes. Assemble the event snapshots without a
            # later REST refresh, which may only see their cleared values.
            await asyncio.sleep(KEYPAD_PACKET_SETTLE_SECONDS)
            packet = self.keypad_packet_buffers.get(reader_id)
            if not packet:
                return
            required = {"transaction", "code", "action"}
            if not required.issubset(packet["values"]):
                await asyncio.sleep(KEYPAD_PACKET_MAX_SPAN_SECONDS)
                if self.keypad_packet_buffers.get(reader_id) is packet:
                    self.keypad_packet_buffers.pop(reader_id, None)
                return
            observed = packet["observed"]
            latest = max(observed[field] for field in required)
            if any(
                latest - observed[field] > KEYPAD_PACKET_MAX_SPAN_SECONDS
                for field in required
            ):
                packet["values"] = {
                    field: value
                    for field, value in packet["values"].items()
                    if latest - observed[field] <= KEYPAD_PACKET_MAX_SPAN_SECONDS
                }
                packet["observed"] = {
                    field: timestamp
                    for field, timestamp in observed.items()
                    if latest - timestamp <= KEYPAD_PACKET_MAX_SPAN_SECONDS
                }
                await asyncio.sleep(KEYPAD_PACKET_MAX_SPAN_SECONDS)
                if self.keypad_packet_buffers.get(reader_id) is packet:
                    self.keypad_packet_buffers.pop(reader_id, None)
                return
            snapshot = dict(packet["values"])
            self.keypad_packet_buffers.pop(reader_id, None)
            current = asyncio.current_task()
            if self.keypad_packet_tasks.get(reader_id) is current:
                self.keypad_packet_tasks.pop(reader_id, None)
            await self.process_keypad_packet(reader_id, snapshot)
        except asyncio.CancelledError:
            return
        except Exception as error:
            LOGGER.warning("Could not assemble keypad packet for %s: %s", reader_id, error)
        finally:
            current = asyncio.current_task()
            if self.keypad_packet_tasks.get(reader_id) is current:
                self.keypad_packet_tasks.pop(reader_id, None)

    async def process_keypad_packet(self, reader_id, packet=None):
        reader = self.registry.reader(reader_id)
        if not reader or not reader["enabled"] or reader["reader_type"] != "keypad":
            return False
        config = reader.get("config", {})
        if packet is None:
            transaction = self.ha.states.get(
                config.get("transaction_entity"), {}
            ).get("state")
            code = self.ha.states.get(config.get("code_entity"), {}).get("state")
            keypad_action = self.ha.states.get(
                config.get("action_entity"), {}
            ).get("state")
        else:
            transaction = packet.get("transaction")
            code = packet.get("code")
            keypad_action = packet.get("action")
        if not all(
            self.valid_keypad_value(value)
            for value in (transaction, code, keypad_action)
        ):
            return False
        setting_key = f"reader_transaction:{reader_id}"
        if self.registry.setting(setting_key) == str(transaction):
            return False
        # Do not consume an incomplete transaction. A later code/action state
        # change must still be able to complete this exact keypad packet.
        self.registry.set_setting(setting_key, str(transaction))
        self.last_keypad_actions[reader_id] = {
            "raw_action": str(keypad_action),
            "observed_at": now_iso(),
        }
        learning = self.keypad_learning_sessions.get(reader_id)
        if learning and learning["expires_at"] > asyncio.get_running_loop().time():
            self.record_learned_keypad_action(reader, str(keypad_action), learning)
            return True
        await self.process_keypad_event(
            reader, str(transaction), str(code), str(keypad_action)
        )
        return True

    def validate_reader_door_action(self, reader, action):
        door = next(
            (item for item in self.registry.doors() if item["id"] == reader.get("door_id")),
            None,
        )
        if not door:
            raise ValueError("The reader has no door assigned")
        if action not in self.ha.door_actions(door["entity_id"]):
            raise ValueError(
                f"Action {action or '(empty)'} is not supported by {door['entity_id']}"
            )
        return door

    async def process_keypad_event(self, reader, transaction, code, keypad_action):
        config = reader.get("config", {})
        action_map = config.get("action_map", {})
        captures = {item["reader_id"]: item for item in self.active_captures()}
        capture = captures.get(reader["id"])
        if capture:
            try:
                if capture.get("owner_type") == "shared":
                    owner_label = capture["shared_label"]
                    credential_id = self.registry.add_shared_keypad_credential(
                        owner_label, reader["id"], code
                    )
                    event_type = "shared_keypad_credential_added"
                    log_owner = f"shared credential {owner_label}"
                else:
                    owner_label = capture["person_name"]
                    credential_id = self.registry.add_keypad_credential(
                        capture["person_id"], reader["id"], code
                    )
                    event_type = "keypad_credential_added"
                    log_owner = f"person {capture['person_id']}"
                self.registry.add_event(
                    event_type, detail=(
                        f"{owner_label} · {reader['name']} · captured"
                    ),
                )
                self.ha.management_message = (
                    f"Credential saved for {owner_label} on {reader['name']}"
                )
                LOGGER.info(
                    "Keypad credential %d captured for %s",
                    credential_id, log_owner,
                )
                await self.ha.emit_display_event(
                    reader.get("door_id"), "credential_captured",
                    f"capture:{reader['id']}:{transaction}", owner_label,
                )
            except ValueError as error:
                self.ha.management_message = str(error)
                self.registry.add_event("keypad_capture_failed", detail=str(error))
            finally:
                self.capture_sessions.pop(reader["id"], None)
            return

        if keypad_action not in action_map:
            self.registry.add_event(
                "keypad_action_ignored", detail=f"{reader['name']} · {keypad_action}"
            )
            return
        action_name = str(action_map[keypad_action]).strip().lower()

        credential = self.registry.find_keypad_credential(
            reader["id"], code, keypad_action
        )
        if not credential:
            self.registry.add_event(
                "keypad_denied", detail=f"{reader['name']} · {action_name}"
            )
            await self.ha.emit_credential_event(
                reader["id"], None, "keypad", "unknown", action_name,
                transaction, authorized=False,
            )
            return
        shared = credential.get("owner_type") == "shared"
        person = None if shared else self.registry.person(credential["person_id"])
        if not shared and not person:
            return
        if person and person.get("status") != "active":
            self.registry.add_event(
                "keypad_denied",
                detail=f"{reader['name']} · {action_name}",
            )
            await self.ha.emit_credential_event(
                reader["id"], person, "keypad", credential["id"],
                action_name, transaction, authorized=False,
            )
            return
        # The keypad is intentionally dumb: identity comes from the stored
        # code/tag, while the current reader mapping decides what that physical
        # action button does now.
        credential_action = action_name
        owner_label = credential["label"] if shared else person["name"]
        self.registry.add_event(
            "access_granted",
            detail=f"{owner_label} · {reader['name']} · {credential_action}",
        )
        await self.ha.emit_credential_event(
            reader["id"], person, "shared_keypad" if shared else "keypad",
            credential["id"], credential_action, transaction, authorized=True,
            credential_label=owner_label if shared else None,
        )

    @staticmethod
    def retry_due(item):
        if item["state"] == "queued":
            return True
        try:
            updated = datetime.fromisoformat(item["updated_at"])
            age = (datetime.now(timezone.utc) - updated).total_seconds()
            return age >= DELETE_RETRY_SECONDS
        except (TypeError, ValueError):
            return True

    async def process_pending_deletions(self):
        if self.deletion_lock.locked():
            return
        async with self.deletion_lock:
            for item in self.registry.deletions():
                reader_id = item["reader_id"]
                if not self.retry_due(item):
                    continue
                if not self.ha.device_online(reader_id):
                    if item.get("last_error") != "Reader offline":
                        self.registry.add_event(
                            "person_deletion_blocked",
                            item["slot"],
                            detail=f"{reader_id} · reader offline",
                            source="access_manager",
                        )
                    self.registry.mark_delete_retry(
                        item["slot"], "Reader offline", reader_id
                    )
                    continue
                count = self.ha.fingerprint_count(reader_id)
                if count is None:
                    if item.get("last_error") != "Reader count is unavailable":
                        self.registry.add_event(
                            "person_deletion_blocked",
                            item["slot"],
                            detail=f"{reader_id} · count unavailable",
                            source="access_manager",
                        )
                    self.registry.mark_delete_retry(
                        item["slot"], "Reader count is unavailable", reader_id
                    )
                    continue
                expected = item.get("expected_count")
                if expected is not None and count <= expected:
                    user = self.registry.complete_delete(item["slot"], reader_id)
                    if user:
                        self.registry.add_event(
                            "user_deleted", item["slot"], detail=user["name"]
                        )
                        if user.get("person_archived"):
                            self.registry.add_event(
                                "person_archived",
                                detail=user["name"],
                                source="access_manager",
                            )
                        LOGGER.info(
                            "Deletion of ID %d recovered from reader count",
                            item["slot"],
                        )
                    continue
                self.registry.mark_delete_attempt(item["slot"], count, reader_id)
                if item["attempts"] > 0:
                    self.registry.add_event(
                        "delete_retry", item["slot"],
                        detail=f"Attempt {item['attempts'] + 1}",
                    )
                try:
                    await self.ha.set_slot(item["slot"], reader_id)
                    await self.ha.press("delete", reader_id)
                except Exception as error:
                    self.registry.mark_delete_retry(item["slot"], error, reader_id)
                    LOGGER.warning("Deletion of ID %d pending: %s", item["slot"], error)

    async def deletion_loop(self):
        while True:
            try:
                await self.process_pending_deletions()
            except asyncio.CancelledError:
                raise
            except Exception as error:
                LOGGER.exception("Error processing deletion queue: %s", error)
            await asyncio.sleep(5)

    @staticmethod
    def require_admin_request(request):
        if request.headers.get("X-Fingerprint-Admin") != "1":
            raise web.HTTPForbidden(text="Unauthorized request")

    async def index(self, _request):
        # Build a fresh response instead of FileResponse so ingress/WebViews
        # cannot reuse conditional-file metadata (ETag/Last-Modified) for the
        # single-file administration panel after an app update.
        response = web.Response(
            text=INDEX_PATH.read_text(encoding="utf-8"),
            content_type="text/html",
            charset="utf-8",
        )
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        response.headers["X-Access-Manager-Version"] = APP_VERSION
        return response

    async def health(self, _request):
        response = web.json_response(
            {
                "status": "ok",
                "version": APP_VERSION,
                "home_assistant": self.ha.connected,
                "ha_people_api": self.ha.people_api_ready,
                "ha_tags_api": self.ha.tags_api_ready,
            }
        )
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        return response

    async def state(self, _request):
        await self.ha.ensure_people_storage_fresh()
        self.ha.schedule_tags_refresh()
        reader = {}
        for key in (
            "fingerprint_count",
            "reader_status",
            "reader_capacity",
            "last_finger_id",
            "last_confidence",
            "device_status",
            "management_event",
        ):
            entity_id = self.ha.entities.get(key)
            state = self.ha.states.get(entity_id, {}) if entity_id else {}
            reader[key] = {
                "entity_id": entity_id,
                "state": state.get("state"),
                "attributes": state.get("attributes", {}),
            }
        deletions = {
            (item["reader_id"], item["slot"]): item
            for item in self.registry.deletions()
        }
        users = self.registry.users()
        for user in users:
            user["deletion"] = deletions.get((user["reader_id"], user["slot"]))
        readers = self.registry.readers()
        for access_reader in readers:
            if access_reader["reader_type"] == "fingerprint":
                access_reader["available"] = self.ha.device_online(access_reader["id"])
                access_reader["ready"] = self.ha.reader_ready(access_reader["id"])
                access_reader["fingerprint_count"] = self.ha.fingerprint_count(
                    access_reader["id"]
                )
                capacity_id = self.ha.reader_entity(
                    access_reader["id"], "reader_capacity", required=False
                )
                capacity_state = self.ha.states.get(capacity_id, {}) if capacity_id else {}
                try:
                    access_reader["physical_capacity"] = int(
                        round(float(capacity_state.get("state")))
                    )
                except (TypeError, ValueError):
                    access_reader["physical_capacity"] = 50
                access_reader["capacity"] = min(
                    50, access_reader["physical_capacity"]
                )
                access_reader["availability"] = (
                    "available" if access_reader["available"] else "unavailable"
                )
                config = access_reader.get("config", {})
                legacy = bool(config.get("legacy_autodiscovery"))
                display_entity = config.get("display_event_entity") or (
                    self.ha.entities.get("display_event") if legacy else None
                )
                access_reader["hardware_profile"] = config.get(
                    "hardware_profile",
                    "display" if display_entity else "reader_only",
                )
                language_id = config.get("display_language_entity") or (
                    self.ha.entities.get("display_language") if legacy else None
                )
                language_state = self.ha.states.get(language_id, {}) if language_id else {}
                access_reader["display_language"] = (
                    language_state.get("state")
                    if language_state.get("state") not in {None, "unknown", "unavailable"}
                    else None
                )
                version_id = config.get("firmware_version_entity") or (
                    self.ha.entities.get("firmware_version") if legacy else None
                )
                access_reader["firmware_version"] = (
                    self.ha.states.get(version_id, {}).get("state")
                    if version_id else None
                )
                if access_reader["firmware_version"] in {
                    "", "unknown", "unavailable"
                }:
                    access_reader["firmware_version"] = None
                access_reader["latest_firmware_version"] = READER_FIRMWARE_VERSION
            else:
                config = access_reader.get("config", {})
                entity_id = config.get("transaction_entity") or config.get("access_event_entity")
                entity_state = self.ha.states.get(entity_id, {}) if entity_id else {}
                if entity_id not in self.ha.states:
                    access_reader["availability"] = "missing"
                elif entity_state.get("state") == "unavailable":
                    access_reader["availability"] = "unavailable"
                else:
                    # Zigbee keypads sleep; "unknown" is still a valid configured state.
                    access_reader["availability"] = "configured"
        doors = self.registry.doors()
        for door in doors:
            entity_state = self.ha.states.get(door.get("entity_id"), {})
            door["state"] = entity_state.get("state")
        managed_automations = self.registry.managed_automations()
        doors_by_id = {door["id"]: door for door in doors}
        for automation in managed_automations:
            door = doors_by_id.get(automation["door_id"])
            entity_id = self.ha.automation_entity_id(automation["ha_config_id"])
            entity_state = self.ha.states.get(entity_id, {}) if entity_id else {}
            automation["door_name"] = door["name"] if door else automation["door_id"]
            automation["door_entity_id"] = door.get("entity_id") if door else None
            automation["ha_entity_id"] = entity_id
            automation["state"] = entity_state.get("state", "missing")
        ha_people = (
            self.ha.storage_people()
            if self.ha.people_api_ready
            else self.ha.ha_people()
        )
        people = self.registry.people()
        reader_availability = {
            item["id"]: item.get("availability")
            for item in readers
        }
        for person in people:
            deletion = person.get("deletion")
            if not deletion:
                continue
            deletion["blocked_readers"] = sorted({
                credential["reader_id"]
                for credential in person.get("credentials", [])
                if (
                    credential.get("type") == "fingerprint"
                    and reader_availability.get(
                        credential["reader_id"]
                    ) != "available"
                )
            })
        response = web.json_response(
            {
                "version": APP_VERSION,
                "reader_firmware_version": READER_FIRMWARE_VERSION,
                "esphome_configured": bool(configured_esphome_url()),
                "privacy_mode": self.registry.privacy_mode(),
                "connected": self.ha.connected,
                "reader_online": self.ha.device_online("display1"),
                "ready": all(
                    key in self.ha.entities
                    for key in ("slot", "enroll", "cancel", "delete", "name_registry")
                ),
                "missing": [
                    key for key in (
                        "slot", "enroll", "cancel", "delete", "name_registry",
                        "access_event", "management_event"
                    )
                    if key not in self.ha.entities
                ],
                "reader": reader,
                "users": users,
                "people": people,
                "shared_keypad_credentials": self.registry.shared_keypad_credentials(),
                "ha_people": ha_people,
                "ha_people_api_ready": self.ha.people_api_ready,
                "ha_people_refreshed_at": (
                    self.ha.people_storage_refreshed_iso
                ),
                "ha_tags_api_ready": self.ha.tags_api_ready,
                "doors": doors,
                "ha_tags": self.ha.ha_tags(),
                "mobile_nfc_tags": self.registry.mobile_nfc_tags(),
                "mobile_nfc_permissions": self.registry.mobile_nfc_permissions(),
                "mobile_nfc_permission_records": (
                    self.registry.mobile_nfc_permissions(
                        include_inactive=True
                    )
                ),
                "door_entities": self.ha.door_entities(),
                "door_sensors": self.ha.door_sensor_entities(),
                "notification_entities": self.ha.notification_entities(),
                "access_readers": readers,
                "managed_automations": managed_automations,
                "auto_lock_delays": list(AUTO_LOCK_DELAYS),
                "door_open_delays": list(DOOR_OPEN_DELAYS),
                "denied_attempt_thresholds": list(DENIED_ATTEMPT_THRESHOLDS),
                "denied_attempt_windows": list(DENIED_ATTEMPT_WINDOWS),
                "captures": self.active_captures(),
                "keypad_action_learning": self.active_keypad_learning(),
                "last_keypad_actions": self.last_keypad_actions,
                "access_event_type": "access_manager_credential",
                "finger_labels": FINGER_LABELS,
                "events": self.registry.events(),
                "log_retention_days": self.registry.log_retention_days(),
                "log_retention_options": [1, 7, 14, 30, 90, 180, 365],
                "management_message": self.ha.management_message,
            }
        )
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        return response

    async def enroll(self, request):
        self.require_admin_request(request)
        payload = await request.json()
        reader_id = str(payload.get("reader_id", "display1"))
        access_reader = self.registry.reader(reader_id)
        if not access_reader or access_reader["reader_type"] != "fingerprint":
            raise web.HTTPBadRequest(text="Fingerprint reader not found")
        if not access_reader["enabled"] or not self.ha.reader_ready(reader_id):
            raise web.HTTPConflict(text="Fingerprint reader is not ready")
        try:
            slot = int(payload.get("slot"))
        except (TypeError, ValueError):
            raise web.HTTPBadRequest(text="Invalid ID")
        name = self.ha.clean_name(payload.get("name", ""))
        finger = str(payload.get("finger", ""))
        if not 1 <= slot <= 50 or not name or len(name) > 24:
            raise web.HTTPBadRequest(text="Enter an ID from 1 to 50 and a name up to 24 characters")
        if finger not in FINGER_LABELS:
            raise web.HTTPBadRequest(text="Select one of the ten fingers")
        person = self.registry.person_by_name(name)
        if (
            not person
            or person.get("status") != "active"
            or not person.get("ha_person_entity_id")
        ):
            raise web.HTTPConflict(
                text="Create or link the user to a Home Assistant Person first"
            )
        if self.registry.user(slot, reader_id):
            raise web.HTTPConflict(text="That ID already exists on this reader")
        used = self.registry.finger_in_use(name, finger, reader_id)
        if used:
            raise web.HTTPConflict(
                text=f"That finger is already registered for {name} at ID {used['slot']}"
            )
        self.registry.put_user(slot, name, finger, "pending", reader_id)
        try:
            await self.ha.set_slot(slot, reader_id)
            await self.ha.press("enroll", reader_id)
            self.registry.add_event(
                "enrollment_requested", slot,
                detail=f"{name} · {access_reader['name']} · {FINGER_LABELS[finger]}",
            )
        except Exception:
            self.registry.remove_user(slot, reader_id)
            raise
        return web.json_response(
            {"ok": True, "reader_id": reader_id, "slot": slot, "name": name, "finger": finger}
        )

    async def import_existing(self, request):
        self.require_admin_request(request)
        payload = await request.json()
        reader_id = str(payload.get("reader_id", "display1"))
        access_reader = self.registry.reader(reader_id)
        if not access_reader or access_reader["reader_type"] != "fingerprint":
            raise web.HTTPBadRequest(text="Fingerprint reader not found")
        try:
            slot = int(payload.get("slot"))
        except (TypeError, ValueError):
            raise web.HTTPBadRequest(text="Invalid ID")
        name = self.ha.clean_name(payload.get("name", ""))
        finger = str(payload.get("finger", ""))
        if not 1 <= slot <= 50 or not name or len(name) > 24:
            raise web.HTTPBadRequest(text="Invalid data")
        if finger not in FINGER_LABELS:
            raise web.HTTPBadRequest(text="Select one of the ten fingers")
        person = self.registry.person_by_name(name)
        if (
            not person
            or person.get("status") != "active"
            or not person.get("ha_person_entity_id")
        ):
            raise web.HTTPConflict(
                text="Create or link the user to a Home Assistant Person first"
            )
        if self.registry.user(slot, reader_id):
            raise web.HTTPConflict(text="That ID already exists on this reader")
        used = self.registry.finger_in_use(name, finger, reader_id)
        if used:
            raise web.HTTPConflict(
                text=f"That finger is already registered for {name} at ID {used['slot']}"
            )
        await self.ha.sync_name(slot, name, finger, reader_id)
        self.registry.put_user(slot, name, finger, "active", reader_id)
        self.registry.add_event(
            "existing_id_linked", slot,
            detail=f"{name} · {access_reader['name']} · {FINGER_LABELS[finger]}",
        )
        return web.json_response({"ok": True})

    async def rename(self, request):
        self.require_admin_request(request)
        slot = int(request.match_info["slot"])
        payload = await request.json()
        reader_id = str(payload.get("reader_id", "display1"))
        user = self.registry.user(slot, reader_id)
        name = self.ha.clean_name(payload.get("name", ""))
        finger = str(payload.get("finger", user["finger"] if user else ""))
        if not name or len(name) > 24 or not user:
            raise web.HTTPBadRequest(text="Invalid name or ID")
        if user["status"] == "deleting":
            raise web.HTTPConflict(text="Fingerprint deletion is pending")
        if finger and finger not in FINGER_LABELS:
            raise web.HTTPBadRequest(text="Invalid finger")
        if finger:
            used = self.registry.finger_in_use(
                name, finger, reader_id, exclude_slot=slot
            )
            if used:
                raise web.HTTPConflict(
                    text=f"That finger is already registered for {name}"
                )
        await self.ha.sync_name(slot, name, finger, reader_id)
        self.registry.rename_user(slot, name, finger, reader_id)
        detail = f"{name} · {FINGER_LABELS.get(finger, 'Dedo sin asignar')}"
        self.registry.add_event("user_renamed", slot, detail=detail)
        return web.json_response({"ok": True})

    async def delete(self, request):
        self.require_admin_request(request)
        slot = int(request.match_info["slot"])
        reader_id = str(request.query.get("reader_id", "display1"))
        if not 1 <= slot <= 50:
            raise web.HTTPBadRequest(text="Invalid ID")
        user = self.registry.user(slot, reader_id)
        if not user:
            raise web.HTTPNotFound(text="No fingerprint exists with that ID on this reader")
        already_queued = self.registry.deletion(slot, reader_id) is not None
        if not already_queued:
            self.registry.queue_delete(slot, reader_id)
            self.registry.add_event("delete_queued", slot, detail=user["name"])
        asyncio.create_task(self.process_pending_deletions())
        return web.json_response(
            {
                "ok": True,
                "queued": True,
                "reader_online": self.ha.device_online(reader_id),
            },
            status=202,
        )

    async def cancel(self, request):
        self.require_admin_request(request)
        payload = await request.json() if request.can_read_body else {}
        reader_id = str(payload.get("reader_id", "display1"))
        await self.ha.press("cancel", reader_id)
        return web.json_response({"ok": True})

    async def create_person(self, request):
        self.require_admin_request(request)
        payload = await request.json()
        name = self.ha.clean_name(payload.get("name", ""))
        if not name:
            raise web.HTTPBadRequest(text="Enter a name")
        if self.registry.person_by_name(name):
            raise web.HTTPConflict(text="A person with that name already exists")
        requested_entity = str(payload.get("ha_person_entity_id", "")).strip()
        if requested_entity:
            if not await self.ha.ensure_people_storage_fresh():
                raise web.HTTPBadGateway(
                    text="Home Assistant People API is unavailable"
                )
            available = {
                item["entity_id"] for item in self.ha.storage_people()
            }
            if requested_entity not in available:
                raise web.HTTPBadRequest(text="Home Assistant Person does not exist")
            ha_entity_id = requested_entity
        else:
            try:
                ha_entity_id = await self.ha.create_ha_person(name)
            except RuntimeError as error:
                raise web.HTTPBadGateway(text=str(error))
        try:
            person_id = self.registry.create_person(name)
            self.registry.link_ha_person(person_id, ha_entity_id)
        except ValueError as error:
            raise web.HTTPConflict(text=str(error))
        self.registry.add_event("person_created", detail=name)
        return web.json_response({"ok": True, "person_id": person_id, "name": name})

    async def create_ha_person_for_local(self, request):
        self.require_admin_request(request)
        person_id = int(request.match_info["person_id"])
        person = self.registry.person(person_id)
        if not person:
            raise web.HTTPNotFound(text="Person not found")
        if person.get("status") != "active":
            raise web.HTTPConflict(text="Identity is not active")
        if person.get("ha_person_entity_id"):
            raise web.HTTPConflict(text="This identity is already linked to Home Assistant")
        try:
            entity_id = await self.ha.create_ha_person(person["name"])
            self.registry.link_ha_person(person_id, entity_id)
        except (ValueError, RuntimeError) as error:
            raise web.HTTPBadGateway(text=str(error))
        self.registry.add_event(
            "person_linked", detail=f"{person['name']} · {entity_id}"
        )
        return web.json_response({"ok": True, "ha_person_entity_id": entity_id})

    async def rename_person(self, request):
        self.require_admin_request(request)
        person_id = int(request.match_info["person_id"])
        payload = await request.json()
        name = self.ha.clean_name(payload.get("name", ""))
        person = self.registry.person(person_id)
        if not person:
            raise web.HTTPNotFound(text="Person not found")
        try:
            if person.get("ha_person_entity_id"):
                await self.ha.ensure_people_storage_fresh()
                refreshed_person = self.registry.person(person_id)
                if refreshed_person.get("ha_link_status") == "linked":
                    await self.ha.update_ha_person(
                        refreshed_person["ha_person_entity_id"], name
                    )
            self.registry.rename_person(person_id, name)
        except (ValueError, RuntimeError, sqlite3.IntegrityError) as error:
            raise web.HTTPConflict(text=str(error))
        self.registry.add_event("person_renamed", detail=name)
        return web.json_response({"ok": True})

    async def link_ha_person(self, request):
        self.require_admin_request(request)
        person_id = int(request.match_info["person_id"])
        payload = await request.json()
        entity_id = str(
            payload.get("ha_person_entity_id", "")
        ).strip()
        if not await self.ha.ensure_people_storage_fresh():
            raise web.HTTPBadGateway(
                text="Home Assistant People API is unavailable"
            )
        available = {
            item["entity_id"] for item in self.ha.storage_people()
        }
        if entity_id not in available:
            raise web.HTTPBadRequest(text="Home Assistant Person does not exist")
        try:
            result = self.registry.link_ha_person(person_id, entity_id)
        except ValueError as error:
            raise web.HTTPConflict(text=str(error))
        person = self.registry.person(person_id)
        event_type = (
            "person_relinked"
            if (
                result["previous_entity_id"]
                and result["previous_entity_id"] != entity_id
            )
            else "person_linked"
        )
        self.registry.add_event(
            event_type,
            detail=f"{person['name']} · {entity_id}",
            source="access_manager",
        )
        return web.json_response({"ok": True, **result})

    async def unlink_ha_person(self, request):
        self.require_admin_request(request)
        try:
            person_id = int(request.match_info["person_id"])
            person = self.registry.person(person_id)
            result = self.registry.unlink_ha_person(person_id)
        except (TypeError, ValueError) as error:
            raise web.HTTPConflict(text=str(error))
        self.registry.add_event(
            "person_unlinked",
            detail=(
                f"{person['name']} · "
                f"{result['previous_entity_id'] or 'none'}"
            ),
            source="access_manager",
        )
        return web.json_response({"ok": True, **result})

    def deletion_preview_with_availability(self, person_id):
        preview = self.registry.person_deletion_preview(person_id)
        blocked = set(preview.get("blocked_readers", []))
        for item in preview["fingerprints"]:
            item["reader_online"] = self.ha.device_online(
                item["reader_id"]
            )
            if not item["reader_online"]:
                blocked.add(item["reader_id"])
        preview["blocked_readers"] = sorted(blocked)
        preview["can_archive_immediately"] = not preview["fingerprints"]
        return preview

    async def person_deletion_preview(self, request):
        self.require_admin_request(request)
        try:
            person_id = int(request.match_info["person_id"])
            preview = self.deletion_preview_with_availability(person_id)
        except TypeError as error:
            raise web.HTTPBadRequest(text=str(error))
        except ValueError as error:
            raise web.HTTPNotFound(text=str(error))
        return web.json_response(preview)

    async def delete_person(self, request):
        self.require_admin_request(request)
        try:
            person_id = int(request.match_info["person_id"])
            before = self.deletion_preview_with_availability(person_id)
            result = self.registry.begin_person_deletion(person_id)
        except TypeError as error:
            raise web.HTTPBadRequest(text=str(error))
        except ValueError as error:
            raise web.HTTPConflict(text=str(error))
        if result.get("archived"):
            self.registry.add_event(
                "person_archived",
                detail=before["person"]["name"],
                source="access_manager",
            )
        else:
            asyncio.create_task(self.process_pending_deletions())
        body = {
            "ok": True,
            "status": (
                "archived"
                if result.get("archived")
                else "deletion_pending"
            ),
            "preview": before,
            "blocked_readers": before["blocked_readers"],
        }
        return web.json_response(
            body, status=200 if result.get("archived") else 202
        )

    async def start_keypad_capture(self, request):
        self.require_admin_request(request)
        payload = await request.json()
        try:
            raw_person_id = payload.get("person_id")
            if isinstance(raw_person_id, bool):
                raise ValueError("Invalid person")
            person_id = int(raw_person_id)
        except (TypeError, ValueError):
            raise web.HTTPBadRequest(text="Invalid person")
        reader_id = str(payload.get("reader_id", ""))
        person = self.registry.person(person_id)
        reader = self.registry.reader(reader_id)
        if not person:
            raise web.HTTPNotFound(text="Person not found")
        if person.get("status") != "active":
            raise web.HTTPConflict(text="Identity is not active")
        if not reader or reader["reader_type"] != "keypad" or not reader["enabled"]:
            raise web.HTTPBadRequest(text="Select an enabled keypad")
        self.capture_sessions[reader_id] = {
            "owner_type": "person",
            "person_id": person_id,
            "person_name": person["name"],
            "expires_at": asyncio.get_running_loop().time() + 90,
        }
        self.ha.management_message = (
            f"Waiting for a code or tag from {reader['name']}"
        )
        return web.json_response({"ok": True, "expires_in": 90})

    async def start_shared_keypad_capture(self, request):
        self.require_admin_request(request)
        payload = await request.json()
        label = str(payload.get("label", "")).strip()
        reader_id = str(payload.get("reader_id", ""))
        reader = self.registry.reader(reader_id)
        if not label or len(label) > 80 or any(char in label for char in "\r\n"):
            raise web.HTTPBadRequest(text="Enter a shared credential label")
        if not reader or reader["reader_type"] != "keypad" or not reader["enabled"]:
            raise web.HTTPBadRequest(text="Select an enabled keypad")
        self.capture_sessions[reader_id] = {
            "owner_type": "shared",
            "shared_label": label,
            "expires_at": asyncio.get_running_loop().time() + 90,
        }
        self.ha.management_message = (
            f"Waiting for shared credential {label} from {reader['name']}"
        )
        return web.json_response({"ok": True, "expires_in": 90})

    async def create_keypad_credential(self, request):
        self.require_admin_request(request)
        payload = await request.json()
        try:
            person_id = int(payload.get("person_id"))
        except (TypeError, ValueError):
            raise web.HTTPBadRequest(text="Invalid person")
        reader_id = str(payload.get("reader_id", ""))
        person = self.registry.person(person_id)
        reader = self.registry.reader(reader_id)
        if not person:
            raise web.HTTPNotFound(text="Person not found")
        if not reader or reader["reader_type"] != "keypad" or not reader["enabled"]:
            raise web.HTTPBadRequest(text="Select an enabled keypad")
        try:
            code = self.registry.clean_keypad_secret(payload.get("code"))
            credential_id = self.registry.add_keypad_credential(
                person_id, reader_id, code
            )
        except ValueError as error:
            if "already linked" in str(error):
                raise web.HTTPConflict(text=str(error))
            raise web.HTTPBadRequest(text=str(error))
        self.registry.add_event(
            "keypad_credential_added",
            detail=f"{person['name']} · {reader['name']} · manual",
        )
        self.ha.management_message = (
            f"Credential saved for {person['name']} on {reader['name']}"
        )
        await self.ha.emit_display_event(
            reader.get("door_id"), "credential_captured",
            f"manual:{reader['id']}:{credential_id}", person["name"],
        )
        return web.json_response({"ok": True, "credential_id": credential_id})

    async def create_shared_keypad_credential(self, request):
        self.require_admin_request(request)
        payload = await request.json()
        label = str(payload.get("label", "")).strip()
        reader_id = str(payload.get("reader_id", ""))
        reader = self.registry.reader(reader_id)
        if not reader or reader["reader_type"] != "keypad" or not reader["enabled"]:
            raise web.HTTPBadRequest(text="Select an enabled keypad")
        try:
            code = self.registry.clean_keypad_secret(payload.get("code"))
            credential_id = self.registry.add_shared_keypad_credential(
                label, reader_id, code
            )
        except ValueError as error:
            if "already linked" in str(error):
                raise web.HTTPConflict(text=str(error))
            raise web.HTTPBadRequest(text=str(error))
        self.registry.add_event(
            "shared_keypad_credential_added",
            detail=f"{label} · {reader['name']} · manual",
        )
        self.ha.management_message = (
            f"Shared credential {label} saved on {reader['name']}"
        )
        await self.ha.emit_display_event(
            reader.get("door_id"), "credential_captured",
            f"shared-manual:{reader['id']}:{credential_id}", label,
        )
        return web.json_response({"ok": True, "credential_id": credential_id})

    async def cancel_keypad_capture(self, request):
        self.require_admin_request(request)
        reader_id = str(request.match_info["reader_id"])
        self.capture_sessions.pop(reader_id, None)
        return web.json_response({"ok": True})

    async def start_keypad_action_learning(self, request):
        self.require_admin_request(request)
        reader_id = str(request.match_info["reader_id"])
        reader = self.registry.reader(reader_id)
        if not reader or reader["reader_type"] != "keypad" or not reader["enabled"]:
            raise web.HTTPBadRequest(text="Select an enabled keypad")
        self.keypad_learning_sessions[reader_id] = {
            "raw_action": None,
            "expires_at": asyncio.get_running_loop().time() + 60,
        }
        return web.json_response({"ok": True, "expires_in": 60})

    async def cancel_keypad_action_learning(self, request):
        self.require_admin_request(request)
        reader_id = str(request.match_info["reader_id"])
        self.keypad_learning_sessions.pop(reader_id, None)
        return web.json_response({"ok": True})

    async def delete_keypad_credential(self, request):
        self.require_admin_request(request)
        credential_id = int(request.match_info["credential_id"])
        if not self.registry.delete_keypad_credential(credential_id):
            raise web.HTTPNotFound(text="Credential not found")
        self.registry.add_event(
            "keypad_credential_deleted", detail=f"Keypad credential {credential_id}"
        )
        return web.json_response({"ok": True})

    async def delete_shared_keypad_credential(self, request):
        self.require_admin_request(request)
        credential_id = int(request.match_info["credential_id"])
        if not self.registry.delete_shared_keypad_credential(credential_id):
            raise web.HTTPNotFound(text="Shared credential not found")
        self.registry.add_event(
            "shared_keypad_credential_deleted",
            detail=f"Shared keypad credential {credential_id}",
        )
        return web.json_response({"ok": True})

    async def reveal_keypad_credential(self, request):
        self.require_admin_request(request)
        try:
            credential_id = int(request.match_info["credential_id"])
            value = self.registry.reveal_keypad_credential(credential_id)
        except (TypeError, ValueError) as error:
            raise web.HTTPConflict(text=str(error))
        except LookupError as error:
            raise web.HTTPNotFound(text=str(error))
        response = web.json_response({"value": value})
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        return response

    async def reveal_shared_keypad_credential(self, request):
        self.require_admin_request(request)
        try:
            credential_id = int(request.match_info["credential_id"])
            value = self.registry.reveal_shared_keypad_credential(credential_id)
        except (TypeError, ValueError) as error:
            raise web.HTTPConflict(text=str(error))
        except LookupError as error:
            raise web.HTTPNotFound(text=str(error))
        response = web.json_response({"value": value})
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        return response

    async def set_privacy_mode(self, request):
        self.require_admin_request(request)
        payload = await request.json()
        enabled = payload.get("enabled")
        if not isinstance(enabled, bool):
            raise web.HTTPBadRequest(text="Privacy mode must be true or false")
        if not enabled and payload.get("acknowledge") is not True:
            raise web.HTTPBadRequest(
                text="Disabling privacy requires explicit acknowledgement"
            )
        self.registry.set_privacy_mode(enabled)
        self.registry.add_event(
            "privacy_mode_changed",
            detail="enabled" if enabled else "disabled",
        )
        return web.json_response({"ok": True, "privacy_mode": enabled})

    async def create_door(self, request):
        self.require_admin_request(request)
        payload = await request.json()
        name = str(payload.get("name", "")).strip()[:40]
        requested_id = str(payload.get("id", "") or name)
        door_id = re.sub(r"[^a-z0-9_]+", "_", normalized(requested_id).replace(" ", "_"))
        entity_id = str(payload.get("entity_id", "")).strip()
        default_action = str(
            payload.get("default_action", payload.get("open_action", ""))
        ).strip()
        door_sensor_entity = str(payload.get("door_sensor_entity", "")).strip()
        self.validate_door(entity_id, default_action)
        self.validate_door_sensor(door_sensor_entity)
        if not door_id or not name:
            raise web.HTTPBadRequest(text="Door ID and name are required")
        try:
            self.registry.create_door(
                door_id, name, entity_id, default_action, door_sensor_entity
            )
        except sqlite3.IntegrityError:
            raise web.HTTPConflict(text="A door with that ID already exists")
        return web.json_response({"ok": True, "door_id": door_id})

    def validate_door(self, entity_id, default_action):
        state = self.ha.states.get(entity_id)
        if not state:
            raise web.HTTPBadRequest(text="Select an existing Home Assistant entity")
        allowed = self.ha.door_actions(entity_id)
        if default_action not in allowed:
            raise web.HTTPBadRequest(
                text=(
                    f"Action {default_action or '(empty)'} is not supported by "
                    f"{entity_id}"
                )
            )

    def validate_door_sensor(self, door_sensor_entity):
        if door_sensor_entity and not self.ha.is_door_sensor(door_sensor_entity):
            raise web.HTTPBadRequest(
                text="Select an available binary sensor with the door device class"
            )

    async def update_door(self, request):
        self.require_admin_request(request)
        door_id = str(request.match_info["door_id"])
        payload = await request.json()
        name = str(payload.get("name", "")).strip()[:40]
        entity_id = str(payload.get("entity_id", "")).strip()
        default_action = str(
            payload.get("default_action", payload.get("open_action", ""))
        ).strip()
        door_sensor_entity = (
            str(payload.get("door_sensor_entity", "")).strip()
            if "door_sensor_entity" in payload
            else None
        )
        if not name:
            raise web.HTTPBadRequest(text="Door name is required")
        self.validate_door(entity_id, default_action)
        self.validate_door_sensor(door_sensor_entity)
        try:
            self.registry.update_door(
                door_id, name, entity_id, default_action, door_sensor_entity
            )
        except ValueError as error:
            raise web.HTTPNotFound(text=str(error))
        return web.json_response({"ok": True})

    async def test_door_action(self, request):
        self.require_admin_request(request)
        door_id = str(request.match_info["door_id"])
        payload = await request.json()
        action = str(payload.get("action", "")).strip().lower()
        door = next(
            (item for item in self.registry.doors() if item["id"] == door_id), None
        )
        if not door:
            raise web.HTTPNotFound(text="Door not found")
        if action not in self.ha.door_actions(door["entity_id"]):
            raise web.HTTPBadRequest(text="The selected action is not supported")
        result = await self.ha.emit_door_action_event(
            door, action, "admin_test", f"admin:{door_id}:{now_iso()}"
        )
        status = 200 if result["action_executed"] else 502
        return web.json_response(result, status=status)

    async def save_mobile_nfc_tag(self, request):
        self.require_admin_request(request)
        payload = await request.json()
        tag_id = str(payload.get("tag_id", "")).strip()
        known_tag = next(
            (item for item in self.ha.ha_tags() if item["tag_id"] == tag_id), None
        )
        if not known_tag:
            raise web.HTTPBadRequest(text="Select a tag registered in Home Assistant")
        door_id = str(payload.get("door_id", "")).strip()
        enabled = payload.get("enabled", True)
        if not isinstance(enabled, bool):
            raise web.HTTPBadRequest(text="Invalid enabled value")
        try:
            self.registry.save_mobile_nfc_tag(
                tag_id, known_tag["name"], door_id, enabled
            )
        except ValueError as error:
            raise web.HTTPBadRequest(text=str(error))
        self.registry.add_event(
            "mobile_nfc_tag_saved",
            detail=f"{known_tag['name']} · {door_id}",
            door_id=door_id,
            source="access_manager",
        )
        return web.json_response({"ok": True, "tag_id": tag_id})

    async def delete_mobile_nfc_tag(self, request):
        self.require_admin_request(request)
        tag_id = str(request.match_info["tag_id"])
        if not self.registry.delete_mobile_nfc_tag(tag_id):
            raise web.HTTPNotFound(text="Mobile NFC tag not found")
        self.registry.add_event(
            "mobile_nfc_tag_deleted", detail=tag_id, source="access_manager"
        )
        return web.json_response({"ok": True})

    async def set_mobile_nfc_permission(self, request):
        self.require_admin_request(request)
        payload = await request.json()
        try:
            person_id = int(payload.get("person_id"))
            tag_id = str(payload.get("tag_id", "")).strip()
            mapping = self.registry.mobile_nfc_tag(tag_id) if tag_id else None
            if tag_id and (not mapping or not mapping["enabled"]):
                raise ValueError("Select an enabled fixed-door NFC tag")
            door_id = (
                mapping["door_id"] if mapping
                else str(payload.get("door_id", "")).strip()
            )
            enabled = payload.get("enabled")
            if not isinstance(enabled, bool):
                raise ValueError("Invalid enabled value")
            person = self.registry.person(person_id)
            if not person:
                raise ValueError("User not found")
            if (
                enabled
                and not await self.ha.ensure_people_storage_fresh()
            ):
                raise ValueError(
                    "Home Assistant People API is unavailable"
                )
            if enabled and not self.registry.mobile_nfc_eligible(person_id):
                raise ValueError(
                    "Link the user to a confirmed "
                    "Home Assistant Person first"
                )
            self.registry.set_mobile_nfc_permission(person_id, door_id, enabled)
        except (TypeError, ValueError) as error:
            raise web.HTTPBadRequest(text=str(error))
        self.registry.add_event(
            "mobile_nfc_permission_changed",
            detail=(
                f"{person['name']} · {mapping['name'] if mapping else door_id} · "
                f"{'enabled' if enabled else 'disabled'}"
            ),
            door_id=door_id,
            source="access_manager",
        )
        return web.json_response(
            {"ok": True, "person_id": person_id, "door_id": door_id, "tag_id": tag_id}
        )

    async def esphome_process(self, session, base_url, command, payload, job):
        ws_url = re.sub(r"^http", "ws", base_url, count=1) + f"/{command}"
        async with session.ws_connect(ws_url, heartbeat=30) as socket:
            await socket.send_json({"type": "spawn", **payload})
            async for message in socket:
                if message.type != WSMsgType.TEXT:
                    continue
                event = json.loads(message.data)
                if event.get("event") == "line":
                    line = str(event.get("data", "")).rstrip()
                    if line:
                        job["logs"] = (job["logs"] + [line])[-80:]
                elif event.get("event") == "exit":
                    code = int(event.get("code", 1))
                    if code:
                        raise RuntimeError(f"ESPHome {command} failed with exit code {code}")
                    return
        raise RuntimeError(f"ESPHome {command} connection closed unexpectedly")

    async def run_firmware_job(self, job_id, yaml, filename, install):
        job = self.firmware_jobs[job_id]
        base_url = configured_esphome_url()
        if not base_url:
            job.update(status="failed", error="Configure esphome_dashboard_url in the add-on options")
            return
        timeout = ClientTimeout(total=None, sock_connect=15, sock_read=None)
        try:
            async with self.firmware_lock, ClientSession(timeout=timeout) as session:
                job.update(status="saving", step="saving")
                async with session.get(f"{base_url}/") as dashboard:
                    if dashboard.status >= 400:
                        raise RuntimeError(
                            f"ESPHome Device Builder is unavailable ({dashboard.status})"
                        )
                    xsrf_cookie = dashboard.cookies.get("_xsrf")
                xsrf = xsrf_cookie.value if xsrf_cookie else ""
                request_headers = {"Content-Type": "text/yaml; charset=utf-8"}
                if xsrf:
                    request_headers["X-CSRFToken"] = xsrf
                query = urlencode({"configuration": filename})
                async with session.post(
                    f"{base_url}/edit?{query}", data=yaml,
                    headers=request_headers,
                    cookies={"_xsrf": xsrf} if xsrf else None,
                ) as response:
                    if response.status >= 400:
                        detail = (await response.text())[:500]
                        raise RuntimeError(f"ESPHome could not save the configuration: {detail or response.status}")
                job.update(status="compiling", step="compiling")
                await self.esphome_process(
                    session, base_url, "compile", {"configuration": filename}, job
                )
                if install:
                    job.update(status="installing", step="installing")
                    await self.esphome_process(
                        session, base_url, "run",
                        {"configuration": filename, "port": "OTA"}, job,
                    )
                job.update(status="completed", step="completed", finished_at=now_iso())
        except asyncio.CancelledError:
            job.update(status="cancelled", step="cancelled", finished_at=now_iso())
            raise
        except Exception as error:
            LOGGER.exception("ESPHome firmware job %s failed", job_id)
            job.update(status="failed", step="failed", error=str(error), finished_at=now_iso())

    async def generate_esphome_config(self, request):
        self.require_admin_request(request)
        payload = await request.json()
        try:
            yaml = esphome_reader_config(payload)
        except (AttributeError, TypeError, ValueError) as error:
            raise web.HTTPBadRequest(text=str(error))
        return web.json_response(
            {
                "yaml": yaml,
                "firmware_version": READER_FIRMWARE_VERSION,
                "profile": str(payload.get("profile", "reader_only")),
            }
        )

    def queue_firmware_job(self, yaml, filename, install, reader_id=None):
        job_id = secrets.token_urlsafe(9)
        self.firmware_jobs[job_id] = {
            "id": job_id,
            "reader_id": reader_id,
            "configuration": filename,
            "install": install,
            "status": "queued",
            "step": "queued",
            "logs": [],
            "error": None,
            "created_at": now_iso(),
        }
        task = asyncio.create_task(
            self.run_firmware_job(job_id, yaml, filename, install)
        )
        self.firmware_tasks.add(task)
        task.add_done_callback(self.firmware_tasks.discard)
        return self.firmware_jobs[job_id]

    async def build_esphome_firmware(self, request):
        self.require_admin_request(request)
        if not configured_esphome_url():
            raise web.HTTPConflict(
                text="Configure the ESPHome Device Builder URL in the add-on options"
            )
        payload = await request.json()
        try:
            yaml = esphome_reader_config(payload)
        except (AttributeError, TypeError, ValueError) as error:
            raise web.HTTPBadRequest(text=str(error))
        device_name = str(payload.get("device_name", "")).strip()
        filename = f"{device_name}-access-manager.yaml"
        install = bool(payload.get("install")) and payload.get("install_mode") == "existing"
        return web.json_response(
            self.queue_firmware_job(yaml, filename, install)
        )

    async def update_reader_firmware(self, request):
        self.require_admin_request(request)
        reader_id = str(request.match_info["reader_id"])
        reader = self.registry.reader(reader_id)
        if not reader or reader["reader_type"] != "fingerprint":
            raise web.HTTPNotFound(text="Fingerprint reader not found")
        config = reader.get("config", {})
        profile = config.get(
            "hardware_profile",
            "display"
            if (
                config.get("display_event_entity")
                or (config.get("legacy_autodiscovery") and self.ha.entities.get("display_event"))
            ) else "reader_only",
        )
        payload = {
            "profile": profile,
            "install_mode": "existing",
            "device_name": config.get("device_name") or reader_id.replace("_", "-"),
            "friendly_name": reader["name"],
        }
        if profile == "display":
            payload["display_language"] = (
                config.get("display_language")
                or ("Español" if config.get("preferred_language") == "es" else "English")
            )
        else:
            firmware = config.get("firmware_config", {})
            if not all(firmware.get(key) for key in ("board", "fingerprint_tx_pin", "fingerprint_rx_pin")):
                raise web.HTTPConflict(
                    text="Configure the board and UART pins before updating this sensor-only reader"
                )
            payload.update(firmware)
        yaml = esphome_reader_config(payload)
        filename = f"{payload['device_name']}-access-manager.yaml"
        return web.json_response(
            self.queue_firmware_job(yaml, filename, True, reader_id)
        )

    async def firmware_job(self, request):
        self.require_admin_request(request)
        job = self.firmware_jobs.get(str(request.match_info["job_id"]))
        if not job:
            raise web.HTTPNotFound(text="Firmware job not found")
        return web.json_response(job)

    async def create_reader(self, request):
        self.require_admin_request(request)
        payload = await request.json()
        reader_id = re.sub(
            r"[^a-z0-9_]+", "_", normalized(payload.get("id", "")).replace(" ", "_")
        )
        name = str(payload.get("name", "")).strip()[:50]
        reader_type = str(payload.get("reader_type", ""))
        door_id = str(payload.get("door_id", ""))
        config = payload.get("config", {})
        if not reader_id or not name or not isinstance(config, dict):
            raise web.HTTPBadRequest(text="Invalid reader data")
        self.validate_reader_config(reader_type, config)
        try:
            self.registry.create_reader(
                reader_id, name, reader_type, door_id, config,
                bool(payload.get("enabled", True)),
            )
        except (ValueError, sqlite3.IntegrityError) as error:
            raise web.HTTPConflict(text=str(error))
        await self.ha.sync_reader_door(reader_id)
        return web.json_response({"ok": True, "reader_id": reader_id})

    def validate_reader_config(self, reader_type, config):
        required = (
            ("transaction_entity", "code_entity", "action_entity")
            if reader_type == "keypad"
            else (
                "slot_entity", "enroll_entity", "cancel_entity", "delete_entity",
                "name_registry_entity", "access_event_entity", "management_event_entity",
            )
        )
        missing = [key for key in required if not str(config.get(key, "")).strip()]
        if missing:
            raise web.HTTPBadRequest(
                text=f"Missing reader entities: {', '.join(missing)}"
            )
        optional = (
            ("assigned_door_entity", "display_event_entity", "firmware_version_entity", "display_language_entity")
            if reader_type == "fingerprint"
            else ()
        )
        configured = tuple(required) + tuple(
            key for key in optional if str(config.get(key, "")).strip()
        )
        unknown = [
            config[key] for key in configured
            if config.get(key) not in self.ha.states
        ]
        if unknown:
            raise web.HTTPBadRequest(
                text=f"Home Assistant entities not found: {', '.join(unknown)}"
            )
        if reader_type == "keypad":
            action_map = config.get("action_map", {})
            if not isinstance(action_map, dict):
                raise web.HTTPBadRequest(text="Keypad action mapping must be an object")
            keypad_actions = {"open", "unlock", "lock"}
            invalid_actions = sorted({
                str(action).strip().lower() for action in action_map.values()
                if str(action).strip().lower() not in keypad_actions
            })
            if invalid_actions:
                raise web.HTTPBadRequest(
                    text=f"Invalid keypad door actions: {', '.join(invalid_actions)}"
                )
        elif any(
            config.get(key) and not str(config[key]).startswith("text.")
            for key in ("assigned_door_entity", "display_event_entity")
        ):
            raise web.HTTPBadRequest(
                text="Display event and assigned door entities must use the text domain"
            )
        if config.get("display_language_entity") and not str(
            config["display_language_entity"]
        ).startswith("select."):
            raise web.HTTPBadRequest(text="Display language entity must use the select domain")


    async def update_reader(self, request):
        self.require_admin_request(request)
        reader_id = str(request.match_info["reader_id"])
        payload = await request.json()
        reader = self.registry.reader(reader_id)
        if not reader:
            raise web.HTTPNotFound(text="Reader not found")
        try:
            new_config = payload.get("config") if isinstance(payload.get("config"), dict) else None
            if new_config is not None:
                self.validate_reader_config(reader["reader_type"], new_config)
            self.registry.update_reader(
                reader_id,
                str(payload.get("name", reader["name"])).strip()[:50],
                str(payload.get("door_id", reader.get("door_id") or "")),
                bool(payload.get("enabled", reader["enabled"])),
                new_config,
            )
        except ValueError as error:
            raise web.HTTPBadRequest(text=str(error))
        await self.ha.sync_reader_door(reader_id)
        return web.json_response({"ok": True})
    async def set_reader_display_language(self, request):
        self.require_admin_request(request)
        reader_id = str(request.match_info["reader_id"])
        reader = self.registry.reader(reader_id)
        if not reader or reader["reader_type"] != "fingerprint":
            raise web.HTTPNotFound(text="Fingerprint reader not found")
        config = reader.get("config", {})
        entity_id = str(config.get("display_language_entity") or (
            self.ha.entities.get("display_language")
            if config.get("legacy_autodiscovery") else "")).strip()
        if not entity_id:
            raise web.HTTPConflict(
                text="This reader has no display language entity configured"
            )
        language = str((await request.json()).get("language", "")).strip().lower()
        option = {"en": "English", "es": "Español"}.get(language)
        if not option:
            raise web.HTTPBadRequest(text="Unsupported display language")
        await self.ha.call_service(
            "select", "select_option",
            {"entity_id": entity_id, "option": option},
        )
        self.registry.add_event(
            "reader_display_language_changed",
            detail=f"{reader_id} · {option}",
            source="access_manager",
        )
        return web.json_response({"ok": True, "language": language})


    @staticmethod
    def auto_lock_automation_id(door_id):
        return f"{AUTOMATION_ID_PREFIX}auto_lock_{door_id}"

    @staticmethod
    def door_open_automation_id(door_id):
        return f"{AUTOMATION_ID_PREFIX}door_open_{door_id}"

    @staticmethod
    def denied_access_automation_id(door_id):
        return f"{AUTOMATION_ID_PREFIX}denied_access_{door_id}"

    @staticmethod
    def owned_automation_config(config, expected_id):
        if not isinstance(config, dict):
            return False
        config_id = str(config.get("id") or expected_id)
        return (
            config_id == expected_id
            and str(config.get("alias", "")).startswith(AUTOMATION_ALIAS_PREFIX)
            and str(config.get("description", "")).startswith(
                AUTOMATION_DESCRIPTION_MARKER
            )
        )

    @staticmethod
    def build_auto_lock_config(
        door, config_id, delay_minutes, door_sensor_entity=""
    ):
        if door_sensor_entity:
            return {
                "id": config_id,
                "alias": (
                    f"{AUTOMATION_ALIAS_PREFIX} Auto-lock {door['name']} "
                    f"after it closes for {delay_minutes} minutes"
                ),
                "description": (
                    f"{AUTOMATION_DESCRIPTION_MARKER} "
                    f"Auto-lock for Access Manager door {door['id']}."
                ),
                "triggers": [
                    {
                        "trigger": "door.closed",
                        "target": {"entity_id": door_sensor_entity},
                        "options": {},
                    }
                ],
                "conditions": [],
                "actions": [
                    {
                        "delay": {
                            "hours": delay_minutes // 60,
                            "minutes": delay_minutes % 60,
                            "seconds": 0,
                            "milliseconds": 0,
                        }
                    },
                    {
                        "if": [
                            {
                                "condition": "lock.is_unlocked",
                                "target": {"entity_id": [door["entity_id"]]},
                                "options": {},
                            },
                            {
                                "condition": "door.is_closed",
                                "target": {"entity_id": door_sensor_entity},
                                "options": {},
                            },
                        ],
                        "then": [
                            {
                                "action": "lock.lock",
                                "target": {"entity_id": door["entity_id"]},
                            }
                        ],
                    },
                ],
                "mode": "restart",
            }
        return {
            "id": config_id,
            "alias": (
                f"{AUTOMATION_ALIAS_PREFIX} Auto-lock {door['name']} "
                f"after {delay_minutes} minutes"
            ),
            "description": (
                f"{AUTOMATION_DESCRIPTION_MARKER} "
                f"Auto-lock for Access Manager door {door['id']}."
            ),
            "triggers": [
                {
                    "trigger": "state",
                    "entity_id": door["entity_id"],
                    "to": "unlocked",
                    "for": {
                        "hours": delay_minutes // 60,
                        "minutes": delay_minutes % 60,
                        "seconds": 0,
                    },
                }
            ],
            "conditions": [
                {
                    "condition": "state",
                    "entity_id": door["entity_id"],
                    "state": "unlocked",
                }
            ],
            "actions": [
                {
                    "action": "lock.lock",
                    "target": {"entity_id": door["entity_id"]},
                }
            ],
            "mode": "restart",
        }

    @staticmethod
    def notification_action(title, message, notification_entity=""):
        if notification_entity:
            return {
                "action": "notify.send_message",
                "target": {"entity_id": notification_entity},
                "data": {"message": message},
            }
        return {
            "action": "notify.persistent_notification",
            "data": {"title": title, "message": message},
        }

    @classmethod
    def build_door_open_config(
        cls, door, config_id, delay_minutes, door_sensor_entity,
        notification_entity="",
    ):
        return {
            "id": config_id,
            "alias": (
                f"{AUTOMATION_ALIAS_PREFIX} Door open alert for {door['name']} "
                f"after {delay_minutes} minutes"
            ),
            "description": (
                f"{AUTOMATION_DESCRIPTION_MARKER} "
                f"Door-open alert for Access Manager door {door['id']}."
            ),
            "triggers": [
                {
                    "trigger": "state",
                    "entity_id": door_sensor_entity,
                    "to": "on",
                    "for": {
                        "hours": delay_minutes // 60,
                        "minutes": delay_minutes % 60,
                        "seconds": 0,
                    },
                }
            ],
            "conditions": [
                {
                    "condition": "state",
                    "entity_id": door_sensor_entity,
                    "state": "on",
                }
            ],
            "actions": [
                cls.notification_action(
                    "Door left open",
                    (
                        f"{door['name']} has remained open for "
                        f"{delay_minutes} minutes."
                    ),
                    notification_entity,
                )
            ],
            "mode": "single",
        }

    @staticmethod
    def denied_event_trigger(door_id):
        return {
            "trigger": "event",
            "event_type": "access_manager_credential",
            "event_data": {"door_id": door_id, "authorized": False},
        }

    @classmethod
    def build_denied_access_config(
        cls, door, config_id, attempt_threshold, window_minutes,
        notification_entity="",
    ):
        trigger = cls.denied_event_trigger(door["id"])
        actions = []
        if attempt_threshold > 1:
            actions.append(
                {
                    "wait_for_trigger": [dict(trigger)],
                    "timeout": {
                        "hours": window_minutes // 60,
                        "minutes": window_minutes % 60,
                        "seconds": 0,
                    },
                    "continue_on_timeout": False,
                }
            )
        if attempt_threshold > 2:
            actions.append(
                {
                    "repeat": {
                        "count": attempt_threshold - 2,
                        "sequence": [
                            {
                                "wait_for_trigger": [dict(trigger)],
                                "timeout": "{{ wait.remaining }}",
                                "continue_on_timeout": False,
                            }
                        ],
                    }
                }
            )
        noun = "attempt" if attempt_threshold == 1 else "attempts"
        actions.append(
            cls.notification_action(
                "Denied access alert",
                (
                    f"Access Manager detected {attempt_threshold} denied access {noun} "
                    f"at {door['name']} within {window_minutes} minutes."
                ),
                notification_entity,
            )
        )
        return {
            "id": config_id,
            "alias": (
                f"{AUTOMATION_ALIAS_PREFIX} Denied access alert for {door['name']}"
            ),
            "description": (
                f"{AUTOMATION_DESCRIPTION_MARKER} "
                f"Denied-access alert for Access Manager door {door['id']}."
            ),
            "triggers": [trigger],
            "conditions": [],
            "actions": actions,
            # While the first run waits for the configured threshold, subsequent
            # denied events are consumed by wait_for_trigger instead of starting
            # overlapping counters.
            "mode": "single",
            "max_exceeded": "silent",
        }

    async def resolve_automation_entity(self, config_id):
        for _attempt in range(4):
            await self.ha.refresh_states()
            entity_id = self.ha.automation_entity_id(config_id)
            if entity_id:
                return entity_id
            await asyncio.sleep(0.25)
        return None

    def automation_door(self, door_id):
        door = next(
            (item for item in self.registry.doors() if item["id"] == door_id), None
        )
        if not door:
            raise web.HTTPNotFound(text="Door not found")
        return door

    def automation_notification_entity(self, payload):
        entity_id = str(payload.get("notification_entity", "")).strip()
        if not self.ha.is_notification_entity(entity_id):
            raise web.HTTPBadRequest(
                text="Select an available Home Assistant notification entity"
            )
        return entity_id

    async def persist_managed_automation(
        self, automation_type, door, config_id, enabled, config, stored_config,
        event_detail,
    ):
        local = self.registry.managed_automation(config_id)
        current = await self.ha.automation_config(config_id)
        if not local and current:
            raise web.HTTPConflict(
                text="That Home Assistant automation ID already exists outside Access Manager"
            )
        if local and (
            local["ha_config_id"] != config_id
            or local["automation_type"] != automation_type
            or local["door_id"] != door["id"]
        ):
            raise web.HTTPConflict(text="The managed automation identity does not match")
        if current and not self.owned_automation_config(current, config_id):
            raise web.HTTPConflict(
                text="The Home Assistant automation is no longer owned by Access Manager"
            )
        await self.ha.save_automation_config(config_id, config)
        self.registry.upsert_managed_automation(
            config_id, automation_type, door["id"], config_id, enabled,
            stored_config,
        )
        entity_id = await self.resolve_automation_entity(config_id)
        if not entity_id:
            raise web.HTTPBadGateway(
                text="Home Assistant saved the automation but did not expose its entity"
            )
        await self.ha.call_service(
            "automation", "turn_on" if enabled else "turn_off",
            {"entity_id": entity_id},
        )
        self.registry.add_event("automation_saved", detail=event_detail)
        return web.json_response(
            {"ok": True, "automation_id": config_id, "entity_id": entity_id}
        )

    async def save_auto_lock_automation(self, request):
        self.require_admin_request(request)
        payload = await request.json()
        door_id = str(payload.get("door_id", "")).strip()
        try:
            delay_minutes = int(payload.get("delay_minutes"))
        except (TypeError, ValueError):
            raise web.HTTPBadRequest(text="Select a valid auto-lock delay")
        if delay_minutes not in AUTO_LOCK_DELAYS:
            raise web.HTTPBadRequest(text="Select a supported auto-lock delay")
        door_sensor_entity = str(payload.get("door_sensor_entity", "")).strip()
        if door_sensor_entity and not self.ha.is_door_sensor(door_sensor_entity):
            raise web.HTTPBadRequest(
                text="Select an available binary sensor with the door device class"
            )
        enabled = bool(payload.get("enabled", True))
        door = self.automation_door(door_id)
        if not str(door.get("entity_id", "")).startswith("lock."):
            raise web.HTTPBadRequest(
                text="Native auto-lock is available only for Home Assistant lock entities"
            )
        if "lock" not in self.ha.door_actions(door["entity_id"]):
            raise web.HTTPBadRequest(text="This entity does not support locking")
        config_id = self.auto_lock_automation_id(door_id)
        config = self.build_auto_lock_config(
            door, config_id, delay_minutes, door_sensor_entity
        )
        response = await self.persist_managed_automation(
            "auto_lock", door, config_id, enabled, config,
            {
                "delay_minutes": delay_minutes,
                "door_sensor_entity": door_sensor_entity,
            },
            f"{door['name']} · auto-lock · {delay_minutes} min",
        )
        if door_sensor_entity:
            self.registry.set_door_sensor(door["id"], door_sensor_entity)
        return response

    async def save_door_open_automation(self, request):
        self.require_admin_request(request)
        payload = await request.json()
        door_id = str(payload.get("door_id", "")).strip()
        try:
            delay_minutes = int(payload.get("delay_minutes"))
        except (TypeError, ValueError):
            raise web.HTTPBadRequest(text="Select a valid door-open delay")
        if delay_minutes not in DOOR_OPEN_DELAYS:
            raise web.HTTPBadRequest(text="Select a supported door-open delay")
        door_sensor_entity = str(payload.get("door_sensor_entity", "")).strip()
        if not self.ha.is_door_sensor(door_sensor_entity):
            raise web.HTTPBadRequest(
                text="Select an available binary sensor with the door device class"
            )
        notification_entity = self.automation_notification_entity(payload)
        enabled = bool(payload.get("enabled", True))
        door = self.automation_door(door_id)
        config_id = self.door_open_automation_id(door_id)
        config = self.build_door_open_config(
            door, config_id, delay_minutes, door_sensor_entity,
            notification_entity,
        )
        response = await self.persist_managed_automation(
            "door_open", door, config_id, enabled, config,
            {
                "delay_minutes": delay_minutes,
                "door_sensor_entity": door_sensor_entity,
                "notification_entity": notification_entity,
            },
            f"{door['name']} · door-open alert · {delay_minutes} min",
        )
        self.registry.set_door_sensor(door["id"], door_sensor_entity)
        return response

    async def save_denied_access_automation(self, request):
        self.require_admin_request(request)
        payload = await request.json()
        door_id = str(payload.get("door_id", "")).strip()
        try:
            attempt_threshold = int(payload.get("attempt_threshold"))
            window_minutes = int(payload.get("window_minutes"))
        except (TypeError, ValueError):
            raise web.HTTPBadRequest(text="Select a valid denied-attempt threshold")
        if attempt_threshold not in DENIED_ATTEMPT_THRESHOLDS:
            raise web.HTTPBadRequest(text="Select a supported attempt threshold")
        if window_minutes not in DENIED_ATTEMPT_WINDOWS:
            raise web.HTTPBadRequest(text="Select a supported attempt window")
        notification_entity = self.automation_notification_entity(payload)
        enabled = bool(payload.get("enabled", True))
        door = self.automation_door(door_id)
        config_id = self.denied_access_automation_id(door_id)
        config = self.build_denied_access_config(
            door, config_id, attempt_threshold, window_minutes,
            notification_entity,
        )
        return await self.persist_managed_automation(
            "denied_access", door, config_id, enabled, config,
            {
                "attempt_threshold": attempt_threshold,
                "window_minutes": window_minutes,
                "notification_entity": notification_entity,
            },
            (
                f"{door['name']} · denied-access alert · "
                f"{attempt_threshold}/{window_minutes} min"
            ),
        )

    async def delete_managed_automation(self, request):
        self.require_admin_request(request)
        automation_id = str(request.match_info["automation_id"])
        local = self.registry.managed_automation(automation_id)
        if not local:
            raise web.HTTPNotFound(text="Managed automation not found")
        current = await self.ha.automation_config(local["ha_config_id"])
        if current and not self.owned_automation_config(
            current, local["ha_config_id"]
        ):
            raise web.HTTPConflict(
                text="Refusing to delete an automation not owned by Access Manager"
            )
        if current:
            await self.ha.delete_automation_config(local["ha_config_id"])
        self.registry.delete_managed_automation(automation_id)
        self.registry.add_event(
            "automation_deleted",
            detail=f"{local['door_id']} · {local['automation_type']}",
        )
        return web.json_response({"ok": True})

    async def set_log_retention(self, request):
        self.require_admin_request(request)
        payload = await request.json()
        try:
            self.registry.set_log_retention_days(int(payload.get("days")))
        except (TypeError, ValueError) as error:
            raise web.HTTPBadRequest(text=str(error))
        return web.json_response(
            {"ok": True, "days": self.registry.log_retention_days()}
        )

    def application(self):
        app = web.Application(client_max_size=32 * 1024)
        app.router.add_get("/", self.index)
        app.router.add_get("/health", self.health)
        app.router.add_get("/api/state", self.state)
        app.router.add_post("/api/users/enroll", self.enroll)
        app.router.add_post("/api/users/import", self.import_existing)
        app.router.add_put("/api/users/{slot}", self.rename)
        app.router.add_delete("/api/users/{slot}", self.delete)
        app.router.add_post("/api/enrollment/cancel", self.cancel)
        app.router.add_post("/api/people", self.create_person)
        app.router.add_put("/api/people/{person_id}", self.rename_person)
        app.router.add_put("/api/people/{person_id}/ha-person", self.link_ha_person)
        app.router.add_delete(
            "/api/people/{person_id}/ha-person",
            self.unlink_ha_person,
        )
        app.router.add_get(
            "/api/people/{person_id}/deletion-preview",
            self.person_deletion_preview,
        )
        app.router.add_delete(
            "/api/people/{person_id}", self.delete_person
        )
        app.router.add_post(
            "/api/people/{person_id}/create-ha-person",
            self.create_ha_person_for_local,
        )
        app.router.add_post("/api/keypad/capture", self.start_keypad_capture)
        app.router.add_post(
            "/api/keypad/shared-capture", self.start_shared_keypad_capture
        )
        app.router.add_post(
            "/api/keypad/credentials", self.create_keypad_credential
        )
        app.router.add_post(
            "/api/keypad/shared-credentials", self.create_shared_keypad_credential
        )
        app.router.add_delete("/api/keypad/capture/{reader_id}", self.cancel_keypad_capture)
        app.router.add_post(
            "/api/keypads/{reader_id}/action-learning",
            self.start_keypad_action_learning,
        )
        app.router.add_delete(
            "/api/keypads/{reader_id}/action-learning",
            self.cancel_keypad_action_learning,
        )
        app.router.add_delete(
            "/api/keypad/credentials/{credential_id}", self.delete_keypad_credential
        )
        app.router.add_post(
            "/api/keypad/credentials/{credential_id}/reveal",
            self.reveal_keypad_credential,
        )
        app.router.add_delete(
            "/api/keypad/shared-credentials/{credential_id}",
            self.delete_shared_keypad_credential,
        )
        app.router.add_post(
            "/api/keypad/shared-credentials/{credential_id}/reveal",
            self.reveal_shared_keypad_credential,
        )
        app.router.add_post("/api/doors", self.create_door)
        app.router.add_put("/api/doors/{door_id}", self.update_door)
        app.router.add_post("/api/doors/{door_id}/test", self.test_door_action)
        app.router.add_put("/api/mobile-nfc/tags", self.save_mobile_nfc_tag)
        app.router.add_delete(
            "/api/mobile-nfc/tags/{tag_id}", self.delete_mobile_nfc_tag
        )
        app.router.add_put(
            "/api/mobile-nfc/permissions", self.set_mobile_nfc_permission
        )
        app.router.add_post(
            "/api/esphome/config", self.generate_esphome_config
        )
        app.router.add_post("/api/esphome/build", self.build_esphome_firmware)
        app.router.add_get("/api/esphome/jobs/{job_id}", self.firmware_job)
        app.router.add_post(
            "/api/readers/{reader_id}/firmware/update", self.update_reader_firmware)
        app.router.add_post("/api/readers", self.create_reader)
        app.router.add_put("/api/readers/{reader_id}", self.update_reader)
        app.router.add_put(
            "/api/readers/{reader_id}/display-language", self.set_reader_display_language
        )
        app.router.add_put("/api/automations/auto-lock", self.save_auto_lock_automation)
        app.router.add_put(
            "/api/automations/door-open", self.save_door_open_automation
        )
        app.router.add_put(
            "/api/automations/denied-access", self.save_denied_access_automation
        )
        app.router.add_delete(
            "/api/automations/{automation_id}", self.delete_managed_automation
        )
        app.router.add_put("/api/settings/log-retention", self.set_log_retention)
        app.router.add_put("/api/settings/privacy", self.set_privacy_mode)
        app.on_startup.append(self.startup)
        app.on_cleanup.append(self.cleanup)
        return app


if __name__ == "__main__":
    admin = FingerprintAdmin()
    LOGGER.info(
        "Starting Access Manager %s with %s logging and privacy mode %s",
        APP_VERSION, LOG_LEVEL,
        "enabled" if admin.registry.privacy_mode() else "disabled",
    )
    # Home Assistant Ingress reaches this process over the private app network;
    # config.yaml deliberately exposes no host port.
    web.run_app(
        admin.application(),
        host="0.0.0.0",  # nosec B104
        port=PORT,
        access_log=None,
    )
