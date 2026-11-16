"""Parsers for account databases, fstab, package databases, and procfs."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field


@dataclass(frozen=True)
class UserAccount:
    name: str
    password: str
    uid: int
    gid: int
    gecos: str
    home: str
    shell: str


@dataclass(frozen=True)
class GroupAccount:
    name: str
    password: str
    gid: int
    members: tuple[str, ...]


@dataclass(frozen=True)
class ShadowEntry:
    name: str
    password: str
    last_change: int | None = None
    min_days: int | None = None
    max_days: int | None = None
    warn_days: int | None = None
    inactive_days: int | None = None
    expire_date: int | None = None
    reserved: str = ""


@dataclass(frozen=True)
class MountEntry:
    device: str
    mountpoint: str
    fstype: str
    options: tuple[str, ...]
    dump: str = "0"
    passno: str = "0"
    line: int = 0

    def has_option(self, option: str) -> bool:
        return option in self.options


@dataclass(frozen=True)
class PackageRecord:
    name: str
    version: str
    status: str
    architecture: str = ""

    @property
    def installed(self) -> bool:
        return self.status.lower() == "install ok installed" or self.status.lower() == "installed"


@dataclass(frozen=True)
class ProcSocket:
    family: str
    address: str
    port: int
    state: str

    @property
    def listening(self) -> bool:
        return self.state.upper() == "0A"


@dataclass
class PackageDatabase:
    source: str
    packages: dict[str, PackageRecord] = field(default_factory=dict)
    available: bool = True

    def is_installed(self, name: str) -> bool:
        record = self.packages.get(name)
        if record is not None:
            return record.installed
        # Debian virtual/minimal package names are sometimes referenced with a
        # trailing colon (e.g. ``python3:any``); check the bare name as well.
        bare = name.split(":", 1)[0]
        record = self.packages.get(bare)
        return record is not None and record.installed

    def is_known(self, name: str) -> bool:
        return name in self.packages or name.split(":", 1)[0] in self.packages


def _safe_int(value: str) -> int | None:
    try:
        return int(value, 10)
    except (TypeError, ValueError):
        return None


def parse_passwd(text: str) -> list[UserAccount]:
    accounts: list[UserAccount] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 7:
            continue
        uid = _safe_int(fields[2])
        gid = _safe_int(fields[3])
        if uid is None or gid is None:
            continue
        accounts.append(
            UserAccount(
                name=fields[0],
                password=fields[1],
                uid=uid,
                gid=gid,
                gecos=fields[4],
                home=fields[5],
                # This is a passwd field, not a subprocess argument.
                shell=fields[6],  # nosec B604
            )
        )
    return accounts


def parse_group(text: str) -> list[GroupAccount]:
    groups: list[GroupAccount] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 4:
            continue
        gid = _safe_int(fields[2])
        if gid is None:
            continue
        members = tuple(member for member in fields[3].split(",") if member)
        groups.append(GroupAccount(fields[0], fields[1], gid, members))
    return groups


def parse_shadow(text: str) -> list[ShadowEntry]:
    entries: list[ShadowEntry] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 2:
            continue
        padded = fields + [""] * (9 - len(fields))
        entries.append(
            ShadowEntry(
                name=padded[0],
                password=padded[1],
                last_change=_safe_int(padded[2]),
                min_days=_safe_int(padded[3]),
                max_days=_safe_int(padded[4]),
                warn_days=_safe_int(padded[5]),
                inactive_days=_safe_int(padded[6]),
                expire_date=_safe_int(padded[7]),
                reserved=padded[8],
            )
        )
    return entries


_FSTAB_ESCAPE = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}


def unescape_fstab(value: str) -> str:
    result: list[str] = []
    index = 0
    while index < len(value):
        if value[index] == "\\" and index + 3 < len(value) + 1:
            code = value[index + 1 : index + 4]
            if code in _FSTAB_ESCAPE:
                result.append(_FSTAB_ESCAPE[code])
                index += 4
                continue
        result.append(value[index])
        index += 1
    return "".join(result)


def parse_fstab(text: str) -> list[MountEntry]:
    entries: list[MountEntry] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 4:
            continue
        options = tuple(option for option in fields[3].split(",") if option)
        entries.append(
            MountEntry(
                device=unescape_fstab(fields[0]),
                mountpoint=unescape_fstab(fields[1]),
                fstype=fields[2],
                options=options,
                dump=fields[4] if len(fields) > 4 else "0",
                passno=fields[5] if len(fields) > 5 else "0",
                line=lineno,
            )
        )
    return entries


def parse_dpkg_status(text: str) -> PackageDatabase:
    db = PackageDatabase(source="dpkg")
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        current_key: str | None = None
        for line in block.splitlines():
            if line.startswith((" ", "\t")) and current_key:
                fields[current_key] += "\n" + line.strip()
                continue
            key, sep, value = line.partition(":")
            if not sep:
                continue
            current_key = key.strip()
            fields[current_key] = value.strip()
        name = fields.get("Package")
        if not name:
            continue
        db.packages[name] = PackageRecord(
            name=name,
            version=fields.get("Version", ""),
            status=fields.get("Status", ""),
            architecture=fields.get("Architecture", ""),
        )
    return db


def parse_apk_installed(text: str) -> PackageDatabase:
    db = PackageDatabase(source="apk")
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            key, sep, value = line.partition(":")
            if sep:
                fields[key.strip()] = value.strip()
        name = fields.get("P")
        if name:
            db.packages[name] = PackageRecord(
                name=name,
                version=fields.get("V", ""),
                status="installed",
                architecture=fields.get("A", ""),
            )
    return db


def parse_os_release(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        result[key.strip()] = value
    return result


def parse_proc_net_tcp(text: str, family: str) -> list[ProcSocket]:
    """Parse ``/proc/net/tcp`` or ``tcp6`` output.

    Only established data is used: the local address, local port, and socket
    state.  Addresses are decoded for IPv4; IPv6 uses the canonical exploded
    form when possible.
    """
    sockets: list[ProcSocket] = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4:
            continue
        local = fields[1]
        state = fields[3]
        address_text, _, port_text = local.partition(":")
        try:
            port = int(port_text, 16)
        except ValueError:
            continue
        address = _decode_proc_address(address_text, family)
        sockets.append(ProcSocket(family=family, address=address, port=port, state=state))
    return sockets


def _decode_proc_address(value: str, family: str) -> str:
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return value
    if family == "tcp" and len(raw) == 4:
        # procfs stores IPv4 addresses in host (little-endian) order.
        return str(ipaddress.IPv4Address(raw[::-1]))
    if family == "tcp6" and len(raw) == 16:
        words = [raw[i : i + 4][::-1] for i in range(0, 16, 4)]
        packed = b"".join(words)
        try:
            address = ipaddress.IPv6Address(packed)
        except ValueError:
            return value
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return address.compressed
    return value


def is_system_uid(uid: int) -> bool:
    """CIS treats UID < 1000 as a system account (UID 0 handled separately)."""
    return 0 < uid < 1000
