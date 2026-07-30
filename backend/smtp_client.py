"""
SMTP delivery helpers for NetGuard.

Some on-premise Exchange relays respond normally to raw socket SMTP commands
but time out when Python's smtplib waits for the EHLO reply. For plain,
unauthenticated port-25 relay delivery we use a small raw SMTP client and keep
smtplib for SSL, STARTTLS, and authenticated sessions.
"""
import base64
import logging
import socket
import smtplib
import ssl
from email.message import Message
from typing import List, Optional, Sequence, Tuple


logger = logging.getLogger("netguard.smtp")


def describe_smtp_error(exc: Exception, host: str, port: int) -> str:
    if isinstance(exc, socket.gaierror):
        return (
            f"SMTP host name resolution failed: {host}. "
            "Check DNS, /etc/hosts, or enter the SMTP server IP address directly."
        )
    if isinstance(exc, (ConnectionRefusedError, TimeoutError, socket.timeout)):
        return (
            f"SMTP server connection failed: {host}:{port}. "
            "Check firewall, routing, SMTP port, and relay service status."
        )
    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return (
            f"SMTP server disconnected or did not send a valid SMTP response: {host}:{port}. "
            f"Stage/detail: {exc}. "
            "Check the SMTP port, TLS/STARTTLS mode, relay policy, and whether the server allows this NetGuard host."
        )
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "SMTP authentication failed. Check SMTP account and password."
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "SMTP recipient was refused. Check the recipient address or relay policy."
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return "SMTP sender was refused. Check the sender address or relay policy."
    if isinstance(exc, smtplib.SMTPException):
        return f"SMTP protocol error: {exc}"
    return f"SMTP send failed: {exc}"


def _payload_bytes(msg: Message) -> bytes:
    payload = msg.as_bytes()
    payload = payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")
    lines = payload.split(b"\r\n")
    payload = b"\r\n".join((b"." + line if line.startswith(b".") else line) for line in lines)
    if not payload.endswith(b"\r\n"):
        payload += b"\r\n"
    return payload


def _smtp_docmd(smtp: smtplib.SMTP, stage: str, command: str, args: Optional[str] = None):
    try:
        if args is None:
            return smtp.docmd(command)
        return smtp.docmd(command, args)
    except smtplib.SMTPServerDisconnected as e:
        raise smtplib.SMTPServerDisconnected(f"{stage}: {e}") from e
    except TimeoutError as e:
        raise smtplib.SMTPServerDisconnected(f"{stage}: timed out") from e


def _smtp_ehlo_upper(smtp: smtplib.SMTP, hostname: str = "netguard-srv"):
    logger.info("SMTP stage: EHLO %s", hostname)
    code, msg = _smtp_docmd(smtp, "EHLO", "EHLO", hostname)
    smtp.ehlo_resp = msg
    if code != 250:
        logger.info("SMTP stage: HELO %s", hostname)
        code, msg = _smtp_docmd(smtp, "HELO", "HELO", hostname)
        smtp.helo_resp = msg
        if code != 250:
            raise smtplib.SMTPHeloError(code, msg)
        return code, msg

    smtp.does_esmtp = True
    smtp.esmtp_features = {}
    text = msg.decode("latin-1", errors="replace") if isinstance(msg, bytes) else str(msg)
    for line in text.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        smtp.esmtp_features[parts[0].lower()] = " ".join(parts[1:])
    return code, msg


def _smtp_send_message_upper(smtp: smtplib.SMTP, msg: Message, sender: str, recipients: Sequence[str]):
    logger.info("SMTP stage: MAIL FROM <%s>", sender)
    code, reply = _smtp_docmd(smtp, "MAIL FROM", "MAIL", f"FROM:<{sender}>")
    if code != 250:
        raise smtplib.SMTPSenderRefused(code, reply, sender)

    refused = {}
    accepted = []
    for recipient in recipients:
        logger.info("SMTP stage: RCPT TO <%s>", recipient)
        code, reply = _smtp_docmd(smtp, f"RCPT TO {recipient}", "RCPT", f"TO:<{recipient}>")
        if code in (250, 251):
            accepted.append(recipient)
        else:
            refused[recipient] = (code, reply)

    if not accepted:
        raise smtplib.SMTPRecipientsRefused(refused)

    logger.info("SMTP stage: DATA")
    code, reply = _smtp_docmd(smtp, "DATA", "DATA")
    if code != 354:
        raise smtplib.SMTPDataError(code, reply)

    smtp.send(_payload_bytes(msg) + b".\r\n")
    code, reply = smtp.getreply()
    if code != 250:
        raise smtplib.SMTPDataError(code, reply)


def _read_reply(sock: socket.socket, stage: str) -> Tuple[int, bytes]:
    lines: List[bytes] = []
    while True:
        line = bytearray()
        try:
            while not line.endswith(b"\n"):
                chunk = sock.recv(1)
                if not chunk:
                    break
                line.extend(chunk)
                if len(line) > 8192:
                    raise smtplib.SMTPServerDisconnected(f"{stage}: reply line too long")
        except TimeoutError as e:
            raise smtplib.SMTPServerDisconnected(f"{stage}: timed out") from e
        except socket.timeout as e:
            raise smtplib.SMTPServerDisconnected(f"{stage}: timed out") from e
        if not line:
            raise smtplib.SMTPServerDisconnected(f"{stage}: connection closed")
        lines.append(bytes(line).rstrip(b"\r\n"))
        if len(line) >= 4 and line[3:4] == b" ":
            break
    try:
        code = int(lines[-1][:3])
    except ValueError as e:
        raise smtplib.SMTPServerDisconnected(f"{stage}: invalid reply {lines[-1]!r}") from e
    return code, b"\n".join(lines)


def _raw_command(sock: socket.socket, stage: str, command: str, expected: Sequence[int]) -> Tuple[int, bytes]:
    logger.info("SMTP stage: %s", stage)
    sock.sendall(command.encode("ascii") + b"\r\n")
    code, reply = _read_reply(sock, stage)
    if code not in expected:
        raise smtplib.SMTPResponseException(code, reply)
    return code, reply


def _raw_auth_login(sock: socket.socket, username: str, password: str):
    _raw_command(sock, "AUTH LOGIN", "AUTH LOGIN", (334,))
    _raw_command(sock, "AUTH USER", base64.b64encode(username.encode()).decode("ascii"), (334,))
    _raw_command(sock, "AUTH PASSWORD", base64.b64encode(password.encode()).decode("ascii"), (235,))


def _send_raw_socket(
    host: str,
    port: int,
    msg: Message,
    sender: str,
    recipients: Sequence[str],
    timeout: int,
    *,
    starttls: bool = False,
    username: str = "",
    password: str = "",
):
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        code, reply = _read_reply(sock, "CONNECT")
        if code != 220:
            raise smtplib.SMTPConnectError(code, reply)

        _raw_command(sock, "EHLO netguard-srv", "EHLO netguard-srv", (250,))
        if starttls:
            _raw_command(sock, "STARTTLS", "STARTTLS", (220,))
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
            sock.settimeout(timeout)
            _raw_command(sock, "EHLO netguard-srv", "EHLO netguard-srv", (250,))

        if username:
            _raw_auth_login(sock, username, password)

        _raw_command(sock, f"MAIL FROM <{sender}>", f"MAIL FROM:<{sender}>", (250,))
        accepted = []
        refused = {}
        for recipient in recipients:
            try:
                _raw_command(sock, f"RCPT TO <{recipient}>", f"RCPT TO:<{recipient}>", (250, 251))
                accepted.append(recipient)
            except smtplib.SMTPResponseException as e:
                refused[recipient] = (e.smtp_code, e.smtp_error)
        if not accepted:
            raise smtplib.SMTPRecipientsRefused(refused)

        _raw_command(sock, "DATA", "DATA", (354,))
        sock.sendall(_payload_bytes(msg) + b".\r\n")
        code, reply = _read_reply(sock, "DATA body")
        if code != 250:
            raise smtplib.SMTPDataError(code, reply)
        _raw_command(sock, "QUIT", "QUIT", (221,))
    finally:
        try:
            sock.close()
        except Exception:
            pass


def send_smtp_message(settings, msg: Message, recipients: Sequence[str]):
    timeout = int(getattr(settings, "SMTP_TIMEOUT", 30) or 30)
    host = settings.SMTP_HOST
    port = int(settings.SMTP_PORT)
    sender = settings.SMTP_FROM
    starttls = bool(getattr(settings, "SMTP_STARTTLS", False))
    username = getattr(settings, "SMTP_USER", "") or ""
    password = getattr(settings, "SMTP_PASSWORD", "") or ""

    if port != 465:
        try:
            _send_raw_socket(
                host,
                port,
                msg,
                sender,
                recipients,
                timeout,
                starttls=starttls,
                username=username,
                password=password,
            )
            return
        except Exception as e:
            logger.warning("Raw SMTP send failed, retrying with smtplib: %s", e)

    smtp_cls = smtplib.SMTP_SSL if port == 465 else smtplib.SMTP
    smtp = smtp_cls(host, port, timeout=timeout)
    try:
        _smtp_ehlo_upper(smtp)
        if port != 465 and starttls:
            smtp.starttls()
            _smtp_ehlo_upper(smtp)
        if username:
            if port != 465 and not starttls:
                smtp.starttls()
                _smtp_ehlo_upper(smtp)
            smtp.login(username, password)
        _smtp_send_message_upper(smtp, msg, sender, recipients)
    finally:
        try:
            smtp.docmd("QUIT")
        except Exception:
            smtp.close()
