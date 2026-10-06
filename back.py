"""
MailFlow X — Backend Server
====================================================================
Interactive Email Protocol Failure & Recovery Simulator

This is a SIMULATOR. It does NOT:
  - Send real emails
  - Connect to Gmail/Outlook or any real SMTP/POP3/IMAP server
  - Require real credentials
  - Use any external email service

Everything is simulated locally in Python.

Project layout (two files only):
    mailflow-x/
    ├── back.py          ← this file
    ├── index.html       ← frontend
    └── database/        ← auto-created on first run

Run:
    pip install Flask
    python back.py
Then open http://127.0.0.1:5000
====================================================================
"""

import os
import sqlite3
import json
import random
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory

# ============================================================
# FLASK APP CONFIGURATION
# ============================================================
# Both back.py and index.html live in the same folder, so
# BASE_DIR is used for both static and template lookup.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_DIR, "mailflow.db")

app = Flask(
    __name__,
    static_folder=BASE_DIR,       # serve static files (index.html) from project root
    template_folder=BASE_DIR,     # (not really used, but harmless)
)
app.config["JSON_SORT_KEYS"] = False


# ============================================================
# DATABASE INITIALIZATION
# ============================================================
def init_database():
    """Create the database folder and required tables if missing."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Simulation history
    cur.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sim_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            protocol TEXT NOT NULL,
            scenario TEXT NOT NULL,
            result TEXT NOT NULL,
            failure_type TEXT,
            duration TEXT,
            events_json TEXT
        )
    """)

    # Simulated mailbox (messages stored by SMTP, read by POP3/IMAP)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS mailbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            sender TEXT NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            received_at TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            is_deleted INTEGER DEFAULT 0
        )
    """)

    # Experiment progress
    cur.execute("""
        CREATE TABLE IF NOT EXISTS experiments (
            id TEXT PRIMARY KEY,
            completed INTEGER DEFAULT 0,
            score INTEGER DEFAULT 0,
            completed_at TEXT
        )
    """)

    conn.commit()
    conn.close()


def get_db():
    """Return a new SQLite connection with row access by name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# DNS / MX ENGINE
# ============================================================
class DNSEngine:
    """
    Simulated DNS resolver.

    Real email flow:
      1. Client asks a DNS resolver for the MX record of the recipient domain.
      2. MX record points to a mail server hostname.
      3. A second DNS query resolves that hostname to an IP address.

    Here we deterministically generate MX hosts and IPs for any domain.
    """

    @staticmethod
    def lookup_mx(domain):
        return {
            "domain": domain,
            "mx_host": f"mail.{domain}",
            "priority": 10,
            "status": "RESOLVED",
            "protocol": "DNS",
            "port": 53,
            "transport": "UDP",
        }

    @staticmethod
    def lookup_a(hostname):
        # Deterministic fake IP based on hostname hash (stable across runs)
        h = abs(hash(hostname)) % 254 + 1
        return {
            "hostname": hostname,
            "ip": f"192.0.2.{h}",
            "status": "RESOLVED",
            "protocol": "DNS",
            "port": 53,
            "transport": "UDP",
        }

    @staticmethod
    def full_lookup(recipient):
        domain = recipient.split("@")[-1] if "@" in recipient else recipient
        mx = DNSEngine.lookup_mx(domain)
        a = DNSEngine.lookup_a(mx["mx_host"])
        return {
            "domain": domain,
            "mx_record": mx["mx_host"],
            "mx_priority": mx["priority"],
            "resolved_ip": a["ip"],
            "status": "RESOLVED",
        }


# ============================================================
# PROTOCOL MEANINGS (used by the simulation engines)
# ============================================================
PROTOCOL_MEANINGS = {
    "DNS Query":     {"app": "DNS",  "trans": "UDP", "port": 53,  "meaning": "Client asks the DNS resolver for the MX record of the recipient domain."},
    "MX Response":   {"app": "DNS",  "trans": "UDP", "port": 53,  "meaning": "DNS resolver returns the MX record pointing to the mail server hostname."},
    "A Response":    {"app": "DNS",  "trans": "UDP", "port": 53,  "meaning": "DNS resolver returns the IPv4 address of the mail server."},
    "SYN":           {"app": "TCP",  "trans": "TCP", "port": 587, "meaning": "Client initiates a TCP three-way handshake with the SMTP server."},
    "SYN-ACK":       {"app": "TCP",  "trans": "TCP", "port": 587, "meaning": "Server acknowledges the SYN and sends its own sequence number."},
    "ACK":           {"app": "TCP",  "trans": "TCP", "port": 587, "meaning": "Client acknowledges the server SYN; connection established."},
    "220 Greeting":  {"app": "SMTP", "trans": "TCP", "port": 587, "meaning": "Server announces readiness for an SMTP conversation."},
    "EHLO":          {"app": "SMTP", "trans": "TCP", "port": 587, "meaning": "Client introduces itself and requests supported extensions."},
    "250 EHLO OK":   {"app": "SMTP", "trans": "TCP", "port": 587, "meaning": "Server accepts EHLO and lists capabilities."},
    "STARTTLS":      {"app": "SMTP", "trans": "TCP", "port": 587, "meaning": "Client requests an upgrade of the channel to TLS."},
    "220 TLS Ready": {"app": "SMTP", "trans": "TCP", "port": 587, "meaning": "Server accepts STARTTLS; a TLS handshake begins."},
    "AUTH LOGIN":    {"app": "SMTP", "trans": "TCP", "port": 587, "meaning": "Client begins SASL LOGIN authentication."},
    "235 Auth OK":   {"app": "SMTP", "trans": "TCP", "port": 587, "meaning": "Server accepts credentials; session authenticated."},
    "MAIL FROM":     {"app": "SMTP", "trans": "TCP", "port": 587, "meaning": "Client specifies the envelope sender."},
    "250 MAIL OK":   {"app": "SMTP", "trans": "TCP", "port": 587, "meaning": "Server accepts the sender address."},
    "RCPT TO":       {"app": "SMTP", "trans": "TCP", "port": 587, "meaning": "Client specifies one recipient for the message."},
    "250 RCPT OK":   {"app": "SMTP", "trans": "TCP", "port": 587, "meaning": "Server accepts the recipient address."},
    "DATA":          {"app": "SMTP", "trans": "TCP", "port": 587, "meaning": "Client signals it is about to transmit the message content."},
    "354 Data Go":   {"app": "SMTP", "trans": "TCP", "port": 587, "meaning": "Server tells the client to start sending the body."},
    "250 Accepted":  {"app": "SMTP", "trans": "TCP", "port": 587, "meaning": "Server accepted the message and queued it for delivery."},
    "USER":          {"app": "POP3", "trans": "TCP", "port": 110, "meaning": "Client sends the mailbox username."},
    "PASS":          {"app": "POP3", "trans": "TCP", "port": 110, "meaning": "Client sends the mailbox password (masked)."},
    "+OK Login":     {"app": "POP3", "trans": "TCP", "port": 110, "meaning": "Server accepted credentials; mailbox is locked."},
    "STAT":          {"app": "POP3", "trans": "TCP", "port": 110, "meaning": "Client requests message count and total size."},
    "LIST":          {"app": "POP3", "trans": "TCP", "port": 110, "meaning": "Client requests the list of message numbers and sizes."},
    "RETR":          {"app": "POP3", "trans": "TCP", "port": 110, "meaning": "Client retrieves a specific message."},
    "DELE":          {"app": "POP3", "trans": "TCP", "port": 110, "meaning": "Client marks a message for deletion."},
    "QUIT":          {"app": "POP3", "trans": "TCP", "port": 110, "meaning": "Ends the POP3 session and commits deletions."},
    "LOGIN":         {"app": "IMAP", "trans": "TCP", "port": 143, "meaning": "Client authenticates with username and password."},
    "OK LOGIN":      {"app": "IMAP", "trans": "TCP", "port": 143, "meaning": "Server accepted credentials."},
    "SELECT INBOX":  {"app": "IMAP", "trans": "TCP", "port": 143, "meaning": "Client opens the INBOX mailbox."},
    "OK INBOX":      {"app": "IMAP", "trans": "TCP", "port": 143, "meaning": "Server selected the mailbox; message count returned."},
    "FETCH":         {"app": "IMAP", "trans": "TCP", "port": 143, "meaning": "Client requests message headers or bodies."},
    "STORE":         {"app": "IMAP", "trans": "TCP", "port": 143, "meaning": "Client updates flags on a message."},
    "EXPUNGE":       {"app": "IMAP", "trans": "TCP", "port": 143, "meaning": "Client permanently removes messages marked as deleted."},
    "LOGOUT":        {"app": "IMAP", "trans": "TCP", "port": 143, "meaning": "Client closes the IMAP session gracefully."},
}


# ============================================================
# SMTP ENGINE
# ============================================================
class SMTPEngine:
    """
    Simulated SMTP server engine (RFC 5321).
    Produces a list of events representing the SMTP conversation.
    """

    @staticmethod
    def simulate(sender, recipient, subject, message, failure=None):
        events = []
        domain = recipient.split("@")[-1] if "@" in recipient else "example.com"
        mx_host = f"mail.{domain}"
        mx_ip = DNSEngine.lookup_a(mx_host)["ip"]

        def add(protocol, command, response, status, sender_side, receiver_side,
                text, node=None, node_state="processing", conn=None,
                timeline_label=None, port=587, meaning=""):
            events.append({
                "step": len(events) + 1,
                "protocol": protocol,
                "command": command,
                "response": response,
                "status": status,
                "sender": sender_side,
                "receiver": receiver_side,
                "text": text,
                "node": node,
                "node_state": node_state,
                "conn": conn,
                "timeline_label": timeline_label or command,
                "port": port,
                "meaning": meaning or PROTOCOL_MEANINGS.get(command, {}).get("meaning", ""),
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            })

        # ---- DNS FAILURE SHORT-CIRCUIT ----
        if failure == "dns_unavailable":
            add("DNS", "DNS Query", "—", "success", "Client", "DNS Resolver",
                f"C: DNS MX lookup for {domain}", node="topo-client",
                node_state="processing", conn="conn-client-dns",
                timeline_label="DNS Query", port=53)
            add("ERROR", "DNS NXDOMAIN", "NXDOMAIN", "failed", "DNS Resolver", "Client",
                f"S: NXDOMAIN — {domain} could not be resolved",
                node="topo-dns", node_state="failed", conn="conn-client-dns",
                timeline_label="DNS Failed", port=53,
                meaning="The queried domain does not exist in the DNS namespace.")
            return SMTPEngine._result(events, "failed", "DNS Lookup", "DNS",
                                      "NXDOMAIN", "DNS resolution failed for " + domain,
                                      failure)

        # ---- DNS SUCCESS ----
        add("DNS", "DNS Query", "—", "success", "Client", "DNS Resolver",
            f"C: DNS MX lookup for {domain}", node="topo-client",
            node_state="processing", conn="conn-client-dns",
            timeline_label="DNS Query", port=53)

        add("DNS", "MX Response", f"MX {mx_host}", "success", "DNS Resolver", "Client",
            f"S: MX {mx_host} (priority 10)", node="topo-dns",
            node_state="success", conn="conn-client-dns",
            timeline_label="MX Record", port=53)

        add("DNS", "A Response", f"A {mx_ip}", "success", "DNS Resolver", "Client",
            f"S: A {mx_ip} (mail server IPv4)", node="topo-dns",
            node_state="success", conn="conn-dns-smtp",
            timeline_label="A Record", port=53)

        # ---- SMTP OFFLINE / PORT BLOCKED / TIMEOUT ----
        if failure == "smtp_offline":
            add("TCP", "SYN", "—", "success", "Client", "SMTP Server",
                f"C: SYN → {mx_host}:587", node="topo-client",
                node_state="processing", conn="conn-dns-smtp",
                timeline_label="TCP SYN")
            add("ERROR", "Connection Refused", "RST", "failed", "SMTP Server", "Client",
                "S: TCP RST — connection refused (no listener on port 587)",
                node="topo-smtp", node_state="failed", conn="conn-dns-smtp",
                timeline_label="Refused")
            return SMTPEngine._result(events, "failed", "SMTP Connection", "SMTP",
                                      "Connection refused", "SMTP server is unavailable.",
                                      failure)

        if failure in ("smtp_port_blocked", "connection_timeout"):
            add("TCP", "SYN", "—", "success", "Client", "SMTP Server",
                f"C: SYN → {mx_host}:587", node="topo-client",
                node_state="processing", conn="conn-dns-smtp",
                timeline_label="TCP SYN")
            add("ERROR", "Connection Timeout", "timeout", "failed", "SMTP Server", "Client",
                "S: no response within timeout window — connection timed out",
                node="topo-smtp", node_state="failed", conn="conn-dns-smtp",
                timeline_label="Timeout")
            return SMTPEngine._result(events, "failed", "TCP Connection", "TCP",
                                      "Connection timed out",
                                      "Server unreachable or packets silently dropped.",
                                      failure)

        # ---- NORMAL TCP HANDSHAKE ----
        add("TCP", "SYN", "—", "success", "Client", "SMTP Server",
            f"C: SYN → {mx_host}:587", node="topo-client",
            node_state="processing", conn="conn-dns-smtp",
            timeline_label="TCP SYN")
        add("TCP", "SYN-ACK", "SYN-ACK", "success", "SMTP Server", "Client",
            "S: SYN-ACK", node="topo-smtp", node_state="processing",
            conn="conn-dns-smtp", timeline_label="TCP SYN-ACK")
        add("TCP", "ACK", "—", "success", "Client", "SMTP Server",
            "C: ACK — TCP connection established", node="topo-client",
            node_state="success", conn="conn-dns-smtp",
            timeline_label="TCP ACK")

        # ---- SMTP GREETING ----
        add("SMTP", "220 Greeting", f"220 {mx_host} SMTP Ready", "success",
            "SMTP Server", "Client", f"S: 220 {mx_host} SMTP Ready",
            node="topo-smtp", node_state="success", conn="conn-smtp-relay",
            timeline_label="220 Greeting")

        add("SMTP", "EHLO", "—", "success", "Client", "SMTP Server",
            "C: EHLO client.local", node="topo-client",
            node_state="processing", conn="conn-smtp-relay",
            timeline_label="EHLO")

        add("SMTP", "250 EHLO OK", f"250 {mx_host}", "success",
            "SMTP Server", "Client",
            f"S: 250-{mx_host} — STARTTLS, AUTH LOGIN supported",
            node="topo-smtp", node_state="success", conn="conn-smtp-relay",
            timeline_label="250 EHLO")

        # ---- STARTTLS ----
        add("SMTP", "STARTTLS", "—", "success", "Client", "SMTP Server",
            "C: STARTTLS", node="topo-client", node_state="processing",
            conn="conn-smtp-relay", timeline_label="STARTTLS")

        if failure == "starttls_failure":
            add("ERROR", "454 TLS Unavailable", "454 TLS not available", "failed",
                "SMTP Server", "Client",
                "S: 454 TLS not available — session aborted",
                node="topo-smtp", node_state="failed", conn="conn-smtp-relay",
                timeline_label="TLS Failed",
                meaning="The server does not support or cannot start TLS.")
            return SMTPEngine._result(events, "failed", "STARTTLS", "SMTP",
                                      "454 TLS not available",
                                      "Server cannot negotiate TLS.",
                                      failure)

        add("SMTP", "220 TLS Ready", "220 Ready to start TLS", "success",
            "SMTP Server", "Client", "S: 220 Ready to start TLS",
            node="topo-smtp", node_state="success", conn="conn-smtp-relay",
            timeline_label="220 TLS")

        # ---- AUTH ----
        add("SMTP", "AUTH LOGIN", "—", "success", "Client", "SMTP Server",
            "C: AUTH LOGIN (base64 credentials — simulated)",
            node="topo-client", node_state="processing", conn="conn-smtp-relay",
            timeline_label="AUTH LOGIN")

        if failure == "auth_failure":
            add("ERROR", "535 Auth Failed", "535 Authentication failed", "failed",
                "SMTP Server", "Client",
                "S: 535 Authentication failed — credentials rejected",
                node="topo-smtp", node_state="failed", conn="conn-smtp-relay",
                timeline_label="Auth Failed")
            return SMTPEngine._result(events, "failed", "AUTH", "SMTP",
                                      "535 Authentication failed",
                                      "Incorrect username or password.",
                                      failure)

        add("SMTP", "235 Auth OK", "235 Authentication successful", "success",
            "SMTP Server", "Client", "S: 235 Authentication successful",
            node="topo-smtp", node_state="success", conn="conn-smtp-relay",
            timeline_label="235 Auth OK")

        # ---- MAIL FROM ----
        add("SMTP", "MAIL FROM", "—", "success", "Client", "SMTP Server",
            f"C: MAIL FROM:<{sender}>", node="topo-client",
            node_state="processing", conn="conn-smtp-relay",
            timeline_label="MAIL FROM")

        if failure == "invalid_sender":
            add("ERROR", "550 Sender Fail", "550 Sender rejected", "failed",
                "SMTP Server", "Client",
                "S: 550 Sender rejected — relay denied",
                node="topo-smtp", node_state="failed", conn="conn-smtp-relay",
                timeline_label="550 Sender")
            return SMTPEngine._result(events, "failed", "MAIL FROM", "SMTP",
                                      "550 Sender rejected",
                                      "Sender address is not permitted to relay.",
                                      failure)

        add("SMTP", "250 MAIL OK", "250 OK", "success", "SMTP Server", "Client",
            "S: 250 OK", node="topo-smtp", node_state="success",
            conn="conn-smtp-relay", timeline_label="250 MAIL")

        # ---- RCPT TO ----
        add("SMTP", "RCPT TO", "—", "success", "Client", "SMTP Server",
            f"C: RCPT TO:<{recipient}>", node="topo-client",
            node_state="processing", conn="conn-smtp-relay",
            timeline_label="RCPT TO")

        if failure == "invalid_recipient":
            add("ERROR", "550 RCPT Fail", "550 User unknown", "failed",
                "SMTP Server", "Client",
                "S: 550 User unknown — RCPT TO rejected",
                node="topo-smtp", node_state="failed", conn="conn-smtp-relay",
                timeline_label="550 RCPT")
            return SMTPEngine._result(events, "failed", "RCPT TO", "SMTP",
                                      "550 User unknown",
                                      "Recipient mailbox does not exist.",
                                      failure)

        add("SMTP", "250 RCPT OK", "250 OK", "success", "SMTP Server", "Client",
            "S: 250 OK", node="topo-smtp", node_state="success",
            conn="conn-smtp-relay", timeline_label="250 RCPT")

        # ---- DATA ----
        add("SMTP", "DATA", "—", "success", "Client", "SMTP Server",
            "C: DATA", node="topo-client", node_state="processing",
            conn="conn-smtp-relay", timeline_label="DATA")

        add("SMTP", "354 Data Go", "354 Start mail input", "success",
            "SMTP Server", "Client",
            "S: 354 Start mail input; end with <CRLF>.<CRLF>",
            node="topo-smtp", node_state="success", conn="conn-smtp-relay",
            timeline_label="354 Data")

        add("SMTP", "MESSAGE DATA", "—", "success", "Client", "SMTP Server",
            f"C: Subject: {subject} | Body: {message}",
            node="topo-client", node_state="processing",
            conn="conn-relay-mailbox", timeline_label="Body")

        if failure == "mailbox_full":
            add("ERROR", "552 Mailbox Full", "552 Mailbox full", "failed",
                "Mail Relay", "Client",
                "S: 552 Mailbox full — message rejected",
                node="topo-mailbox", node_state="failed",
                conn="conn-relay-mailbox", timeline_label="552 Full")
            return SMTPEngine._result(events, "failed", "DELIVERY", "SMTP",
                                      "552 Mailbox full",
                                      "Recipient quota exceeded.",
                                      failure)

        add("SMTP", "250 Accepted", "250 Message accepted", "success",
            "SMTP Server", "Client", "S: 250 Message accepted for delivery",
            node="topo-relay", node_state="success",
            conn="conn-relay-mailbox", timeline_label="250 Accepted")

        add("SMTP", "DELIVERED", "stored", "success", "Mail Relay", "Mailbox",
            "→ Message stored in recipient mailbox",
            node="topo-mailbox", node_state="success",
            conn="conn-relay-mailbox", timeline_label="Delivered")

        # ---- PERSIST TO SIMULATED MAILBOX ----
        SMTPEngine._store_message(sender, recipient, subject, message)

        result = SMTPEngine._result(events, "success", "Complete", "SMTP",
                                    "250 Message accepted",
                                    "Message delivered successfully.",
                                    failure)

        if failure == "network_delay":
            result["latency_ms"] = 3000

        return result

    @staticmethod
    def _store_message(sender, recipient, subject, message):
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO mailbox (recipient, sender, subject, body, received_at, is_read, is_deleted)
                VALUES (?, ?, ?, ?, ?, 0, 0)
            """, (recipient, sender, subject, message, datetime.now().isoformat()))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[SMTP] Failed to store message: {e}")

    @staticmethod
    def _result(events, status, stage, protocol, error, cause, failure):
        return {
            "status": status,
            "protocol": protocol,
            "stage": stage,
            "error": error,
            "cause": cause,
            "failure": failure,
            "events": events,
            "total_events": len(events),
        }


# ============================================================
# POP3 ENGINE
# ============================================================
class POP3Engine:
    """Simulated POP3 client/server engine (RFC 1939)."""

    @staticmethod
    def simulate(username, password, failure=None):
        events = []
        port = 110

        def add(command, response, status, side, text, meaning=""):
            events.append({
                "step": len(events) + 1,
                "protocol": "POP3",
                "command": command,
                "response": response,
                "status": status,
                "sender": "Client" if side == "client" else "POP3 Server",
                "receiver": "POP3 Server" if side == "client" else "Client",
                "text": text,
                "side": side,
                "port": port,
                "meaning": meaning or PROTOCOL_MEANINGS.get(command, {}).get("meaning", ""),
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            })

        add("USER", "—", "success", "client", f"C: USER {username}")
        add("+OK User", "+OK", "success", "server", "S: +OK User accepted")
        add("PASS", "—", "success", "client", "C: PASS ********")

        if failure == "pop3_auth_failure":
            add("-ERR Auth", "-ERR Authentication failed", "failed", "server",
                "S: -ERR Authentication failed")
            return {
                "status": "failed", "protocol": "POP3", "stage": "AUTH",
                "error": "-ERR Authentication failed",
                "cause": "Incorrect POP3 username or password.",
                "failure": failure, "events": events, "total_events": len(events),
            }

        add("+OK Login", "+OK Login successful", "success", "server",
            "S: +OK Login successful, mailbox locked")
        add("STAT", "+OK 2 3200", "success", "client", "C: STAT")
        add("+OK STAT", "+OK 2 3200", "success", "server", "S: +OK 2 messages (3200 octets)")
        add("LIST", "+OK 2 messages", "success", "client", "C: LIST")
        add("+OK LIST", "+OK\n1 1600\n2 1600", "success", "server",
            "S: +OK 2 messages (1600 octets each)")
        add("RETR", "+OK 1600 octets", "success", "client", "C: RETR 1")
        add("+OK RETR", "+OK 1600 octets", "success", "server",
            "S: +OK 1600 octets — Subject: Network Lab Test")
        add("DELE", "+OK marked", "success", "client", "C: DELE 1")
        add("+OK DELE", "+OK message 1 deleted", "success", "server",
            "S: +OK message 1 marked for deletion")
        add("QUIT", "+OK bye", "success", "client", "C: QUIT")
        add("+OK QUIT", "+OK goodbye", "success", "server",
            "S: +OK POP3 server signing off")

        return {
            "status": "success", "protocol": "POP3", "stage": "Complete",
            "error": "", "cause": "Messages downloaded and marked for deletion.",
            "failure": failure, "events": events, "total_events": len(events),
        }


# ============================================================
# IMAP ENGINE
# ============================================================
class IMAPEngine:
    """Simulated IMAP client/server engine (RFC 3501)."""

    @staticmethod
    def simulate(username, password, failure=None):
        events = []
        port = 143

        def add(command, response, status, side, text, meaning=""):
            events.append({
                "step": len(events) + 1,
                "protocol": "IMAP",
                "command": command,
                "response": response,
                "status": status,
                "sender": "Client" if side == "client" else "IMAP Server",
                "receiver": "IMAP Server" if side == "client" else "Client",
                "text": text,
                "side": side,
                "port": port,
                "meaning": meaning or PROTOCOL_MEANINGS.get(command, {}).get("meaning", ""),
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            })

        add("LOGIN", "—", "success", "client",
            f"C: a001 LOGIN {username} ********")

        if failure == "imap_auth_failure":
            add("NO LOGIN", "a001 NO LOGIN failed", "failed", "server",
                "S: a001 NO LOGIN failed")
            return {
                "status": "failed", "protocol": "IMAP", "stage": "AUTH",
                "error": "NO LOGIN failed",
                "cause": "Incorrect IMAP credentials.",
                "failure": failure, "events": events, "total_events": len(events),
            }

        add("OK LOGIN", "a001 OK LOGIN completed", "success", "server",
            "S: a001 OK LOGIN completed")
        add("SELECT INBOX", "—", "success", "client", "C: a002 SELECT INBOX")
        add("OK INBOX", "a002 OK INBOX selected (2 messages)", "success", "server",
            "S: * 2 EXISTS\nS: * 0 RECENT\nS: a002 OK INBOX selected")
        add("FETCH", "—", "success", "client",
            "C: a003 FETCH 1:2 (FLAGS BODY.PEEK[HEADER])")
        add("FETCH DATA", "* 1 FETCH (FLAGS (\\Seen) BODY[HEADER])", "success", "server",
            "S: * 1 FETCH (FLAGS (\\Seen) Subject: Network Lab Test)\nS: a003 OK FETCH completed")
        add("STORE", "—", "success", "client",
            "C: a004 STORE 1 +FLAGS (\\Flagged)")
        add("OK STORE", "a004 OK STORE completed", "success", "server",
            "S: * 1 FETCH (FLAGS (\\Seen \\Flagged))\nS: a004 OK STORE completed")
        add("EXPUNGE", "—", "success", "client", "C: a005 EXPUNGE")
        add("OK EXPUNGE", "a005 OK EXPUNGE completed", "success", "server",
            "S: a005 OK EXPUNGE completed")
        add("LOGOUT", "—", "success", "client", "C: a006 LOGOUT")
        add("OK LOGOUT", "* BYE\n a006 OK LOGOUT completed", "success", "server",
            "S: * BYE IMAP4rev1 Server logging out\nS: a006 OK LOGOUT completed")

        return {
            "status": "success", "protocol": "IMAP", "stage": "Complete",
            "error": "", "cause": "Mailbox state synchronised with server.",
            "failure": failure, "events": events, "total_events": len(events),
        }


# ============================================================
# FAILURE ENGINE
# ============================================================
class FailureEngine:
    """
    Central failure rule book.
    Each failure id maps to stage / protocol / error / cause / layer /
    investigation steps / recommended fix.
    """

    RULES = {
        "dns_unavailable": {
            "stage": "DNS Lookup", "protocol": "DNS", "error": "NXDOMAIN",
            "cause": "DNS resolution failed for the recipient domain.",
            "layer": "Application / Network dependency",
            "investigation": ["Check DNS server configuration",
                              "Verify the recipient domain exists",
                              "Test with nslookup or dig",
                              "Check network connectivity to the resolver"],
            "recommended_fix": "Verify DNS configuration and MX record resolution.",
        },
        "smtp_offline": {
            "stage": "SMTP Connection", "protocol": "SMTP", "error": "Connection refused",
            "cause": "SMTP server is unavailable.",
            "layer": "Application Layer (SMTP)",
            "investigation": ["Check server availability",
                              "Verify port 587 is listening",
                              "Check network connectivity",
                              "Retry the connection"],
            "recommended_fix": "Verify SMTP server availability and port configuration.",
        },
        "smtp_port_blocked": {
            "stage": "TCP Connection", "protocol": "TCP", "error": "Connection timed out",
            "cause": "Firewall or network policy blocking port 587.",
            "layer": "Transport Layer",
            "investigation": ["Check firewall rules",
                              "Verify outbound port 587 is permitted",
                              "Test connectivity with telnet or nc",
                              "Review ACLs on intermediate devices"],
            "recommended_fix": "Open port 587 in the firewall or use an alternate submission port.",
        },
        "starttls_failure": {
            "stage": "STARTTLS", "protocol": "SMTP", "error": "454 TLS not available",
            "cause": "Server cannot negotiate TLS.",
            "layer": "Application Layer (SMTP)",
            "investigation": ["Check server TLS configuration",
                              "Verify the certificate chain",
                              "Test with openssl s_client",
                              "Check the server's supported cipher suites"],
            "recommended_fix": "Verify the server's TLS configuration and certificate validity.",
        },
        "auth_failure": {
            "stage": "AUTH", "protocol": "SMTP", "error": "535 Authentication failed",
            "cause": "The server rejected the supplied credentials.",
            "layer": "Application Layer (SMTP)",
            "investigation": ["Verify the username and password",
                              "Check the account status",
                              "Ensure TLS is enabled before AUTH",
                              "Check for IP-based restrictions"],
            "recommended_fix": "Verify username and password, and ensure the account is active.",
        },
        "invalid_sender": {
            "stage": "MAIL FROM", "protocol": "SMTP", "error": "550 Sender rejected",
            "cause": "Sender address is not permitted to relay.",
            "layer": "Application Layer (SMTP)",
            "investigation": ["Check the sender address format",
                              "Verify the domain's SPF/DKIM records",
                              "Check relay permissions",
                              "Review server access lists"],
            "recommended_fix": "Check the sender address and relay permissions.",
        },
        "invalid_recipient": {
            "stage": "RCPT TO", "protocol": "SMTP", "error": "550 User unknown",
            "cause": "The recipient was rejected by the SMTP server.",
            "layer": "Application Layer (SMTP)",
            "investigation": ["Verify the recipient address",
                              "Check whether the mailbox exists",
                              "Verify the domain's MX records",
                              "Check for recipient-side filtering"],
            "recommended_fix": "Verify the recipient address and domain MX records.",
        },
        "mailbox_full": {
            "stage": "DELIVERY", "protocol": "SMTP", "error": "552 Mailbox full",
            "cause": "Recipient mailbox has exceeded its storage quota.",
            "layer": "Application Layer (SMTP)",
            "investigation": ["Ask the recipient to free up space",
                              "Check the mailbox quota settings",
                              "Retry after the mailbox is cleared",
                              "Consider increasing the quota"],
            "recommended_fix": "Ask the recipient to free space or increase the quota.",
        },
        "network_delay": {
            "stage": "Network", "protocol": "TCP", "error": "High latency",
            "cause": "Simulated network delay of 3000 ms.",
            "layer": "Transport Layer",
            "investigation": ["Check network congestion",
                              "Verify routing paths",
                              "Test with ping or traceroute",
                              "Check for bandwidth saturation"],
            "recommended_fix": "Investigate routing and network utilisation.",
        },
        "pop3_auth_failure": {
            "stage": "POP3 AUTH", "protocol": "POP3", "error": "-ERR Authentication failed",
            "cause": "POP3 username or password is incorrect.",
            "layer": "Application Layer (POP3)",
            "investigation": ["Verify POP3 credentials",
                              "Check the account settings",
                              "Ensure POP3 access is enabled",
                              "Check for IP restrictions"],
            "recommended_fix": "Verify POP3 credentials and account status.",
        },
        "imap_auth_failure": {
            "stage": "IMAP AUTH", "protocol": "IMAP", "error": "NO LOGIN failed",
            "cause": "IMAP authentication was rejected.",
            "layer": "Application Layer (IMAP)",
            "investigation": ["Verify IMAP credentials",
                              "Check the IMAP server settings",
                              "Ensure the account is active",
                              "Check for OAuth2 requirements"],
            "recommended_fix": "Verify IMAP credentials and account status.",
        },
        "connection_timeout": {
            "stage": "TCP Connection", "protocol": "TCP", "error": "Connection timed out",
            "cause": "No response from the server within the timeout window.",
            "layer": "Transport Layer",
            "investigation": ["Check server status",
                              "Verify the IP address is correct",
                              "Check firewall rules",
                              "Test with ping or telnet"],
            "recommended_fix": "Check server status, IP address and firewall rules.",
        },
    }

    @staticmethod
    def get_diagnosis(failure_id):
        rule = FailureEngine.RULES.get(failure_id)
        if not rule:
            return {
                "failure": failure_id, "stage": "Unknown", "protocol": "—",
                "error": "Unknown failure", "cause": "No rule defined for this failure id.",
                "layer": "—", "investigation": [], "recommended_fix": "—",
            }
        return {
            "failure": failure_id,
            "stage": rule["stage"], "protocol": rule["protocol"],
            "error": rule["error"], "cause": rule["cause"],
            "layer": rule["layer"], "investigation": rule["investigation"],
            "recommended_fix": rule["recommended_fix"],
        }

    @staticmethod
    def list_failures():
        return [
            {
                "id": fid,
                "label": fid.replace("_", " ").title(),
                "stage": rule["stage"],
                "protocol": rule["protocol"],
                "error": rule["error"],
            }
            for fid, rule in FailureEngine.RULES.items()
        ]


# ============================================================
# FLASK ROUTES — PAGES
# ============================================================
@app.route("/")
def index():
    """Serve index.html directly from the project folder."""
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "MailFlow X",
        "time": datetime.now().isoformat(),
    })


# ============================================================
# FLASK ROUTES — SIMULATION APIS
# ============================================================
@app.route("/api/simulate/smtp", methods=["POST"])
def api_simulate_smtp():
    try:
        data = request.get_json(force=True) or {}
        sender = data.get("sender", "student@example.com")
        recipient = data.get("recipient", "receiver@example.com")
        subject = data.get("subject", "Network Lab Test")
        message = data.get("message", "Hello from MailFlow X.")
        failure = data.get("failure") or None

        if failure and failure not in FailureEngine.RULES:
            return jsonify({
                "status": "error",
                "message": f"Unknown failure id: {failure}",
                "valid_failures": list(FailureEngine.RULES.keys()),
            }), 400

        result = SMTPEngine.simulate(sender, recipient, subject, message, failure)

        if result["status"] == "failed" and failure:
            result["diagnosis"] = FailureEngine.get_diagnosis(failure)

        _save_history(
            protocol="SMTP",
            scenario=_scenario_label(failure),
            result=result["status"].upper(),
            failure_type=failure or "",
            duration=f"{random.uniform(0.8, 2.4):.1f}s",
            events=result["events"],
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/simulate/pop3", methods=["POST"])
def api_simulate_pop3():
    try:
        data = request.get_json(force=True) or {}
        username = data.get("username", "student")
        password = data.get("password", "********")
        failure = data.get("failure") or None

        result = POP3Engine.simulate(username, password, failure)
        if result["status"] == "failed" and failure:
            result["diagnosis"] = FailureEngine.get_diagnosis(failure)

        _save_history(
            protocol="POP3",
            scenario=_scenario_label(failure) if failure else "POP3 Retrieval",
            result=result["status"].upper(),
            failure_type=failure or "",
            duration=f"{random.uniform(0.5, 1.8):.1f}s",
            events=result["events"],
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/simulate/imap", methods=["POST"])
def api_simulate_imap():
    try:
        data = request.get_json(force=True) or {}
        username = data.get("username", "student")
        password = data.get("password", "********")
        failure = data.get("failure") or None

        result = IMAPEngine.simulate(username, password, failure)
        if result["status"] == "failed" and failure:
            result["diagnosis"] = FailureEngine.get_diagnosis(failure)

        _save_history(
            protocol="IMAP",
            scenario=_scenario_label(failure) if failure else "IMAP Synchronization",
            result=result["status"].upper(),
            failure_type=failure or "",
            duration=f"{random.uniform(0.6, 2.0):.1f}s",
            events=result["events"],
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/failure", methods=["POST"])
def api_failure():
    try:
        data = request.get_json(force=True) or {}
        failure = data.get("failure")
        if not failure:
            return jsonify({"status": "error", "message": "Missing failure id"}), 400
        if failure not in FailureEngine.RULES:
            return jsonify({
                "status": "error",
                "message": f"Unknown failure id: {failure}",
                "valid_failures": list(FailureEngine.RULES.keys()),
            }), 400

        sender = data.get("sender", "student@example.com")
        recipient = data.get("recipient", "receiver@example.com")
        subject = data.get("subject", "Network Lab Test")
        message = data.get("message", "Hello from MailFlow X.")

        result = SMTPEngine.simulate(sender, recipient, subject, message, failure)
        result["diagnosis"] = FailureEngine.get_diagnosis(failure)

        _save_history(
            protocol="SMTP",
            scenario=_scenario_label(failure),
            result=result["status"].upper(),
            failure_type=failure,
            duration=f"{random.uniform(1.2, 3.0):.1f}s",
            events=result["events"],
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/replay", methods=["POST"])
def api_replay():
    try:
        data = request.get_json(force=True) or {}
        sim_id = data.get("sim_id")
        if not sim_id:
            return jsonify({"status": "error", "message": "Missing sim_id"}), 400

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM history WHERE sim_id = ? ORDER BY id DESC LIMIT 1", (sim_id,))
        row = cur.fetchone()
        conn.close()

        if not row:
            return jsonify({"status": "error", "message": "Simulation not found"}), 404

        events = json.loads(row["events_json"]) if row["events_json"] else []
        return jsonify({
            "status": "success",
            "sim_id": row["sim_id"],
            "timestamp": row["timestamp"],
            "protocol": row["protocol"],
            "scenario": row["scenario"],
            "result": row["result"],
            "failure_type": row["failure_type"],
            "events": events,
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/dns/lookup", methods=["POST"])
def api_dns_lookup():
    try:
        data = request.get_json(force=True) or {}
        recipient = data.get("recipient", "receiver@example.com")
        result = DNSEngine.full_lookup(recipient)
        return jsonify({"status": "success", "protocol": "DNS", "lookup": result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ============================================================
# FLASK ROUTES — HISTORY
# ============================================================
@app.route("/api/history", methods=["GET"])
def api_history_get():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, sim_id, timestamp, protocol, scenario, result, failure_type, duration
            FROM history
            ORDER BY id DESC
            LIMIT 50
        """)
        rows = cur.fetchall()
        conn.close()
        return jsonify({
            "status": "success",
            "count": len(rows),
            "history": [dict(r) for r in rows],
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/history", methods=["POST"])
def api_history_post():
    try:
        data = request.get_json(force=True) or {}
        _save_history(
            protocol=data.get("protocol", "SMTP"),
            scenario=data.get("scenario", "Manual Entry"),
            result=data.get("result", "SUCCESS"),
            failure_type=data.get("failure_type", ""),
            duration=data.get("duration", "—"),
            events=data.get("events", []),
        )
        return jsonify({"status": "success", "message": "History record added"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/history", methods=["DELETE"])
def api_history_delete():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM history")
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "History cleared"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


def _save_history(protocol, scenario, result, failure_type, duration, events):
    try:
        conn = get_db()
        cur = conn.cursor()
        sim_id = _next_sim_id(conn)
        cur.execute("""
            INSERT INTO history
                (sim_id, timestamp, protocol, scenario, result, failure_type, duration, events_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            sim_id,
            datetime.now().strftime("%d %b %H:%M:%S"),
            protocol, scenario, result, failure_type, duration,
            json.dumps(events),
        ))
        conn.commit()
        conn.close()
        return sim_id
    except Exception as e:
        print(f"[DB] Failed to save history: {e}")
        return None


def _next_sim_id(conn):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM history")
    count = cur.fetchone()["c"] + 1
    return f"SIM-{count:03d}"


def _scenario_label(failure_id):
    if not failure_id:
        return "Normal Delivery"
    return failure_id.replace("_", " ").title()


# ============================================================
# FLASK ROUTES — MAILBOX (simulated storage)
# ============================================================
@app.route("/api/mailbox", methods=["GET"])
def api_mailbox_list():
    try:
        recipient = request.args.get("recipient")
        conn = get_db()
        cur = conn.cursor()
        if recipient:
            cur.execute("""
                SELECT id, recipient, sender, subject, body, received_at, is_read, is_deleted
                FROM mailbox WHERE recipient = ? AND is_deleted = 0
                ORDER BY id DESC
            """, (recipient,))
        else:
            cur.execute("""
                SELECT id, recipient, sender, subject, body, received_at, is_read, is_deleted
                FROM mailbox WHERE is_deleted = 0
                ORDER BY id DESC
            """)
        rows = cur.fetchall()
        conn.close()
        return jsonify({
            "status": "success",
            "count": len(rows),
            "messages": [dict(r) for r in rows],
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/mailbox/clear", methods=["POST"])
def api_mailbox_clear():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM mailbox")
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Mailbox cleared"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ============================================================
# FLASK ROUTES — FAILURES / EXPERIMENTS
# ============================================================
@app.route("/api/failures", methods=["GET"])
def api_failures():
    return jsonify({"status": "success", "failures": FailureEngine.list_failures()})


@app.route("/api/diagnosis/<failure_id>", methods=["GET"])
def api_diagnosis(failure_id):
    if failure_id not in FailureEngine.RULES:
        return jsonify({
            "status": "error",
            "message": f"Unknown failure id: {failure_id}",
            "valid_failures": list(FailureEngine.RULES.keys()),
        }), 404
    return jsonify({"status": "success", "diagnosis": FailureEngine.get_diagnosis(failure_id)})


@app.route("/api/experiments", methods=["GET"])
def api_experiments():
    experiments = [
        {"id": "exp1", "title": "Trace a successful SMTP transaction",
         "objective": "Observe EHLO → AUTH → MAIL FROM → RCPT TO → DATA.",
         "protocol": "SMTP", "failure": None},
        {"id": "exp2", "title": "Why can't the email reach the recipient?",
         "objective": "Diagnose invalid recipient rejection.",
         "protocol": "SMTP", "failure": "invalid_recipient"},
        {"id": "exp3", "title": "Compare POP3 and IMAP",
         "objective": "Observe download vs synchronisation behaviour.",
         "protocol": "POP3/IMAP", "failure": None},
        {"id": "exp4", "title": "Identify the protocol responsible for authentication",
         "objective": "Locate AUTH LOGIN in the trace.",
         "protocol": "SMTP", "failure": None},
        {"id": "exp5", "title": "Diagnose a DNS failure",
         "objective": "Observe NXDOMAIN and identify the DNS layer.",
         "protocol": "DNS", "failure": "dns_unavailable"},
        {"id": "exp6", "title": "Diagnose SMTP authentication failure",
         "objective": "Observe 535 and identify root cause.",
         "protocol": "SMTP", "failure": "auth_failure"},
    ]

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, completed, score FROM experiments")
    progress = {row["id"]: dict(row) for row in cur.fetchall()}
    conn.close()

    for exp in experiments:
        p = progress.get(exp["id"], {})
        exp["completed"] = bool(p.get("completed", 0))
        exp["score"] = p.get("score", 0)

    return jsonify({"status": "success", "experiments": experiments})


@app.route("/api/experiments/complete", methods=["POST"])
def api_experiment_complete():
    try:
        data = request.get_json(force=True) or {}
        exp_id = data.get("id")
        score = int(data.get("score", 10))
        if not exp_id:
            return jsonify({"status": "error", "message": "Missing experiment id"}), 400

        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO experiments (id, completed, score, completed_at)
            VALUES (?, 1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                completed = 1,
                score = experiments.score + excluded.score,
                completed_at = excluded.completed_at
        """, (exp_id, score, datetime.now().isoformat()))
        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "message": f"Experiment {exp_id} completed",
            "score_awarded": score,
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ============================================================
# ERROR HANDLERS
# ============================================================
@app.errorhandler(404)
def not_found(e):
    return jsonify({"status": "error", "message": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"status": "error", "message": "Internal server error"}), 500


# ============================================================
# MAIN ENTRY POINT
# ============================================================
if __name__ == "__main__":
    init_database()
    print("=" * 62)
    print("  MailFlow X — Interactive Email Protocol Simulator")
    print("=" * 62)
    print(f"  Project folder: {BASE_DIR}")
    print(f"  Database:       {DB_PATH}")
    print(f"  Frontend:       {os.path.join(BASE_DIR, 'index.html')}")
    print("  All SMTP/POP3/IMAP/DNS operations are SIMULATED locally.")
    print("  No real emails are sent.")
    print("-" * 62)
    print("  Open http://127.0.0.1:5000 in your browser.")
    print("=" * 62)
    app.run(host="127.0.0.1", port=5000, debug=True)