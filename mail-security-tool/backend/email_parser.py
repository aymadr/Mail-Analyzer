"""
Parser d'entete email - Extrait SPF, DKIM, DMARC, IPs et URLs locales
"""
import re
import ipaddress
import hashlib
from pathlib import Path
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit
from email.header import decode_header, make_header
from email.parser import Parser
from typing import Dict, List


class LocalHTMLURLExtractor(HTMLParser):
    """Extracteur HTML local: href/src + motifs de redirection JS."""

    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attrs):
        attr_map = dict(attrs)
        href = attr_map.get("href")
        src = attr_map.get("src")
        if href:
            self.urls.append(href)
        if src:
            self.urls.append(src)

    def handle_data(self, data):
        # Redirections JavaScript inline usuelles
        js_patterns = [
            r"(?:window\.)?location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]",
            r"location\.replace\(\s*['\"]([^'\"]+)['\"]\s*\)",
            r"location\.assign\(\s*['\"]([^'\"]+)['\"]\s*\)",
        ]
        for pattern in js_patterns:
            for match in re.findall(pattern, data, flags=re.IGNORECASE):
                self.urls.append(match)

class EmailHeaderParser:
    def __init__(self):
        self.parser = Parser()
    
    def parse_eml_file(self, file_path: str) -> Dict:
        """Charge et parse un fichier .eml/.msg."""
        path = Path(file_path)
        extension = path.suffix.lower()

        if extension == ".msg":
            return self._parse_msg_file(path)

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            email_content = f.read()
        return self.parse_email_content(email_content)

    def _parse_msg_file(self, file_path: Path) -> Dict:
        """Parse un fichier Outlook .msg (avec fallback local si lib absente)."""
        try:
            import extract_msg  # type: ignore
        except Exception:
            return self._parse_msg_file_fallback(file_path)

        msg = extract_msg.Message(str(file_path))

        transport_headers = self._extract_msg_transport_headers(msg)
        headers_message = self.parser.parsestr(transport_headers) if transport_headers else None

        sender = self._first_non_empty(
            self._clean_header_value(getattr(msg, "sender", "")),
            self._decode_mime_header(headers_message.get("From", "") if headers_message else "")
        )
        to_header = self._first_non_empty(
            self._clean_header_value(getattr(msg, "to", "")),
            self._decode_mime_header(headers_message.get("To", "") if headers_message else "")
        )
        subject = self._first_non_empty(
            self._clean_header_value(getattr(msg, "subject", "")),
            self._decode_mime_header(headers_message.get("Subject", "") if headers_message else "")
        )
        date_value = getattr(msg, "date", None)
        date = str(date_value) if date_value else self._decode_mime_header(headers_message.get("Date", "") if headers_message else "")

        body_text = (getattr(msg, "body", "") or "")
        html_body = ""
        html_raw = getattr(msg, "htmlBody", None)
        if isinstance(html_raw, bytes):
            html_body = html_raw.decode("utf-8", errors="ignore")
        elif isinstance(html_raw, str):
            html_body = html_raw

        attachments_raw = self._extract_msg_attachments(msg)
        url_data = self._extract_urls_from_msg_content(body_text, html_body, attachments_raw)
        attachments = [
            {k: v for k, v in item.items() if k != "raw_bytes"}
            for item in attachments_raw
        ]

        synthetic_raw = "\n".join([
            transport_headers,
            f"From: {sender}",
            f"To: {to_header}",
            f"Subject: {subject}",
            f"Date: {date}",
            body_text,
            html_body,
        ])

        received_recipients = (
            self._extract_recipients_from_received(headers_message)
            if headers_message else
            self._extract_recipients_from_received_text(synthetic_raw)
        )
        resolved_to = to_header or (received_recipients[0] if received_recipients else "")
        to_source = "To" if to_header else ("Received for" if received_recipients else "Unknown")

        return {
            "from": sender,
            "to": resolved_to,
            "to_header": to_header,
            "to_detected": received_recipients,
            "to_source": to_source,
            "subject": subject,
            "date": date,
            "spf": self._extract_spf(synthetic_raw),
            "dkim": self._extract_dkim(synthetic_raw),
            "dmarc": self._extract_dmarc(synthetic_raw),
            "ips": self._extract_ips(synthetic_raw),
            "domains": self._extract_domains(synthetic_raw),
            "received_from": self._extract_received_headers(headers_message) if headers_message else [],
            "attachments": attachments,
            "urls": url_data,
            "raw_headers": dict(headers_message.items()) if headers_message else {},
            "format": "msg"
        }

    def _parse_msg_file_fallback(self, file_path: Path) -> Dict:
        """Fallback local sans dépendance externe: extraction best-effort sur bytes .msg."""
        raw_bytes = file_path.read_bytes()
        blob = raw_bytes.decode("latin-1", errors="ignore")

        header_block = self._extract_header_block_from_blob(blob)
        headers_message = self.parser.parsestr(header_block) if header_block else None

        def find_first(pattern: str) -> str:
            match = re.search(pattern, blob, flags=re.IGNORECASE)
            return (match.group(1).strip() if match else "")

        sender = self._first_non_empty(
            self._decode_mime_header(headers_message.get("From", "") if headers_message else ""),
            find_first(r"From:\s*([^\r\n\x00]+)")
        )
        to_header = self._first_non_empty(
            self._decode_mime_header(headers_message.get("To", "") if headers_message else ""),
            find_first(r"To:\s*([^\r\n\x00]+)")
        )
        subject = self._first_non_empty(
            self._decode_mime_header(headers_message.get("Subject", "") if headers_message else ""),
            find_first(r"Subject:\s*([^\r\n\x00]+)")
        )
        date = self._first_non_empty(
            self._decode_mime_header(headers_message.get("Date", "") if headers_message else ""),
            find_first(r"Date:\s*([^\r\n\x00]+)")
        )

        received_recipients = (
            self._extract_recipients_from_received(headers_message)
            if headers_message else
            self._extract_recipients_from_received_text(blob)
        )
        resolved_to = to_header or (received_recipients[0] if received_recipients else "")
        to_source = "To" if to_header else ("Received for" if received_recipients else "Unknown")

        url_data = self._extract_urls_from_msg_content(blob, "", [])

        return {
            "from": sender,
            "to": resolved_to,
            "to_header": to_header,
            "to_detected": received_recipients,
            "to_source": to_source,
            "subject": subject,
            "date": date,
            "spf": self._extract_spf(blob),
            "dkim": self._extract_dkim(blob),
            "dmarc": self._extract_dmarc(blob),
            "ips": self._extract_ips(blob),
            "domains": self._extract_domains(blob),
            "received_from": self._extract_received_headers(headers_message) if headers_message else [],
            "attachments": [],
            "urls": url_data,
            "raw_headers": dict(headers_message.items()) if headers_message else {},
            "format": "msg-fallback",
            "warnings": [
                "extract_msg non disponible: parsing .msg en mode dégradé"
            ]
        }

    def _extract_msg_transport_headers(self, msg) -> str:
        """Récupère les headers transport d'un objet extract_msg si disponibles."""
        candidates = [
            getattr(msg, "header", None),
            getattr(msg, "headers", None),
            getattr(msg, "transport_headers", None),
            getattr(msg, "transportHeaders", None),
            getattr(msg, "internetHeaders", None),
            getattr(msg, "headerText", None),
            getattr(msg, "messageHeaders", None),
        ]

        for candidate in candidates:
            if not candidate:
                continue
            try:
                if hasattr(candidate, "as_string"):
                    value = candidate.as_string()
                else:
                    value = str(candidate)
                if value and any(h in value for h in ["From:", "To:", "Subject:", "Received:"]):
                    return value.replace("\x00", "")
            except Exception:
                continue

        return ""

    def _extract_header_block_from_blob(self, blob: str) -> str:
        """Extrait un bloc de headers RFC822 depuis un texte brut/bytes décodés."""
        cleaned = (blob or "").replace("\x00", "")

        start_positions = []
        for marker in ["Received:", "From:", "To:", "Subject:", "Date:"]:
            idx = cleaned.find(marker)
            if idx >= 0:
                start_positions.append(idx)

        if not start_positions:
            return ""

        start = min(start_positions)
        candidate = cleaned[start: start + 100000]
        if "\n\n" in candidate:
            candidate = candidate.split("\n\n", 1)[0]

        return candidate

    def _decode_mime_header(self, value: str) -> str:
        """Décode les headers encodés MIME (=?utf-8?...?=)."""
        if not value:
            return ""
        try:
            return str(make_header(decode_header(value))).strip()
        except Exception:
            return str(value).strip()

    def _clean_header_value(self, value: str) -> str:
        return (value or "").replace("\x00", "").strip()

    def _first_non_empty(self, *values: str) -> str:
        for value in values:
            cleaned = self._clean_header_value(value)
            if cleaned:
                return cleaned
        return ""

    def _extract_msg_attachments(self, msg) -> List[Dict]:
        """Extrait les pièces jointes d'un .msg et calcule les hashes."""
        attachments = []

        for att in getattr(msg, "attachments", []) or []:
            filename = (
                getattr(att, "longFilename", None)
                or getattr(att, "shortFilename", None)
                or getattr(att, "filename", None)
                or "attachment"
            )

            data = getattr(att, "data", None)
            if not isinstance(data, (bytes, bytearray)):
                continue

            payload = bytes(data)
            attachments.append({
                "filename": filename,
                "size": len(payload),
                "md5": hashlib.md5(payload).hexdigest(),
                "sha1": hashlib.sha1(payload).hexdigest(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "content_type": self._guess_mime_from_filename(filename),
                "raw_bytes": payload,
            })

        return attachments

    def _extract_urls_from_msg_content(self, body_text: str, body_html: str, attachments: List[Dict]) -> Dict:
        """Extraction URL locale pour .msg (texte, html, PJ html/pdf)."""
        extracted = []

        def add_urls(raw_urls: List[str], source: str):
            for original in raw_urls:
                normalized = self._normalize_url(original)
                if not normalized:
                    continue
                host = (urlsplit(normalized).hostname or "").lower()
                root_domain = self._registrable_domain(host)
                extracted.append({
                    "original": original,
                    "normalized": normalized,
                    "source": source,
                    "domain": host,
                    "root_domain": root_domain,
                })

        add_urls(self._extract_urls_from_text(body_text or ""), "body_text")
        add_urls(self._extract_urls_from_html(body_html or ""), "body_html")

        for att in attachments:
            raw = att.get("raw_bytes")
            if not raw:
                continue

            filename = att.get("filename", "unknown")
            content_type = (att.get("content_type") or "").lower()

            if content_type == "text/html" or self._is_html_filename(filename):
                html = raw.decode("utf-8", errors="ignore")
                add_urls(self._extract_urls_from_html(html), f"attachment_html:{filename}")

            if content_type == "application/pdf" or self._is_pdf_filename(filename):
                add_urls(self._extract_urls_from_pdf_bytes(raw), f"attachment_pdf:{filename}")

        deduped = []
        seen = set()
        for item in extracted:
            key = (item["normalized"], item["source"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)

        return {
            "items": deduped,
            "grouped_domains": self._group_urls_by_domain(deduped),
            "summary": {
                "total_found": len(deduped),
                "unique_urls": len({u["normalized"] for u in deduped}),
                "sources": self._count_by_source(deduped),
            },
        }

    @staticmethod
    def _guess_mime_from_filename(filename: str) -> str:
        lower = (filename or "").lower()
        if lower.endswith(".html") or lower.endswith(".htm"):
            return "text/html"
        if lower.endswith(".pdf"):
            return "application/pdf"
        return "application/octet-stream"
    
    def parse_email_content(self, email_content: str) -> Dict:
        """Parse le contenu brut d'un email"""
        message = self.parser.parsestr(email_content)
        url_data = self._extract_urls(message, email_content)
        from_header = self._decode_mime_header(message.get("From", ""))
        to_header = self._decode_mime_header(message.get("To", ""))
        subject_header = self._decode_mime_header(message.get("Subject", ""))
        date_header = self._decode_mime_header(message.get("Date", ""))
        received_recipients = self._extract_recipients_from_received(message)

        resolved_to = to_header
        to_source = "To"
        if not resolved_to and received_recipients:
            resolved_to = received_recipients[0]
            to_source = "Received for"
        
        return {
            "from": from_header,
            "to": resolved_to,
            "to_header": to_header,
            "to_detected": received_recipients,
            "to_source": to_source,
            "subject": subject_header,
            "date": date_header,
            "spf": self._extract_spf(email_content),
            "dkim": self._extract_dkim(email_content),
            "dmarc": self._extract_dmarc(email_content),
            "ips": self._extract_ips(email_content),
            "domains": self._extract_domains(email_content),
            "received_from": self._extract_received_headers(message),
            "attachments": self._extract_attachments(message),
            "urls": url_data,
            "raw_headers": dict(message.items())
        }

    def _extract_recipients_from_received(self, message) -> List[str]:
        """Extrait les destinataires visibles dans les entetes Received (clause 'for')."""
        received_headers = message.get_all("Received", [])
        content = "\n".join(received_headers)
        return self._extract_recipients_from_received_text(content)

    def _extract_recipients_from_received_text(self, content: str) -> List[str]:
        """Extrait les destinataires depuis texte Received via la clause for."""
        recipients = []
        pattern = re.compile(
            r"\bfor\s+<?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>?",
            re.IGNORECASE,
        )
        for match in pattern.findall(content or ""):
            recipients.append(match.strip().lower())
        return list(dict.fromkeys(recipients))

    def _extract_urls(self, message, raw_content: str) -> Dict:
        """Extraction locale des URLs (texte, HTML, PJ HTML/PDF) + normalisation."""
        extracted = []

        def add_urls(raw_urls: List[str], source: str):
            for original in raw_urls:
                normalized = self._normalize_url(original)
                if not normalized:
                    continue
                host = (urlsplit(normalized).hostname or "").lower()
                root_domain = self._registrable_domain(host)
                extracted.append({
                    "original": original,
                    "normalized": normalized,
                    "source": source,
                    "domain": host,
                    "root_domain": root_domain,
                })

        # A) Corps texte brut global
        add_urls(self._extract_urls_from_text(raw_content), "body_text")

        # B) Corps MIME text/plain et text/html
        for part in message.walk():
            if part.is_multipart():
                continue

            disposition = part.get_content_disposition()
            filename = part.get_filename()
            content_type = (part.get_content_type() or "").lower()
            payload = part.get_payload(decode=True)
            if not payload:
                continue

            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="ignore")
            except Exception:
                text = payload.decode("utf-8", errors="ignore")

            is_attachment = disposition == "attachment" or bool(filename)

            if not is_attachment and content_type == "text/plain":
                add_urls(self._extract_urls_from_text(text), "body_text")

            if not is_attachment and content_type == "text/html":
                add_urls(self._extract_urls_from_html(text), "body_html")

            # C) PJ HTML
            if is_attachment and (content_type == "text/html" or self._is_html_filename(filename)):
                add_urls(self._extract_urls_from_html(text), f"attachment_html:{filename or 'unknown'}")

            # C) PJ PDF: extraction locale de motifs /URI et http(s)
            if is_attachment and (content_type == "application/pdf" or self._is_pdf_filename(filename)):
                add_urls(self._extract_urls_from_pdf_bytes(payload), f"attachment_pdf:{filename or 'unknown'}")

        # Dedup par (normalized, source)
        deduped = []
        seen = set()
        for item in extracted:
            key = (item["normalized"], item["source"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)

        return {
            "items": deduped,
            "grouped_domains": self._group_urls_by_domain(deduped),
            "summary": {
                "total_found": len(deduped),
                "unique_urls": len({u["normalized"] for u in deduped}),
                "sources": self._count_by_source(deduped),
            },
        }

    def _extract_urls_from_text(self, text: str) -> List[str]:
        """Extrait des URLs depuis du texte brut (http, https, hxxp, www)."""
        pattern = re.compile(
            r"(?i)\b(?:hxxps?://|https?://|www\.)[^\s<>'\"\]\)]+"
        )
        return [m.group(0) for m in pattern.finditer(text or "")]

    def _extract_urls_from_html(self, html: str) -> List[str]:
        """Parse du HTML local pour href/src + redirections JS inline."""
        extractor = LocalHTMLURLExtractor()
        try:
            extractor.feed(html or "")
        except Exception:
            pass

        # Complete avec URLs en texte libre dans le HTML
        extractor.urls.extend(self._extract_urls_from_text(html or ""))
        return extractor.urls

    def _extract_urls_from_pdf_bytes(self, content: bytes) -> List[str]:
        """Extraction locale de motifs URL dans bytes PDF, sans rendu navigateur."""
        urls = []

        for match in re.findall(rb"/URI\s*\((.*?)\)", content, flags=re.IGNORECASE):
            try:
                urls.append(match.decode("latin-1", errors="ignore"))
            except Exception:
                continue

        try:
            as_text = content.decode("latin-1", errors="ignore")
        except Exception:
            as_text = ""

        urls.extend(self._extract_urls_from_text(as_text))
        return urls

    def _normalize_url(self, value: str) -> str:
        """Normalisation locale anti-obfuscation (hxxp, [.] etc.)."""
        if not value:
            return ""

        cleaned = unescape(value.strip())
        cleaned = cleaned.strip(" \t\r\n\"'`<>()[]{}")

        # Defang courant
        cleaned = re.sub(r"(?i)^hxxps://", "https://", cleaned)
        cleaned = re.sub(r"(?i)^hxxp://", "http://", cleaned)
        cleaned = re.sub(r"\[(?:\.|dot)\]", ".", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\((?:\.|dot)\)", ".", cleaned, flags=re.IGNORECASE)
        cleaned = cleaned.replace("{.}", ".")
        cleaned = cleaned.replace("[://]", "://")

        # Nettoie ponctuation terminale
        cleaned = cleaned.rstrip(".,;:!?)]}")

        if cleaned.lower().startswith("www."):
            cleaned = f"http://{cleaned}"

        if not re.match(r"(?i)^https?://", cleaned):
            # Domaine nu
            if re.match(r"(?i)^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(/.*)?$", cleaned):
                cleaned = f"http://{cleaned}"
            else:
                return ""

        try:
            split = urlsplit(cleaned)
        except Exception:
            return ""

        if split.scheme not in {"http", "https"}:
            return ""
        if not split.netloc:
            return ""

        # Normalise scheme/host en minuscule
        normalized = urlunsplit((
            split.scheme.lower(),
            split.netloc.lower(),
            split.path or "",
            split.query or "",
            "",
        ))
        return normalized

    def _registrable_domain(self, hostname: str) -> str:
        """Approximation locale du domaine racine (sans tldextract)."""
        if not hostname:
            return ""

        parts = hostname.split(".")
        if len(parts) <= 2:
            return hostname

        second_level_markers = {"co", "com", "org", "net", "gov", "edu", "ac"}
        if len(parts[-1]) == 2 and parts[-2] in second_level_markers and len(parts) >= 3:
            return ".".join(parts[-3:])

        return ".".join(parts[-2:])

    def _group_urls_by_domain(self, items: List[Dict]) -> List[Dict]:
        grouped = {}
        for item in items:
            key = item.get("root_domain") or item.get("domain") or "unknown"
            bucket = grouped.setdefault(key, {"domain": key, "count": 0, "urls": []})
            bucket["count"] += 1
            bucket["urls"].append(item.get("normalized"))

        result = []
        for _, group in grouped.items():
            group["urls"] = sorted(list(dict.fromkeys(group["urls"])))
            result.append(group)

        result.sort(key=lambda x: x["count"], reverse=True)
        return result

    def _count_by_source(self, items: List[Dict]) -> Dict:
        counter = {}
        for item in items:
            src = item.get("source", "unknown")
            counter[src] = counter.get(src, 0) + 1
        return counter

    @staticmethod
    def _is_html_filename(filename: str) -> bool:
        if not filename:
            return False
        lower = filename.lower()
        return lower.endswith(".html") or lower.endswith(".htm")

    @staticmethod
    def _is_pdf_filename(filename: str) -> bool:
        return bool(filename and filename.lower().endswith(".pdf"))
    
    def _extract_spf(self, content: str) -> Dict:
        """Extrait les informations SPF, le domaine et l'IP"""
        content = self._normalize_header_text(content)
        status = "Not found"
        domain = None
        ip = None

        # 1. Vérification dans Received-SPF (supporte les headers multi-lignes)
        received_spf_block = self._extract_header_block(content, "Received-SPF")
        if received_spf_block:
            status_match = re.search(r"^\s*([a-zA-Z]+)", received_spf_block, re.IGNORECASE)
            if status_match:
                status = status_match.group(1).capitalize()

            # Essaie de trouver le client-ip ou IP (IPv4 sinon IPv6)
            ip_match = re.search(r"client-ip=([^\s;]+)", received_spf_block, re.IGNORECASE)
            if ip_match:
                ip = self._extract_best_ip(ip_match.group(1))
            if not ip:
                designates_match = re.search(
                    r"designates\s+([^\s;]+)\s+as permitted sender",
                    received_spf_block,
                    re.IGNORECASE
                )
                if designates_match:
                    ip = self._extract_best_ip(designates_match.group(1))
            if not ip:
                ip = self._extract_best_ip(received_spf_block)

            # Essaie de trouver le domaine (envelope-from ou domain of)
            domain_match = re.search(r"envelope-from=[^\s@]*@([^\s;]+)", received_spf_block, re.IGNORECASE)
            if not domain_match:
                domain_match = re.search(r"domain of ([^\s;]+)\s+designates", received_spf_block, re.IGNORECASE)
            if domain_match:
                domain = domain_match.group(1).lstrip(".*@")

            # Fallback sur Authentication-Results pour smtp.mailfrom
            if not domain:
                auth_mailfrom = re.search(r"smtp\.mailfrom=([^\s;]+)", content, re.IGNORECASE)
                if auth_mailfrom:
                    domain = auth_mailfrom.group(1)
                    if "@" in domain:
                        domain = domain.split("@")[-1]
                
        # 2. Sinon, vérification dans Authentication-Results
        else:
            auth_results_match = re.search(r"Authentication-Results:.*?spf=([a-zA-Z]+)(.*)", content, re.IGNORECASE | re.DOTALL)
            if auth_results_match:
                status = auth_results_match.group(1).capitalize()
                
                # IP dans Authentication-Results (IPv4 ou IPv6)
                ip_match = re.search(r"sender IP is ([^\s;]+)", content, re.IGNORECASE)
                if ip_match:
                    ip = self._extract_best_ip(ip_match.group(1))
                if not ip:
                    ip = self._extract_best_ip(content)
                    
                domain_match = re.search(r"smtp\.mailfrom=([^\s;]+)", content, re.IGNORECASE)
                if domain_match:
                    domain = domain_match.group(1)
                    if "@" in domain:
                        domain = domain.split("@")[-1]

        return {
            "status": status,
            "domain": domain,
            "ip": ip,
            "record": self._fetch_spf_record(content)
        }
    
    def _extract_dkim(self, content: str) -> Dict:
        """Extrait les informations DKIM"""
        content = self._normalize_header_text(content)
        status = "Not found"
        domain = None
        
        # On vérifie Authentication-Results pour un statut DKIM (ex: dkim=pass)
        auth_results_match = re.search(r"Authentication-Results:.*?dkim=([a-zA-Z]+)", content, re.IGNORECASE | re.DOTALL)
        if auth_results_match:
            status = auth_results_match.group(1).capitalize()
            if not domain:
                dkim_domain_match = re.search(r"header\.d=([^\s;]+)", content, re.IGNORECASE)
                if dkim_domain_match:
                    domain = dkim_domain_match.group(1).strip()
            
        dkim_pattern = r"DKIM-Signature:(.*?)(?=\n[A-Z]|\Z)"
        match = re.search(dkim_pattern, content, re.IGNORECASE | re.DOTALL)
        
        if match and status == "Not found":
            status = "Present"
            
        if match:
            domain = self._extract_dkim_domain(match.group(1))
            
        return {
            "status": status,
            "domain": domain,
            "algorithm": self._extract_dkim_algo(match.group(1)) if match else None
        }
    
    def _extract_dmarc(self, content: str) -> Dict:
        """Extrait les informations DMARC"""
        content = self._normalize_header_text(content)
        dmarc_pattern = r"Authentication-Results:.*?dmarc=([a-zA-Z]+)(.*)(?:;|$)"
        match = re.search(dmarc_pattern, content, re.IGNORECASE | re.DOTALL)
        
        status = "Not found"
        domain = None
        
        if match:
            status = match.group(1).capitalize()
            # Trouve le domaine header.from (souvent indiqué en header.from=example.com)
            domain_match = re.search(r"header\.from=([^\s;]+)", match.group(2), re.IGNORECASE)
            if domain_match:
                domain = domain_match.group(1)
        
        return {
            "status": status,
            "domain": domain,
            "policy": self._extract_dmarc_policy(content)
        }
    
    def _extract_ips(self, content: str) -> List[str]:
        """Extrait toutes les adresses IP (IPv4 et IPv6)"""
        content = self._normalize_header_text(content)
        candidates = re.findall(r"[A-Fa-f0-9:\.]+", content)
        ips = []

        for candidate in candidates:
            value = candidate.strip("[]()<>{};,\"'")
            if not value:
                continue
            try:
                ipaddress.ip_address(value)
                ips.append(value)
            except ValueError:
                continue

        # Déduplication en conservant l'ordre d'apparition
        return list(dict.fromkeys(ips))
    
    def _extract_domains(self, content: str) -> List[str]:
        """Extrait les domaines"""
        content = self._normalize_header_text(content)
        domain_pattern = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]{2,}"
        domains = re.findall(domain_pattern, content)
        return list(set(domains))
    
    def _extract_received_headers(self, message) -> List[Dict]:
        """Parse les headers 'Received'"""
        received = message.get_all("Received", [])
        return [{"header": h} for h in received] if received else []

    def _extract_header_block(self, content: str, header_name: str) -> str:
        """Extrait un header complet y compris les lignes continuées"""
        content = self._normalize_header_text(content)
        pattern = rf"^{re.escape(header_name)}:\s*(.*(?:\n[ \t].*)*)"
        match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
        return match.group(1) if match else ""

    def _extract_best_ip(self, text: str) -> str:
        """Retourne IPv4 en priorité, sinon IPv6"""
        text = self._normalize_header_text(text)
        ipv4_match = re.search(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            text
        )
        if ipv4_match:
            return ipv4_match.group(0)

        # Fallback IPv6: on valide les candidats pour éviter les captures tronquées
        candidates = re.findall(r"[A-Fa-f0-9:]+", text)
        for candidate in sorted(candidates, key=len, reverse=True):
            value = candidate.strip("[]()<>{};,\"'")
            if ":" not in value:
                continue
            try:
                ipaddress.IPv6Address(value)
                return value
            except ValueError:
                continue

        return None
    
    def _extract_dkim_domain(self, dkim_content: str) -> str:
        """Extrait le domaine DKIM"""
        match = re.search(r"d=([^;]+)", dkim_content)
        return match.group(1).strip() if match else None
    
    def _extract_dkim_algo(self, dkim_content: str) -> str:
        """Extrait l'algorithme DKIM"""
        match = re.search(r"a=([^;]+)", dkim_content)
        return match.group(1).strip() if match else None
    
    def _fetch_spf_record(self, content: str) -> str:
        """Essaie de trouver le record SPF"""
        content = self._normalize_header_text(content)
        spf_pattern = r"v=spf1\s[^\n]*"
        match = re.search(spf_pattern, content, re.IGNORECASE)
        return match.group(0) if match else None
    
    def _extract_dmarc_policy(self, content: str) -> str:
        """Extrait la politique DMARC"""
        content = self._normalize_header_text(content)
        dmarc_pattern = r"p=(reject|quarantine|none)"
        match = re.search(dmarc_pattern, content, re.IGNORECASE)
        return match.group(1) if match else None

    def _normalize_header_text(self, content: str) -> str:
        """Normalise le texte de headers (utile pour .msg avec NULs)."""
        value = content or ""
        value = value.replace("\x00", "")
        value = value.replace("\r\n", "\n")
        value = value.replace("\r", "\n")
        return value

    def _extract_attachments(self, message) -> List[Dict]:
        """Extrait les pièces jointes et calcule leurs hashes"""
        attachments = []
        
        for part in message.walk():
            # Cherche les pièces jointes
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if filename:
                    # Récupère le contenu
                    payload = part.get_payload(decode=True)
                    if payload:
                        # Calcule les hashes
                        md5 = hashlib.md5(payload).hexdigest()
                        sha1 = hashlib.sha1(payload).hexdigest()
                        sha256 = hashlib.sha256(payload).hexdigest()
                        
                        attachments.append({
                            "filename": filename,
                            "size": len(payload),
                            "md5": md5,
                            "sha1": sha1,
                            "sha256": sha256
                        })
        
        return attachments


# Utilisation facile
if __name__ == "__main__":
    parser = EmailHeaderParser()
    # result = parser.parse_eml_file("test_email.eml")
    # print(result)
