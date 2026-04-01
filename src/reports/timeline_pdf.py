from datetime import datetime, timezone
from typing import Any, Dict, List


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _escape_pdf_text(text: str) -> str:
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _wrap_line(text: str, width: int = 100) -> List[str]:
    words = str(text).split()
    if not words:
        return [""]
    lines: List[str] = []
    current: List[str] = []
    current_len = 0
    for word in words:
        extra = len(word) + (1 if current else 0)
        if current and current_len + extra > width:
            lines.append(" ".join(current))
            current = [word]
            current_len = len(word)
        else:
            current.append(word)
            current_len += extra
    if current:
        lines.append(" ".join(current))
    return lines


def _report_lines(report: Dict[str, Any]) -> List[str]:
    summary = report.get("summary", {})
    lines: List[str] = [
        "Realtime Threat Monitoring - Incident Timeline Report",
        f"Generated At (UTC): {report.get('generated_at') or _iso_now()}",
        f"Incident ID: {report.get('incident_id', '-')}",
        f"Threat ID: {report.get('threat_id') or '-'}",
        f"Primary Alert ID: {report.get('primary_alert_id') or '-'}",
        f"Related Alerts: {summary.get('alerts', 0)} | Detections: {summary.get('detections', 0)} | "
        f"Operator Actions: {summary.get('operator_actions', 0)} | Dispatch Events: {summary.get('dispatch_events', 0)} | "
        f"Escalation Events: {summary.get('escalation_events', 0)}",
        "",
        "Chronological Timeline:",
        "",
    ]
    for event in report.get("events", []):
        timestamp = event.get("timestamp") or "-"
        category = event.get("category") or "EVENT"
        source = event.get("source") or "-"
        actor = event.get("operator_id") or "-"
        title = event.get("title") or "-"
        details = event.get("details") or "-"
        header = f"[{timestamp}] [{category}] [{source}] actor={actor}"
        lines.extend(_wrap_line(header, width=105))
        lines.extend(_wrap_line(f"  {title}", width=105))
        lines.extend(_wrap_line(f"  {details}", width=105))
        lines.append("")
    if len(lines) < 12:
        lines.extend(["No timeline events available.", ""])
    return lines


def _build_page_content(lines: List[str]) -> bytes:
    commands = ["BT", "/F1 9 Tf", "14 TL", "48 800 Td"]
    first = True
    for line in lines:
        safe = _escape_pdf_text(line)
        if first:
            commands.append(f"({safe}) Tj")
            first = False
        else:
            commands.append("T*")
            commands.append(f"({safe}) Tj")
    commands.append("ET")
    content = "\n".join(commands).encode("latin-1", errors="replace")
    return content


def build_incident_timeline_pdf(report: Dict[str, Any]) -> bytes:
    lines = _report_lines(report)
    max_lines_per_page = 52
    pages_lines = [lines[idx : idx + max_lines_per_page] for idx in range(0, len(lines), max_lines_per_page)]
    if not pages_lines:
        pages_lines = [["Incident timeline unavailable."]]

    objects: List[bytes] = []

    def add_object(data: bytes) -> int:
        objects.append(data)
        return len(objects)

    font_obj = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

    page_obj_ids: List[int] = []
    content_obj_ids: List[int] = []
    for page_lines in pages_lines:
        content_stream = _build_page_content(page_lines)
        stream_obj = (
            f"<< /Length {len(content_stream)} >>\nstream\n".encode("ascii")
            + content_stream
            + b"\nendstream"
        )
        content_obj_id = add_object(stream_obj)
        content_obj_ids.append(content_obj_id)
        page_obj_ids.append(0)  # placeholder, filled later

    pages_kids_refs = " ".join(f"{obj_id} 0 R" for obj_id in page_obj_ids if obj_id > 0)
    pages_obj_placeholder = add_object(b"<< >>")
    pages_obj_id = pages_obj_placeholder

    for idx, content_obj_id in enumerate(content_obj_ids):
        page_obj = (
            f"<< /Type /Page /Parent {pages_obj_id} 0 R /MediaBox [0 0 612 842] "
            f"/Resources << /Font << /F1 {font_obj} 0 R >> >> /Contents {content_obj_id} 0 R >>"
        ).encode("ascii")
        page_obj_id = add_object(page_obj)
        page_obj_ids[idx] = page_obj_id

    pages_kids_refs = " ".join(f"{obj_id} 0 R" for obj_id in page_obj_ids)
    objects[pages_obj_id - 1] = (
        f"<< /Type /Pages /Count {len(page_obj_ids)} /Kids [{pages_kids_refs}] >>".encode("ascii")
    )

    catalog_obj_id = add_object(f"<< /Type /Catalog /Pages {pages_obj_id} 0 R >>".encode("ascii"))

    output = bytearray()
    output.extend(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    xref_offsets = [0]
    for idx, obj in enumerate(objects, start=1):
        xref_offsets.append(len(output))
        output.extend(f"{idx} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")

    xref_pos = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in xref_offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))

    trailer = (
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_obj_id} 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n"
    )
    output.extend(trailer.encode("ascii"))
    return bytes(output)
