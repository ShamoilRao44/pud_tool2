from __future__ import annotations

from flask import jsonify


class ApiError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400, error_id: str | None = None):
        self.code = code
        self.message = message
        self.status_code = status_code
        self.error_id = error_id or "ERR-000000"

    def to_response(self):
        return jsonify({"ok": False, "error": {"code": self.code, "message": self.message, "error_id": self.error_id}}), self.status_code
