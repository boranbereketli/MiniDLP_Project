#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/policy", methods=["GET"])
def get_policy():
    policy = {
        "usb_policy": "SMART",
        "banned_words": ["secret", "iban", "password", "tckn"],
        "rules_enabled": ["TCKN", "TEL_NO", "IBAN_TR", "KREDI_KARTI"]
    }
    return jsonify(policy)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)  # LAN üzerinden bile erişilebilir
