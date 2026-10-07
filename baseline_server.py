"""Unprotected plaintext file-sharing baseline (what students do today): no auth, no encryption, no integrity check."""
import os
from flask import Flask, request, jsonify, send_file


def create_app(data_dir="baseline_data"):
    os.makedirs(data_dir, exist_ok=True)
    app = Flask(__name__)
    app.config["DIR"] = data_dir
    n = {"i": 0}

    @app.post("/upload")
    def upload():
        n["i"] += 1
        with open(os.path.join(data_dir, f"{n['i']}.bin"), "wb") as f:
            f.write(request.get_data())
        return jsonify(id=n["i"])

    @app.get("/download/<int:i>")
    def download(i):
        return send_file(os.path.abspath(os.path.join(data_dir, f"{i}.bin")))
    return app


if __name__ == "__main__":
    create_app().run("127.0.0.1", 5002)
