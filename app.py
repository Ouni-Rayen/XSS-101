from flask import Flask, render_template, request, make_response
import re
import os

app = Flask(__name__)

FLAG = "Securinets{xss_f1lt3rs_4r3_w34k}"


def filter_input(text: str) -> str:
    """Weak filter: blocks <script (case-insensitive)"""
    if not text:
        return ""
    return re.sub(r"<\s*script", "", text, flags=re.IGNORECASE)


@app.route("/")
def index():
    query = request.args.get("q", "")
    reflected = filter_input(query)

    resp = make_response(render_template("index.html", query=query, reflected=reflected))

    # Flag cookie readable by JavaScript
    resp.set_cookie(
        "flag",
        FLAG,
        httponly=False,
        samesite="Lax"
    )
    return resp


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
