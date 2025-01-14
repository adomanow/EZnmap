import os
import subprocess
import random
import re
import ipaddress
import hashlib  # <-- For hashing directory names

from flask import Flask, request, render_template, send_file, Response, jsonify, session
from auth import auth_bp, login_required, AUTH_REQUIRED

app = Flask(__name__)
app.secret_key = os.getenv("EZNMAP_SECRET_KEY", "some-fallback-key")  # Ensure a fixed key in production

# Register your auth blueprint
app.register_blueprint(auth_bp)

# Where all scan data is stored
SCANS_ROOT = "scans"

#################################################################
# 1) Predefine Allowed Queries
#################################################################
AVAILABLE_QUERIES = {
    "intense":       "-T4 -A -v",
    "intense_udp":   "-sS -sU -T4 -A -v",
    "all_tcp":       "-p 1-65535 -T4 -A -v",
    "no_ping":       "-T4 -A -v -Pn",
    "ping_scan":     "-sn",
    "quick":         "-T4 -F",
    "quick_plus":    "-sV -T4 -O -F --version-light",
    "traceroute":    "-sn --traceroute",
    "regular":       "",
}

#################################################################
# 2) Per-user directory (Hashed)
#################################################################
def get_user_scan_dir(username: str) -> str:
    """
    Hash the username so the directory name isn't obvious.
    For example, use a partial SHA-256 hex digest.
    """
    # Convert username -> SHA-256, hex, truncated
    hashed_name = hashlib.sha256(username.encode()).hexdigest()[:16]
    user_dir = os.path.join(SCANS_ROOT, hashed_name)
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

#################################################################
# 3) Target Parsing / Validation
#################################################################
def parse_nmap_target(raw_target: str, raw_mask: str) -> tuple[str, str]:
    """
    Attempt to parse/validate the user's target + mask. 
      - Single IP (192.168.1.10)
      - CIDR notation (192.168.1.0/24)
      - IP ranges (192.168.1.1-24, etc.)
    Raises ValueError if invalid.
    """
    forbidden_chars = re.compile(r"[;&|`$<>]")
    if forbidden_chars.search(raw_target) or forbidden_chars.search(raw_mask):
        raise ValueError("Forbidden characters in target/mask")

    # If user typed something like /24 => treat it as CIDR
    if raw_mask.startswith("/"):
        combined = f"{raw_target}{raw_mask}"
        ipaddress.ip_network(combined, strict=False)
        return (raw_target, raw_mask)

    # If dash present => interpret as a range
    if "-" in raw_target:
        return (raw_target, "")

    # Otherwise assume single IP (or if you'd like, allow hostnames)
    try:
        ipaddress.ip_address(raw_target)
        return (raw_target, "")
    except ValueError:
        raise ValueError(f"Invalid IP, CIDR, or range: {raw_target}{raw_mask}")

#################################################################
# 4) Generator to Stream Nmap Output
#################################################################
def generate_nmap_output(user_dir: str, target: str, mask: str, query_str: str):
    full_target = target + mask
    xml_file = os.path.join(user_dir, "scan.xml")
    html_file = os.path.join(user_dir, "scan.html")

    nmap_cmd = ["nmap", "-v", "-oX", xml_file] + query_str.split() + [full_target]
    process = subprocess.Popen(nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    for line in iter(process.stdout.readline, b""):
        yield line.decode("utf-8")

    process.stdout.close()
    process.wait()

    if process.returncode == 0:
        try:
            # Convert XML to HTML
            if os.path.exists(xml_file):
                xsl_path = "/usr/share/nmap/nmap.xsl"
                xslt_cmd = ["xsltproc", xsl_path, xml_file]
                with open(html_file, "wb") as html_out:
                    subprocess.check_call(xslt_cmd, stdout=html_out)

            # Generate PNG via topogen.py
            png_file = os.path.join(user_dir, "scan.png")
            subprocess.check_call(["xvfb-run", "-a", "python3", "topogen.py", xml_file, png_file, "600"])

        except Exception as e:
            yield f"Error generating additional outputs: {e}\n"
    else:
        yield f"Error: Nmap scan failed with return code {process.returncode}.\n"

#################################################################
# 5) Routes
#################################################################
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    default_target = "192.168.1.1"
    default_mask   = ""
    default_query  = "quick"

    target = default_target
    mask   = default_mask
    query_key = default_query
    html_content = None
    png_file     = None

    if request.method == "POST":
        target = request.form.get("target", default_target)
        mask   = request.form.get("mask", default_mask)
        query_key = request.form.get("query", default_query)

    # Derive the hashed directory from the session username
    username = session.get("username", "anonymous")
    user_dir = get_user_scan_dir(username)

    html_path = os.path.join(user_dir, "scan.html")
    png_path  = os.path.join(user_dir, "scan.png")

    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            html_content = f.read()
    if os.path.exists(png_path):
        png_file = os.path.basename(png_path)

    return render_template(
        "index.html",
        target=target,
        mask=mask,
        query=query_key,
        png_file=png_file,
        html_content=html_content,
        random=random.random
    )

@app.route("/start-scan", methods=["POST"])
@login_required
def start_scan():
    username = session.get("username", "anonymous")
    user_dir = get_user_scan_dir(username)

    raw_target = request.form.get("target", "192.168.1.1")
    raw_mask   = request.form.get("mask", "")
    query_key  = request.form.get("query", "quick")

    # 1) Convert query_key -> actual flags
    query_str = AVAILABLE_QUERIES.get(query_key, "-T4 -F")

    # 2) Validate target/mask
    try:
        target, mask = parse_nmap_target(raw_target, raw_mask)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    # 3) Stream Nmap
    return Response(
        generate_nmap_output(user_dir, target, mask, query_str),
        content_type="text/plain"
    )

@app.route("/png", methods=["GET"])
@login_required
def serve_png():
    username = session.get("username", "anonymous")
    user_dir = get_user_scan_dir(username)

    file_name = request.args.get("file", "scan.png")
    file_path = os.path.join(user_dir, file_name)

    if os.path.exists(file_path):
        return send_file(file_path, mimetype="image/png")
    else:
        return jsonify({"error": "File not found"}), 404

@app.route("/html", methods=["GET"])
@login_required
def serve_html():
    username = session.get("username", "anonymous")
    user_dir = get_user_scan_dir(username)

    html_file = os.path.join(user_dir, "scan.html")
    if os.path.exists(html_file):
        return send_file(html_file, mimetype="text/html")
    else:
        return jsonify({"error": "HTML file not found"}), 404

@app.route("/legend", methods=["GET"])
def serve_legend():
    legend_path = os.path.join(app.root_path, "static", "legend.png")
    return send_file(legend_path, mimetype="image/png")

if __name__ == "__main__":
    # Typically you'd run with gunicorn or similar in production
    # Example: gunicorn -c gunicorn_config.py app:app
    pass

