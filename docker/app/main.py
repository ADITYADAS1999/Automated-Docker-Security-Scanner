from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/")
def index():
    return """
    <html>
      <head><title>My Custom App</title></head>
      <body style="font-family: Arial, sans-serif; text-align:center; margin-top:50px;">
        <h1>My Custom App</h1>
        <p>This is a demo application used for vulnerability scanning in CI/CD.</p>
        <p>Try <a href="/health">/health</a> for JSON health status.</p>
      </body>
    </html>
    """

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "message": "Service is up",
    })

if __name__ == "__main__":
    # Use port 5000 to match common Docker examples
    app.run(host="0.0.0.0", port=5000)
