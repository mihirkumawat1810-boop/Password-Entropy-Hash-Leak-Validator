from flask import Flask, render_template, request, jsonify
from entropy import analyze_character_sets
from patterns import detect_patterns
from breach_check import check_hibp_breach

app = Flask(__name__)

def evaluate_risk(password: str, entropy: float, warnings: list, breach_count: int):
    strength_score = min(100, int(entropy - (len(warnings) * 15.0)))
    if len(password) < 8:
        strength_score = max(0, strength_score - 20)

    if breach_count < 0:
        breach_risk = "N/A"
    elif breach_count == 0:
        breach_risk = 0
    elif breach_count < 10:
        breach_risk = 50
    else:
        breach_risk = 100

    if breach_risk == 100 or strength_score < 30:
        overall = "CRITICAL RISK"
    elif (isinstance(breach_risk, int) and breach_risk >= 50) or strength_score < 50:
        overall = "HIGH RISK"
    elif strength_score < 75:
        overall = "MODERATE RISK"
    else:
        overall = "LOW RISK"

    return {
        "strength_score": strength_score,
        "breach_risk_score": breach_risk,
        "overall_risk": overall
    }

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/audit", methods=["POST"])
def audit():
    data = request.get_json() or {}
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "Empty password"}), 400

    char_data = analyze_character_sets(password)
    warnings = detect_patterns(password)
    breach_count, breach_msg = check_hibp_breach(password)

    metrics = evaluate_risk(password, char_data["entropy"], warnings, breach_count)
    del password

    return jsonify({
        "entropy": char_data["entropy"],
        "warnings": warnings,
        "breach_count": breach_count,
        "breach_status": breach_msg,
        "metrics": metrics
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)