from flask import Flask, render_template, request, jsonify

from entropy import analyze_character_sets
from patterns import detect_patterns
from breach_check import check_hibp_breach


app = Flask(__name__)


def evaluate_risk(
    password: str,
    entropy: float,
    warnings: list,
    breach_count: int
):
    # Calculate password strength
    strength_score = min(
        100,
        max(0, int(entropy - (len(warnings) * 15)))
    )

    # Extra penalty for short passwords
    if len(password) < 8:
        strength_score = max(0, strength_score - 20)

    # Calculate breach risk
    if breach_count < 0:
        breach_risk = None
    elif breach_count == 0:
        breach_risk = 0
    elif breach_count < 10:
        breach_risk = 50
    else:
        breach_risk = 100

    # Calculate overall risk
    if breach_risk == 100 or strength_score < 30:
        overall = "CRITICAL RISK"

    elif (
        (breach_risk is not None and breach_risk >= 50)
        or strength_score < 50
    ):
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

    try:
        # Get JSON data from frontend
        data = request.get_json(silent=True) or {}

        password = data.get("password", "")

        # Validate password
        if not isinstance(password, str) or not password:
            return jsonify({
                "error": "Password cannot be empty"
            }), 400

        # Analyze character sets and entropy
        char_data = analyze_character_sets(password)

        # Detect weak patterns
        warnings = detect_patterns(password)

        # Check breach database
        breach_count, breach_msg = check_hibp_breach(password)

        # Calculate final risk
        metrics = evaluate_risk(
            password,
            char_data["entropy"],
            warnings,
            breach_count
        )

        return jsonify({
            "entropy": char_data["entropy"],
            "warnings": warnings,
            "breach_count": breach_count,
            "breach_status": breach_msg,
            "metrics": metrics
        })

    except Exception as e:
        # Print error in terminal for debugging
        app.logger.exception("Error during password audit")

        return jsonify({
            "error": "Internal server error",
            "details": str(e)
        }), 500


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )