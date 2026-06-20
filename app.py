import json
import os
import re

import requests
from flask import Flask, jsonify, render_template, request


app = Flask(__name__)


def load_env():
    """Simple .env loader so students do not need extra setup knowledge."""
    if not os.path.exists(".env"):
        return
    with open(".env", "r", encoding="utf-8-sig") as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ[key.strip()] = value.strip().strip('"').strip("'")


load_env()


SUPPORT_LINKS = [
    {
        "label": "Bao cao lua dao qua 156/5656",
        "url": "https://nospam.vncert.vn/",
        "note": "Co the phan anh qua website, SMS 5656/156 hoac goi 156.",
    }
]


def gemini_keys():
    raw = " ".join([
        os.getenv("GEMINI_API_KEY", ""),
        os.getenv("GEMINI_API_KEYS", ""),
        os.getenv("GOOGLE_API_KEY", ""),
    ])
    keys = [key.strip() for key in re.split(r"[\s,;]+", raw) if key.strip()]
    return list(dict.fromkeys(keys))


def gemini_models():
    models = [os.getenv("GEMINI_MODEL", ""), "gemini-2.5-flash", "gemini-2.0-flash"]
    return [model for model in dict.fromkeys(models) if model]


def clamp(value, fallback=50):
    try:
        return max(0, min(100, round(float(value))))
    except Exception:
        return fallback


def risk_from_score(score):
    if score >= 76:
        return "danger", "Nguy hiem"
    if score >= 26:
        return "suspicious", "Nghi ngo"
    return "safe", "An toan"


def read_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def is_quota_error(text):
    text = str(text).lower()
    return "quota" in text or "429" in text or "resource_exhausted" in text


def parse_json(text):
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`").replace("json\n", "", 1).strip()
    return json.loads(text)


def ask_gemini(prompt, image=None):
    keys = gemini_keys()
    if not keys:
        raise RuntimeError("Chua co Gemini API key trong .env")

    parts = [{"text": prompt}]
    if image and image.get("dataUrl") and image.get("mimeType"):
        image_data = image["dataUrl"].split(",", 1)[1]
        parts.append({"inline_data": {"mime_type": image["mimeType"], "data": image_data}})

    body = {
        "contents": [{"role": "user", "parts": parts}],
        "generationConfig": {"responseMimeType": "application/json", "temperature": 0.15},
    }

    last_error = "Gemini chua phan hoi."
    for key in keys:
        for model in gemini_models():
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
            try:
                response = requests.post(url, json=body, timeout=45)
                if response.ok:
                    text = response.json()["candidates"][0]["content"]["parts"][0]["text"]
                    return parse_json(text)
                last_error = response.text
                if is_quota_error(last_error):
                    break
            except Exception as error:
                last_error = str(error)
                continue
    raise RuntimeError(last_error)


def analysis_prompt(message):
    return f"""
You are ScamCheck, an educational anti-scam helper for Vietnamese adults over 45.
Return ONLY valid JSON. Write user-facing text in simple Vietnamese without accents if needed.

Rate the danger risk from 0 to 100 based only on the input:
- 0-25: normal or safe
- 26-45: slightly suspicious
- around 50: unclear / not enough context
- 51-75: suspicious
- 76-100: dangerous

Important:
- Do not always answer 95.
- Safe family/appointment messages should be low.
- Unclear delivery or unknown sender messages should be around 50.
- OTP, password, bank login, urgent transfer, fake emergency, or strange link should be high.
- Keep the explanation short: only a few sentences.
- next_actions must be checkbox button labels the user can click.

Return this JSON:
{{
  "danger_score_percent": 0,
  "verdict_label": "An toan",
  "summary": "one short sentence",
  "explanation": "one short paragraph",
  "uncertainty": "one short sentence",
  "evidence": [{{"quote":"exact words from input", "why":"short reason"}}],
  "next_actions": [
    {{"label":"Xac minh nguoi gui", "prompt":"Guide the user to verify sender safely"}}
  ]
}}

Input:
{message or "(The user uploaded an image. Read the image and analyze it.)"}
"""


def clean_result(data, message):
    score = clamp(data.get("danger_score_percent"), 50)
    risk, default_label = risk_from_score(score)
    evidence = data.get("evidence") if isinstance(data.get("evidence"), list) else []
    actions = data.get("next_actions") if isinstance(data.get("next_actions"), list) else []
    return {
        "source": "gemini",
        "risk": risk,
        "danger_score_percent": score,
        "verdict_label": data.get("verdict_label") or default_label,
        "summary": data.get("summary") or "Da phan tich xong noi dung nay.",
        "explanation": data.get("explanation") or "Gemini danh gia dua tren dau hieu trong noi dung.",
        "uncertainty": data.get("uncertainty") or "Hay xac minh qua nguon chinh thuc neu con lo lang.",
        "evidence": evidence[:3],
        "next_actions": clean_actions(actions),
        "checked_text": message,
    }


def clean_actions(actions):
    cleaned = []
    for index, action in enumerate(actions[:4]):
        if isinstance(action, dict):
            label = str(action.get("label", "")).strip()
            prompt = str(action.get("prompt", "")).strip()
        else:
            label = str(action).strip()
            prompt = label
        if label:
            cleaned.append({"id": f"step_{index + 1}", "label": label[:80], "prompt": prompt[:240]})
    if cleaned:
        return cleaned
    return [
        {"id": "verify", "label": "Xac minh nguoi gui", "prompt": "Huong dan xac minh nguoi gui"},
        {"id": "stop", "label": "Khong bam link", "prompt": "Huong dan tranh bam link va giu an toan"},
        {"id": "family", "label": "Hoi nguoi than", "prompt": "Huong dan hoi nguoi than dang tin cay"},
    ]


def local_score(text, has_image=False):
    text = (text or "").lower()
    if has_image and not text:
        return 50
    high = ["otp", "mat khau", "password", "ngan hang", "chuyen tien", "http", "www", "cccd", "dang nhap"]
    medium = ["xac minh", "khoa", "gap", "ngay", "trung thuong", "phi", "giao hang", "nhan thuong"]
    if any(word in text for word in high) and any(word in text for word in medium):
        return 90
    if any(word in text for word in high):
        return 78
    if any(word in text for word in medium):
        return 50
    return 8


def fallback_result(message, has_image=False):
    score = local_score(message, has_image)
    risk, label = risk_from_score(score)
    if score >= 76:
        summary = "Noi dung co dau hieu nguy hiem, can dung lai de xac minh."
        explanation = "He thong thay dau hieu nhu link, OTP, ngan hang, tien hoac yeu cau hanh dong gap."
    elif score >= 26:
        summary = "Noi dung chua ro, nen kiem tra them truoc khi lam theo."
        explanation = "Chua du thong tin de ket luan chac chan, nhung co dau hieu can xac minh."
    else:
        summary = "Noi dung co ve binh thuong va rui ro thap."
        explanation = "Chua thay yeu cau tien, OTP, mat khau, link la hoac thong tin rieng."
    return {
        "source": "fallback",
        "risk": risk,
        "danger_score_percent": score,
        "verdict_label": label,
        "summary": summary,
        "explanation": explanation,
        "uncertainty": "Gemini tam thoi khong phan hoi, day la danh gia du phong.",
        "evidence": [],
        "next_actions": clean_actions([]),
        "checked_text": message,
    }


def action_prompt(data):
    return f"""
You are ScamCheck continuing a safety checklist.
Return ONLY JSON in simple Vietnamese.

Original message: {data.get("message", "")}
Current danger score: {data.get("score", "")}
User selected action: {data.get("action", {})}
User description: {data.get("description", "")}

Return:
{{
  "danger_score_percent": 40,
  "title": "short title",
  "message": "1-2 sentence next instruction",
  "completed": false,
  "next_actions": [{{"label":"Next button", "prompt":"What Gemini should guide next"}}],
  "support_links": []
}}

If the user already sent money, OTP, password, bank info, or installed an app, keep risk high.
If the user did not click and verified safely, lower risk and completed may be true.
If high risk or completed, include this support link: {SUPPORT_LINKS}
"""


def fallback_action(data):
    text = f"{data.get('message', '')} {data.get('description', '')}".lower()
    score = local_score(text)
    if "chua" in text or "khong" in text:
        score = min(score, 35)
    completed = score <= 35
    return {
        "source": "fallback",
        "danger_score_percent": score,
        "title": "Buoc tiep theo",
        "message": "Hay dung kenh chinh thuc de xac minh. Khong cung cap OTP, mat khau hay chuyen tien khi con nghi ngo.",
        "completed": completed,
        "next_actions": [] if completed else clean_actions([]),
        "support_links": SUPPORT_LINKS if completed or score >= 76 else [],
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = read_body()
    message = str(data.get("message", "")).strip()
    image = data.get("image")
    if not message and not image:
        return jsonify({"error": "Vui long nhap tin nhan, link, giong noi hoac tai anh."}), 400
    try:
        result = clean_result(ask_gemini(analysis_prompt(message), image), message)
    except Exception:
        result = fallback_result(message, bool(image))
    return jsonify(result)


@app.route("/api/action", methods=["POST"])
def action():
    data = read_body()
    if not data.get("action"):
        return jsonify({"error": "Vui long chon mot viec can hoi."}), 400
    try:
        answer = ask_gemini(action_prompt(data))
        answer["source"] = "gemini"
        answer["danger_score_percent"] = clamp(answer.get("danger_score_percent"), data.get("score", 50))
        answer["next_actions"] = clean_actions(answer.get("next_actions", [])) if not answer.get("completed") else []
        return jsonify(answer)
    except Exception:
        return jsonify(fallback_action(data))


@app.route("/api/test-gemini", methods=["POST"])
def test_gemini():
    try:
        answer = ask_gemini('Return only {"ok":true,"message":"Gemini connected"}')
        return jsonify({"ok": True, "answer": answer})
    except Exception as error:
        return jsonify({"ok": False, "error": str(error)}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
