import os
import json
from flask import Flask, request, render_template_string
from androguard.misc import AnalyzeAPK

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

DANGEROUS_PERMISSIONS = {
    'android.permission.READ_SMS',
    'android.permission.RECORD_AUDIO',
    'android.permission.CAMERA',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.READ_CONTACTS',
    'android.permission.SEND_SMS'
}

def analyze_apk(apk_path):
    a, d, dx = AnalyzeAPK(apk_path)
    used_permissions = set(a.get_permissions())
    risky_permissions = used_permissions & DANGEROUS_PERMISSIONS

    result = {
        "app_name": a.get_app_name(),
        "package": a.get_package(),
        "permissions": list(used_permissions),
        "risky_permissions": list(risky_permissions),
        "insecure_apis": [],
        "risk_score": 0,
        "risk_level": "Low"
    }

    for method in dx.get_methods():
        method_str = method.method.get_class_name() + "->" + method.method.get_name()
        if 'WebView' in method_str and 'addJavascriptInterface' in method_str:
            result["insecure_apis"].append(method_str)
        if 'HttpURLConnection' in method_str:
            result["insecure_apis"].append(method_str)
        if 'openConnection' in method_str and 'java/net/URL' in method_str:
            result["insecure_apis"].append(method_str)

    score = len(risky_permissions) * 2 + len(result["insecure_apis"]) * 3
    result["risk_score"] = score
    result["risk_level"] = (
        "High" if score > 10 else
        "Medium" if score > 5 else
        "Low"
    )

    with open(f"{REPORT_FOLDER}/{result['package']}.json", "w") as f:
        json.dump(result, f, indent=4)

    return result

# Stylish index upload page
INDEX_HTML = '''
<!DOCTYPE html>
<html>
<head>
  <title>Privacy Leak Analyzer</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
  <style>
    body {
      font-family: 'Inter', sans-serif;
      background: linear-gradient(to right, #667eea, #764ba2);
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
    }
    .container {
      background: rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(12px);
      padding: 40px;
      border-radius: 15px;
      box-shadow: 0 8px 30px rgba(0,0,0,0.2);
      width: 400px;
      text-align: center;
      color: #fff;
    }
    h2 {
      margin-bottom: 20px;
      font-weight: 600;
    }
    input[type=file] {
      margin: 20px 0;
      padding: 10px;
      border-radius: 8px;
      background: #fff;
      border: none;
      width: 100%;
    }
    button {
      background: #00c9a7;
      color: white;
      border: none;
      padding: 12px 20px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 16px;
      font-weight: 600;
      width: 100%;
    }
    button:hover {
      background: #02b093;
    }
  </style>
</head>
<body>
  <div class="container">
    <h2>🔐 Privacy Leak Analyzer</h2>
    <form method="POST" enctype="multipart/form-data">
      <input type="file" name="apk" required><br>
      <button type="submit">Scan APK</button>
    </form>
  </div>
</body>
</html>
'''

# Stylish result page
RESULT_HTML = '''
<!DOCTYPE html>
<html>
<head>
  <title>Scan Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
  <style>
    body {
      font-family: 'Inter', sans-serif;
      background: linear-gradient(to right, #43cea2, #185a9d);
      padding: 30px;
      color: #fff;
    }
    .report {
      background: rgba(255, 255, 255, 0.08);
      backdrop-filter: blur(12px);
      max-width: 900px;
      margin: auto;
      padding: 30px 40px;
      border-radius: 15px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.3);
    }
    h2 {
      font-weight: 600;
      margin-bottom: 10px;
    }
    h3 {
      margin-top: 30px;
      font-weight: 600;
    }
    ul {
      background: rgba(255,255,255,0.05);
      padding: 15px 25px;
      border-radius: 8px;
    }
    li {
      margin-bottom: 5px;
    }
    .tag {
      padding: 6px 12px;
      border-radius: 6px;
      font-weight: bold;
    }
    .Low { background: #28a745; color: #fff; }
    .Medium { background: #ffc107; color: #333; }
    .High { background: #dc3545; color: #fff; }
    a {
      display: inline-block;
      margin-top: 25px;
      color: #00ffe1;
      text-decoration: none;
      font-weight: 600;
    }
    a:hover {
      text-decoration: underline;
    }
    canvas {
      max-width: 100%;
      margin-top: 30px;
    }
  </style>
</head>
<body>
  <div class="report">
    <h2>📋 Report for: {{ result.app_name }}</h2>
    <p><strong>📦 Package:</strong> {{ result.package }}</p>
    <p><strong>⚠️ Risk Level:</strong> <span class="tag {{ result.risk_level }}">{{ result.risk_level }}</span></p>
    <p><strong>📈 Risk Score:</strong> {{ result.risk_score }}</p>

    <canvas id="riskChart"></canvas>

    <h3>🔐 Used Permissions:</h3>
    <ul>{% for p in result.permissions %}<li>{{ p }}</li>{% endfor %}</ul>

    <h3>🚨 Risky Permissions:</h3>
    <ul>{% for p in result.risky_permissions %}<li>{{ p }}</li>{% endfor %}</ul>

    <h3>🛡️ Insecure API Usage:</h3>
    <ul>{% for api in result.insecure_apis %}<li>{{ api }}</li>{% endfor %}</ul>

    <a href="/">⬅️ Scan Another APK</a>
  </div>

  <script>
    const ctx = document.getElementById('riskChart');
    const chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Total Permissions', 'Risky Permissions', 'Insecure APIs', 'Risk Score'],
            datasets: [{
                label: 'Privacy Risk Metrics',
                data: [{{ result.permissions|length }}, {{ result.risky_permissions|length }}, {{ result.insecure_apis|length }}, {{ result.risk_score }}],
                backgroundColor: ['#3498db', '#f1c40f', '#e74c3c', '#95a5a6'],
                borderRadius: 10
            }]
        },
        options: {
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: { beginAtZero: true }
            }
        }
    });
  </script>
</body>
</html>
'''

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        apk_file = request.files["apk"]
        path = os.path.join(UPLOAD_FOLDER, apk_file.filename)
        apk_file.save(path)

        try:
            result = analyze_apk(path)
        except Exception as e:
            return f"<h3>Error analyzing APK:</h3><pre>{str(e)}</pre>"

        os.remove(path)
        return render_template_string(RESULT_HTML, result=result)

    return render_template_string(INDEX_HTML)

if __name__ == "__main__":
    app.run(debug=True)
