🔐 Privacy Leak Analyzer for Android APKs
A web-based tool to analyze Android APK files for privacy and security risks using static analysis. This project helps identify dangerous permissions, insecure API usage, and generate a risk score — all presented in a sleek and modern UI.

🧠 Features
✅ Detects risky permissions like CAMERA, READ_SMS, LOCATION, etc.

🔍 Scans for insecure API usage patterns such as:

addJavascriptInterface

HttpURLConnection

openConnection with java.net.URL

📊 Calculates and categorizes a risk score:

Low, Medium, or High

📋 Generates detailed HTML reports with:

Used permissions

Risky permissions

Insecure API usage

Visual risk metrics via Chart.js

🛠 Tech Stack
Layer	Technology
Language	Python
Web Framework	Flask
APK Analysis	Androguard
Frontend	HTML + CSS
Visualization	Chart.js

🚀 How It Works
Upload APK
User uploads an Android .apk file via the web interface.

Static Analysis
The app uses AnalyzeAPK() from Androguard to extract:

Permissions

Package & App Name

Method Calls

Risk Detection

Compares permissions with a predefined list of dangerous ones.

Searches bytecode for insecure API patterns.

Calculates a risk score.

Report Display
A detailed HTML report is generated and visualized with a risk summary chart.
