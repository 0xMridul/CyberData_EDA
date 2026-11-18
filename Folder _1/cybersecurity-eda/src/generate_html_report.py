"""
HTML Document Generator for EDA Report Export
"""

import os
import markdown

report_md_path = "cybersecurity-eda/results/reports/EDA_REPORT.md"
report_html_path = "cybersecurity-eda/results/reports/EDA_REPORT.html"

with open(report_md_path, "r", encoding="utf-8") as f:
    text = f.read()

# Convert markdown to HTML with tables extension
html_body = markdown.markdown(text, extensions=["tables", "fenced_code"])

styled_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Exploratory Data Analysis: Cyber Attack Evaluation Dataset for Deep Packet Inspection and Analysis</title>
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.6;
    color: #24292e;
    max-width: 1000px;
    margin: 40px auto;
    padding: 0 30px;
  }}
  h1, h2, h3, h4 {{
    color: #0366d6;
    border-bottom: 1px solid #eaecef;
    padding-bottom: 0.3em;
  }}
  h1 {{ font-size: 2em; border-bottom: 2px solid #0366d6; }}
  table {{
    border-collapse: collapse;
    width: 100%;
    margin: 20px 0;
    font-size: 0.9em;
  }}
  th, td {{
    border: 1px solid #dfe2e5;
    padding: 8px 12px;
    text-align: left;
  }}
  th {{
    background-color: #f6f8fa;
    font-weight: 600;
  }}
  tr:nth-child(2n) {{
    background-color: #fbfcfd;
  }}
  img {{
    max-width: 100%;
    height: auto;
    border: 1px solid #e1e4e8;
    border-radius: 6px;
    margin: 15px 0;
    box-shadow: 0 2px 5px rgba(0,0,0,0.05);
  }}
  code {{
    background-color: #f6f8fa;
    padding: 0.2em 0.4em;
    border-radius: 3px;
    font-size: 85%;
    font-family: SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace;
  }}
  pre code {{
    display: block;
    padding: 12px;
    overflow-x: auto;
  }}
  blockquote {{
    border-left: 4px solid #dfe2e5;
    color: #6a737d;
    padding: 0 1em;
    margin: 0;
  }}
</style>
</head>
<body>
{html_body}
</body>
</html>
"""

with open(report_html_path, "w", encoding="utf-8") as f:
    f.write(styled_html)

print(f"Generated standalone exportable HTML report at {report_html_path}")
