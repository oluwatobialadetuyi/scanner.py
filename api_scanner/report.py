"""Report generation utilities."""
import json
from jinja2 import Template

HTML_TEMPLATE = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>API Scanner Report - {{ base }}</title>
    <style>
      body{font-family: Arial,Helvetica,sans-serif;margin:20px}
      .issue{border:1px solid #ddd;padding:10px;margin:10px 0}
      .high{border-left:6px solid #c00}
      .medium{border-left:6px solid #f90}
      .low{border-left:6px solid #09c}
    </style>
  </head>
  <body>
    <h1>API Scanner Report</h1>
    <p>Target: {{ base }}</p>
    <h2>Findings</h2>
    {% for r in results %}
      <h3>{{ r.url }}</h3>
      {% if r.issues %}
        {% for i in r.issues %}
          <div class="issue {{ i.severity }}">
            <strong>{{ i.title }} ({{ i.severity }})</strong>
            <p>{{ i.description }}</p>
            <pre>{{ i.evidence }}</pre>
            <p><em>Remediation:</em> {{ i.remediation }}</p>
          </div>
        {% endfor %}
      {% else %}
        <p>No issues found for this endpoint.</p>
      {% endif %}
    {% endfor %}
  </body>
</html>
"""


def generate_json_report(base, results, out_path):
    data = {'base': base, 'results': results}
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


def generate_html_report(base, results, out_path):
    t = Template(HTML_TEMPLATE)
    html = t.render(base=base, results=results)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html)

