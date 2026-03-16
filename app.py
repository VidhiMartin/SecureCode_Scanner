# app.py

import os
from flask import Flask, render_template_string, abort
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import SelectField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_talisman import Talisman

from utils import sanitize_input, scan_code_with_llm, ALLOWED_LANGUAGES

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET", os.urandom(32))
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["20 per minute", "200 per hour"]
)

csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'"],
    'style-src': ["'self'", "'unsafe-inline'"]
}

Talisman(app, content_security_policy=csp)


class ScanForm(FlaskForm):
    language = SelectField("Programming Language", choices=ALLOWED_LANGUAGES)
    code = TextAreaField(
        "Source Code",
        validators=[DataRequired(), Length(min=5, max=10000)]
    )
    submit = SubmitField("Scan Code")


@app.route("/", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def index():

    form = ScanForm()
    result = None

    if form.validate_on_submit():

        language = form.language.data
        code = sanitize_input(form.code.data)

        if len(code) > 10000:
            abort(413)

        result = scan_code_with_llm(language, code)

    return render_template_string(TEMPLATE, form=form, result=result)


TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<title>LLM-Powered Source Code Scanner</title>
<style>
body {
font-family: Arial;
background:#0f172a;
color:white;
padding:40px;
}
.container {
max-width:1000px;
margin:auto;
background:#1e293b;
padding:30px;
border-radius:8px;
}
textarea {
width:100%;
height:300px;
background:#020617;
color:#e2e8f0;
padding:10px;
border-radius:5px;
border:1px solid #334155;
}
select,button{
padding:10px;
margin-top:10px;
}
.result{
margin-top:30px;
background:#020617;
padding:20px;
border-radius:6px;
}
</style>
</head>
<body>

<div class="container">
<h2>LLM-Powered Source Code Scanner</h2>
<p>AI security scanner using Llama 3.3 70B Instruct</p>

<form method="POST">
{{ form.hidden_tag() }}

<label>Language</label><br>
{{ form.language() }}<br><br>

<label>Paste Source Code</label>
{{ form.code() }}

<br>
{{ form.submit() }}

</form>

{% if result %}
<div class="result">
<h3>Scan Results</h3>
<pre>{{ result | tojson(indent=2) }}</pre>
</div>
{% endif %}

</div>

</body>
</html>
"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)


