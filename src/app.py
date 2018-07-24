from flask import Flask
from flask import render_template
from flask import url_for
from flask import redirect
from flask import request
from math import floor
from datetime import datetime 

import json

app = Flask(__name__)

from database import count_vulners
from database import find_vulner_by_id_in_database

def dt2str(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def str2dt(dts):
    return datetime.strptime(dts, '%Y-%m-%d %H:%M:%S')

@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
    return render_template("index.html")

@app.route('/edit/', methods=['GET', 'POST'])
def edit():
    return render_template("edit.html")

@app.route('/statistic/', methods=['GET', 'POST'])
def statistic():
    vulners_count = count_vulners()
    return render_template("statistic.html", vulners_count = vulners_count)

@app.route('/update_vulner_by_id', methods=['GET'])
def update_vulner_by_id():
    data = {}
    status = 404
    if request.method == 'GET':
        id = request.args.get('id', 'CVE-2018-7305', type=str)
        print(id)
        cwe_str = request.args.get('cwe', [], type=str)
        try:
            cwe = json.loads(cwe_str)
        except:
            cwe = []
        capec_str = request.get('capec', [], type=str)
        try:
            capec = json.loads(capec_str)
        except:
            capec = []
        references_str = request.get('references', [], type=str)
        try:
            references = json.loads(references_str)
        except:
            references = []
        data_type = request.get('data_type', '', type=str)
        data_format = request.get('data_format', '', type=str)
        data_version = request.get('data_version', '', type=str)
        description = request.get('description', '', type=str)
        published = str2dt(request.get('published', '', type=str))
        cvss_time = str2dt(request.get('cvss_time', '', type=str))
        cvss = request.get('cvss', '0.0', type=str)
        rank = request.get('rank', '0', type=str)
        vector_string = request.get('vector_string', '', type=str)
        source = request.get('source', '', type=str)


        data = {'result': id}
    response = app.response_class(
        response=json.dumps(data),
        status=200,
        mimetype='application/json'
    )
    return response

@app.route('/find_vulner_by_id', methods=['GET'])
def find_vulner_by_id():
    data = {}
    status = 404
    if request.method == 'GET':
        id = request.args.get('id', 'CVE-2018-7305', type=str)
        vulner = find_vulner_by_id_in_database(id)
        if vulner is not None:
            print(vulner)
            vulner_id = vulner.get("vulnerability_id", "undefined")
            vulner_cwe = "; ".join(vulner.get("cwe", []))
            vulner_capec = "; ".join(vulner.get("capec", []))
            vulner_references = "; ".join(vulner.get("references", []))
            vulner_data_type = vulner.get("data_type", "undefined")
            vulner_data_format = vulner.get("data_format", "undefined")
            vulner_data_version = vulner.get("data_version", "undefined")
            vulner_description = vulner.get("description", dt2str(datetime.utcnow()))
            vulner_published = dt2str(vulner.get("published", datetime.utcnow()))
            vulner_cvss_time = dt2str(vulner.get("cvss_time", datetime.utcnow()))
            vulner_cvss = str(vulner.get("cvss", "0.0"))
            vulner_rank = str(floor(float(vulner_cvss)))
            vulner_vector_string = vulner.get("vector_string", "undefined")
            vulner_references = "; ".join(vulner.get("references", []))
            vulner_source = ""
            if vulner_data_type == "CVE":
                vulner_source = "CVE Database"
            data = {
                'id': vulner_id, 
                'cwe': vulner_cwe, 
                'capec': vulner_capec,
                'data_type': vulner_data_type,
                'data_format': vulner_data_format,
                'data_version': vulner_data_version,
                'description': vulner_description,
                'cvss_time': vulner_cvss_time,
                'published': vulner_published,
                'cvss': vulner_cvss,
                'rank': vulner_rank,
                'vector_string': vulner_vector_string,
                'references': vulner_references,
                'source': vulner_source}
            status = 200
        else:
            data = {
                'id': "undefined", 
                'cwe': "undefined", 
                'capec': "undefined",
                'data_type': "undefined",
                'data_format': "undefined",
                'data_version': "undefined",
                'description': "undefined",
                'cvss_time': "undefined",
                'published': "undefined",
                'cvss': "undefined",
                'rank': "undefined",
                'vector_string': "undefined",
                'references': "undefined",
                'source': "undefined"}
            status = 503
    response = app.response_class(
        response=json.dumps(data),
        status=status,
        mimetype='application/json'
    )
    return response


if __name__ == '__main__':
    app.run(
        host='127.0.0.1',
        port=8000,
        debug=True
    )