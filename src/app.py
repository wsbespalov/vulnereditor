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
from database import update_vulner_by_id_in_database
from database import create_vulner_in_database

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
    data_json = {}
    status = 404
    if request.method == 'GET':
        vid = request.args.get('id', 'CVE-2018-7305', type=str)
        data_json["vulnerability_id"] = vid
        cwe_str = request.args.get('cwe', [], type=str)
        cwe_list = cwe_str.replace(' ', '').split(';')
        cwe = []
        for c in cwe_list:
            if c != "":
                if "CWE-" in c:
                    cwe.append(c)
        data_json["cwe"] = cwe
        capec_str = request.args.get('capec', [], type=str)
        capec_list = capec_str.replace(' ', '').split(';')
        capec = []
        for c in capec_list:
            if c != "":
                if "CAPEC-" in c:
                    capec.append(c)
        data_json["capec"] = capec
        references_str = request.args.get('references', [], type=str)
        references_list = references_str.replace(' ', '').split(';')
        references = []
        for r in references_list:
            if r != "":
                if "http" in r:
                    references.append(r)
        data_json["references"] = references
        data_type = request.args.get('data_type', '', type=str)
        data_json["data_type"] = data_type
        data_format = request.args.get('data_format', '', type=str)
        data_json["data_format"] = data_format
        data_version = request.args.get('data_version', '', type=str)
        data_json["data_version"] = data_version
        description = request.args.get('description', '', type=str)
        data_json["description"] = description
        # published = str2dt(request.get('published', '', type=str))
        # cvss_time = str2dt(request.get('cvss_time', '', type=str))
        cvss = request.args.get('cvss', '0.0', type=str)
        data_json["cvss"] = cvss
        rank = request.args.get('rank', '0', type=str)
        vector_string = request.args.get('vector_string', '', type=str)
        data_json["vector_string"] = vector_string
        source = request.args.get('source', '', type=str)
        data_json["source"] = source

        result = update_vulner_by_id_in_database(id=vid, data=data_json)

        data = {'result': result}

        if result == -1:
            status = 404
        else:
            status = 200
        
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
                vulner_source = "CVE"
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

@app.route('/create_vulner')
def create_vulner():
    result = create_vulner_in_database(vid, data)

if __name__ == '__main__':
    app.run(
        host='127.0.0.1',
        port=8000,
        debug=True
    )