from flask import Flask, request, redirect, url_for, render_template,send_file
import os
import pandas as pd
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
from langchain_google_genai import ChatGoogleGenerativeAI
import subprocess
import hashlib
import requests
import json
import re
import ast
from VBAMacroAnalyzer import VBAMacroAnalyzer
from pdf import PDF
import shutil

base_folder = "/home/arson/Desktop/SGHackathon/uploads/analyze"
api_key = '711e9c49e39b4aee3a84bfb74678e243b44b863e8d87e65c863bb33d39265ecb'
final_report_path = "/home/arson/Desktop/SGHackathon/FinalReport/"

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'

@app.route('/')
def upload_form():
    return render_template('index.html')

def analyze(file_path):
	macros = []
	if not os.path.exists(file_path):
		print(f"File not found: {file_path}")
	else:
		vba_parser = VBA_Parser(file_path)
		if vba_parser.detect_vba_macros():
			folder_loc = os.path.splitext(os.path.basename(file_path))[0]
			os.makedirs(base_folder+"/"+folder_loc)
			for (filename,stream_path,vba_filename,vba_code) in vba_parser.extract_all_macros():
				if ".bas" in vba_filename:
					macros.append(vba_filename)
					with open(base_folder+"/"+folder_loc+"/"+f"{vba_filename}","w") as code_file:
							code_file.write(vba_code)
			vba_file_path =  base_folder + "/" + folder_loc + "/" + vba_filename
			codeFLowVisualization(vba_file_path,folder_loc)
			return macros
		else:
			print(f"no macro")



def codeFLowVisualization(vba_file_path,folder_loc):
	ouput_path = "/home/arson/Desktop/SGHackathon/FinalReport"
	ouput_path  += "/" + "FinalReport" + "_" + folder_loc
	command = f"python3 /home/arson/Desktop/SGHackathon/vba2graph.py -i {vba_file_path} -o {ouput_path}"
	process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout, stderr = process.communicate()

def compute_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to get the VirusTotal report using the file hash
def get_virustotal_report(file_hash,api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    
    # Check if the response status is 200 (OK)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return {"error": "No report found for this file hash."}
    else:
        return {"error": f"An error occurred: {response.status_code}"}



def olevbaAnalysis(file_path,folder_loc):
	output_path = "/home/arson/Desktop/SGHackathon/FinalReport"
	output_path += "/" + "FinalReport" + "_" + folder_loc + "/" + "Securitycheck"
	command = f"olevba {file_path} >> {output_path}"
	process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout, stderr = process.communicate()
    
    
    
def gemini_classification(raw_text):
	if "GOOGLE_API_KEY" not in os.environ:
		os.environ["GOOGLE_API_KEY"] = "AIzaSyAUV3xVC-3YiMHKGNoMH7-nVh0-84Csom8"
	llm = ChatGoogleGenerativeAI(model="gemini-pro")
	result = llm.invoke(f"Explain the following VBA macro in a way that everyone understands and in the response just give the content alone :\n\n{raw_text}")
	result = str(result)
	index = result.find("response_metadata")
	result = result[8:index]
	return result

def mraptorCheck(file_path,folder_loc):
	ouput_path = "/home/arson/Desktop/SGHackathon/FinalReport"
	ouput_path  += "/" + "FinalReport" + "_" + folder_loc + "/" +"Securitycheck"
	command  = f"mraptor {file_path} >> {ouput_path}"
	process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout, stderr = process.communicate()

def codeEfficiency(macros,folder_loc):
	res = []
	for vba_file in macros:
                with open(base_folder+"/"+folder_loc+"/"+f"{vba_file}","r") as f:
                         vba_code = f.read()
                analyzer = VBAMacroAnalyzer(vba_code)
                evaluation = analyzer.evaluate()
                print("Inefficiencies Found:")
                if len(evaluation['inefficiencies']) == 0 and len(evaluation['optimizations']):
                	res.append("No improvement needed for this code")
                	return res
                for inefficiency in evaluation['inefficiencies']:
                       res.append(f"- {inefficiency}")
                print("\nOptimization Suggestions:")
                for optimization in evaluation['optimizations']:
                       res.append(f"- {optimization}")
                return res

def zip_folder(folder_path,output_path):
	shutil.make_archive(output_path,'zip',folder_path)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        macros = analyze(file_path)
        folder_loc = os.path.splitext(os.path.basename(file_path))[0]
        vba_code = ""
        gemini_result= []
        #PDF
        pdf = PDF()
        pdf.add_page()
        for vba_file in macros:
        	with open(base_folder+"/"+folder_loc+"/"+f"{vba_file}","r") as f:
        		vba_code = f.read()
       			gemini_result.append(gemini_classification(vba_code))
       	
       	# gemini classification
       	pdf.chapter_title("Overview of the Macros")
       	for res in gemini_result:
       		pdf.chapter_body(res)
       		
       	#visualization
       	pdf.add_page()
       	pdf.chapter_title("Code flow")
       	for vba_file in macros:
                image_path = final_report_path + "FinalReport"+ "_" + folder_loc + "/png/" + vba_file +".png"
                pdf.add_image(image_path)
                pdf.add_page()
                	
        mraptorCheck(file_path,folder_loc)
        olevbaAnalysis(file_path,folder_loc)
        pdf.chapter_title("Security report")
        pdf.security_section(final_report_path+"FinalReport"+ "_" + folder_loc+"/Securitycheck")
        
        content = codeEfficiency(macros,folder_loc)
       	pdf.add_page()
       	pdf.chapter_title("Code review")
       	for con in content:
       	     pdf.chapter_body(content)
       	
       	pdf.output(final_report_path+"FinalReport"+ "_" + folder_loc+"/PDF_report.pdf")
        
        for vba_file in macros:
                fileHash = compute_file_hash(base_folder + "/" + folder_loc + "/" + f"{vba_file}")
                get_virustotal_report(fileHash,api_key)
        
        folder_path = final_report_path + "FinalReport"+ "_" + folder_loc
        output_path = final_report_path + "FinalReport"+ "_" + folder_loc
        zip_folder(folder_path,output_path)
        
        output_zip_path = final_report_path + "FinalReport"+ "_" + folder_loc + ".zip"
        return send_file(output_zip_path, as_attachment=True)
        return 'File successfully uploaded and processed'
    return 'File upload failed'

portnumber = 7000

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(port=portnumber,debug=True)
