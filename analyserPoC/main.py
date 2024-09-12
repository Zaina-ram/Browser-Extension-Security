import json
import logging
import os
import re

library_indicators = ["angular", "react", "vue", "jquery", "lodash", "moment", "redux", "rxjs", "vuex","lib","node_modules", "compiled","build","assets","vendor"]
ajax_tokens = {
		"fetch",
		"$.get",
		"$$.get",
		"jQuery.get",
		"$.post",
		"$$.post",
		"jQuery.post",
		"$.ajax",
		"$$.ajax",
		"jQuery.ajax",
		"$.getJSON",
		"$$.getJSON",
		"jQuery.getJSON",
		"$http.get",
		"$http.post",
		"$http.jsonp",
		"open"
	}

storage_tokens = {
    "chrome.storage.local.set",
    "browser.storage.sync.set",
    "storage.local.set",
    "storage.sync.set",
    "local.set",
    "sync.set",
    "chrome.storage.local.get",
    "browser.storage.sync.get",
    "storage.local.get",
    "storage.sync.get",
    "local.get",
    "sync.get"
}

def parseAndAnalyseManifest(file) -> dict:
    results = {}
    unsafe_csp = []
    content_scripts = []
    background_scripts = []

    with open(file,"r") as f:
        manifest = json.load(f)
        csp =  manifest.get('content_security_policy') 

    # handle different format for csp in manifest file
    if type(csp) == dict and csp.get('extension_pages') != None:
        policies = csp.get('extension_pages').split(';')
        for policy in policies:
            if "'unsafe-eval'" in policy:
                unsafe_csp.append("unsafe-eval")
            if "'unsafe-inline" in policy:
                unsafe_csp.append("unsafe-inline")

    elif type(csp) == dict and csp.get('extension_pages') == None:
        for _, value in csp.items():
            if value == "'unsafe-eval'":
                unsafe_csp.append("unsafe-eval")

    elif csp:
        policies = csp.split(';')
        for policy in policies:
            if "'unsafe-eval'" in policy:
                unsafe_csp.append("unsafe-eval")
            if "'unsafe-inline'" in policy:
                unsafe_csp.append("unsafe-inline")
 
    if unsafe_csp:
        results["content_security_policy"] = unsafe_csp
    
    # Next check permissions
    permissions = manifest.get('permissions')
    unsafe_permissions = []
    if permissions:
        for permission in permissions:
            if permission in permissions_data["permissions_metadata"]:
                unsafe_permissions.append(
                    {
                        "Permission": permission,
                        "Warning_text": permissions_data["permissions_metadata"][
                            permission
                        ]["warning_text"],
                        "Notes": permissions_data["permissions_metadata"][permission][
                            "notes"
                        ],
                    })
    if unsafe_permissions:
        results["unsafe_permissions"] = unsafe_permissions

    # extract content scripts and background scripts
    if 'content_scripts' in manifest and manifest.get('content_scripts') != None:
        for entry in manifest['content_scripts']:
            if 'js' in entry:
                content_scripts.extend(entry['js'])

    if manifest.get('background') != None:
        if "background" in manifest and "scripts" in manifest["background"]:
            background_scripts.extend(manifest['background']['scripts'])

        if "background" in manifest and "service_worker" in manifest["background"]:
            background_scripts.append(manifest['background']['service_worker'])

    return results, content_scripts, background_scripts


def analyseJSFiles(js_files):
    result_web_entry= {}
    result_dangerous_functions= {}
    result_ajax = {}
    result_storage = {}
    web_entrypoints = []
    dangerous_function_call = []
    found_ajax = []
    found_storage = []

    for file in js_files:
        if any(indicator in file for indicator in library_indicators):
            # skip files that are library code, compiled code, etc.
            continue            
        with open(file, 'r', encoding='utf-8') as f:
            content = f.read()
            logging.info(f"Analyzing {file}")
            
            for indicator in jsindicators["risky_functions"]:
                ind = indicator.copy()
                if not indicator["regex"]:
                    if indicator["string"] in content:
                        dangerous_function_call.append(
                        {
                            "Dangerous_function_call" : indicator["name"],
                            "Description" : indicator["description"]
                        })
                if indicator["regex"]:
                    pattern = indicator['regex']
                    if re.search(pattern, content):
                     dangerous_function_call.append(
                        {
                            "Dangerous_function_call" : indicator["name"],
                            "Description" :  indicator["description"]
                        })
            for indicator in jsindicators["web_entrypoints"]:
                if not indicator["regex"]:
                    if indicator["string"] in content:
                        web_entrypoints.append(
                        {
                            "web_entry_points" : indicator["name"],
                            "Description" :  indicator["description"]
                        })
                if indicator["regex"]:
                    pattern = indicator['regex']
                    if re.search(pattern, content):
                     web_entrypoints.append(
                        {
                            "web_entry_points" : indicator["name"],
                            "Description" : indicator["description"]
                        })
            
            for token in ajax_tokens:
                if token in content:
                    found_ajax.append(token)
            for token in storage_tokens:
                if token in content:
                    found_storage.append(token)

            # clean up path
            path = file.split("/")
            short_path = "/".join(path[-2:])
            
            if web_entrypoints:
                result_web_entry[short_path] = web_entrypoints  
            if dangerous_function_call:               
                result_dangerous_functions[short_path] = dangerous_function_call
            if found_ajax:
                result_ajax[short_path] = found_ajax
            if found_storage:
                result_storage[short_path] = found_storage
        
    return result_web_entry, result_dangerous_functions, result_ajax, result_storage


if __name__ == "__main__":
    
    #### LOAD STATIC DATA

    # source: https://github.com/notbella/bowserjr/blob/master/bowserjr/configs/permissions.json
    with open("permissions.json", "r") as f:
        permissions_data = json.load(f)
    # source: https://github.com/notbella/bowserjr/blob/master/bowserjr/configs/javascript_indicators.json
    with open("jsindicators.json", "r") as f:
        jsindicators = json.load(f)

    #### PERFORM STATIC ANALYSIS

    for directory in os.listdir("extension_data_set"):
        js_files = []
        unsafe_extensions = {}
        
        manifest_path = os.path.join("extension_data_set", directory, "manifest.json")
        if os.path.exists(manifest_path):
            res, content_scripts, background_scripts = parseAndAnalyseManifest(manifest_path)
            if res:
                unsafe_extensions[directory] = res
            for content_script in content_scripts:
                js_files_path = os.path.join("extension_data_set", directory,content_script.lstrip('/'))
                js_files.append(js_files_path)
            
            for background_script in background_scripts:
                js_files_path = os.path.join("extension_data_set", directory,background_script.lstrip('/'))
                js_files.append(js_files_path)
            
            result_web_entry, result_dangerous_functions, res_ajax, res_storage = analyseJSFiles(js_files)
            if result_web_entry:
                if directory in unsafe_extensions:
                    unsafe_extensions[directory]["web_entry_vulnerability"] = result_web_entry
                else:
                    unsafe_extensions[directory] = {"web_entry_vulnerability": result_web_entry}

            if result_dangerous_functions:
                if directory in unsafe_extensions:
                    unsafe_extensions[directory]["dangerous_function_call"] = result_dangerous_functions
                else:
                    unsafe_extensions[directory] = {"dangerous_function_call": result_dangerous_functions}
            
            if res_ajax:
                if directory in unsafe_extensions:
                    unsafe_extensions[directory]["AJAX_calls"] = res_ajax
                else:
                    unsafe_extensions[directory] = {"AJAX_calls": res_ajax}

            if res_storage:
                if directory in unsafe_extensions:
                    unsafe_extensions[directory]["storage_calls"] = res_storage
                else:
                    unsafe_extensions[directory] = {"storage_calls": res_storage}

        if not unsafe_extensions: continue
                
        with open(f"analysis_result/{directory}.json", "w") as f:
          json.dump(unsafe_extensions, f, indent=4)
