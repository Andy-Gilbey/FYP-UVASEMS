
from datetime import datetime, timedelta
from functools import wraps
from html import escape
import os
import re
from flask import Flask, abort, flash, jsonify, make_response, render_template, request, redirect, send_file, session, url_for
from markupsafe import Markup
from Audit import Audit
from werkzeug.exceptions import Unauthorized
from ConfigurationManager import Configurations  
from DBConnectionManager import DBConnectionHandler
from DataVisualization import DataViz  
from EncryptionHandler import hash_salt_pw
from ResultsHandler import ResultsHandler
from StatisticsHandler import StatisticsHandler
from UserDataManager import UserDataManager
from ScanUtils import ScanUtils 




app = Flask(__name__)






# Create the class instances
configs = Configurations()
dbConnection = DBConnectionHandler(configs)
userManager = UserDataManager(dbConnection)
auditer = Audit(dbConnection)
scanUtil = ScanUtils(dbConnection)
reshand = ResultsHandler(dbConnection)
stathand = StatisticsHandler(dbConnection)

# setup cookie
with open('9e83d8.enc', 'r') as file:
    app.config['SECRET_KEY'] = file.read().strip()
app.config['SESSION_COOKIE_NAME'] = 'UVSEMSsession'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)


secret_key = dbConnection.getSecretKey()
if secret_key:
    app.secret_key = secret_key
else:
    raise Exception("Secret key Error")


# Dictionary mapping status codes to their messages and image paths
error_info = {
    400: {
        "code": 400,
        "message": "Bad Request",
        "image_path": "images/403.png"
    },
    401: {
        "code": 401,
        "message": "Unauthorised access attempt detected. Please authenticate.",
        "image_path": "images/401.png"
    },
    403: {
        "message": "Forbidden. Access to this resource is denied.",
        "image_path": "images/405.png"
    },
    404: {
        "message": "Page not found.",
        "image_path": "images/404.png"
    },
    405: {
        "message": "Method not allowed",
        "image_path": "images/405.png"
    },
    301: {
        "message": "The requested resource has been moved permanently.",
        "image_path": "images/301_error.png"
    },
    500: {
        "message": "Internal Server Error.",
        "image_path": "images/500.png"
    },
    503: {
        "message": "Service Unavailable.",
        "image_path": "images/503.png"
    },
}


@app.after_request
def add_headers(response):
    # Content Security Policy (CSP) header, this breaks everything so is disabled right now, until I can mend it if given time
    # The reason is some of the CSS is external so they must all be whitelisted
    #response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' https://maxcdn.bootstrapcdn.com;"

    response.headers['Cache-Control'] = "no-cache, no-store, must-revalidate"
    response.headers['Pragma'] = "no-cache"
    response.headers['Expires'] = "0"
    response.headers['X-Frame-Options'] = "DENY" 
    response.headers['X-Content-Type-Options'] = "nosniff"
    response.headers['Referrer-Policy'] = "no-referrer-when-downgrade"
    response.headers['X-XSS-Protection'] = "1 mode block"
    return response




def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if 'role' not in session:
                abort(401) 
            elif session['role'] not in roles:
                abort(403) 
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(429)
@app.errorhandler(500)
@app.errorhandler(503)
def handle_error(error):
    error_code = error.code if hasattr(error, 'code') else 500
    error_details = error_info.get(error_code, {
        "message": "An unexpected error has occurred.",
        "image_path": "images/unknown_error.png"
    })
    
    image_url = url_for('static', filename=error_details["image_path"])
    

    return render_template('Error.html', code=error_code, message=error_details["message"], image_url=image_url), error_code


@app.route("/")
def login():
    session['start'] = True
    response = make_response(redirect(url_for("login")))
    return render_template("login.html")

#@app.route("/routeTest")
#def test():
#    abort(500)

@app.route('/logout')
def logout():
    session.pop('authenticated', None)
    session.clear()
    response = make_response(redirect(url_for("login")))
    response.set_cookie('session', '', expires=0)
    return response

@app.route("/login", methods=["POST"])
def loginPost():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    
    if not re.match(r'^[a-zA-Z0-9]+$', username):
            flash("Invalid username")
            return redirect(url_for("login"))

    
    result = userManager.validate_login(username, password)

    if result.get('success', False):
        session['authenticated'] = True
        session["username"] = username
        session["user_id"] = result.get('user_id')
        session["access_level"] = result.get('access_level')
        session["role"] = result.get('role')
        session['user_agent'] = request.headers.get('User-Agent')
        session['ip'] = request.remote_addr
        session.permanent = True
        
        if session["role"] == 1:
                return redirect(url_for("renderAdminDashboard"))
        elif session["role"] == 2:
                return redirect(url_for("renderPentesterDash"))
        elif session["role"] == 3:
                return redirect(url_for("renderAnalystDash"))
        elif session["role"] == 4:
                return redirect(url_for("renderEngineerDash"))
        else:
            # If role is not 1-4 or has been misconfigured some how, authentication needs to fail so I did up error 32x for this purpose
            auditer.log_audit_entry(session["user_id"], 'Error 32x', ', Role not recongised.',session['ip'], session['user_agent'], 3, 'Misconfiguration', 'Role value not found, This could be a session problem or user misconfiguration issue')
            flash("Error[32x]: Role not recognised")
            return redirect(url_for("login"))
    else:
        # Failed login-boo
        flash(result.get('message', "An error occurred during login."))
        return redirect(url_for("login"))



@app.route("/AdminDashboard")
@role_required(1)
def renderAdminDashboard():
    currentUsers = userManager.get_current_logged_in_users()
    totalUsers = userManager.count_every_users()
    inactives = userManager.count_redundant_users()
    userRoles = userManager.get_role_counts()
    actions = auditer.get_all_action_count()
    tot_log = auditer.count_all_alog()
    week_scan = stathand.scans_in_week()
    scanOwner = stathand.get_scans_owner()
    pie = DataViz.bake_a_pie_roles(userRoles)
    pie_a = DataViz.bake_a_pie_actions(actions)
    pie_b = DataViz.bake_scan_owners_pie(scanOwner)
    latestAuditLog = auditer.get_latest_auditlog()
    return render_template("AdminDashboard.html", tot_log=tot_log,currentUsers=currentUsers, totalUsers=totalUsers, inactives=inactives, pie=pie, latestAuditLog=latestAuditLog, pie_a=pie_a, pie_b=pie_b, week_scan=week_scan)

@app.route("/PenTesterDashboard")
@role_required(1,2)
def renderPentesterDash():
    user_id = session.get("user_id")
    scan_entries = scanUtil.snatch_scannames_by_id(user_id)
    scan_count = len(scan_entries)
    tot_scans = stathand.get_all_scans_no()
    retest_alerts = scanUtil.get_retests(user_id)[:3]
    sev = stathand.get_vas_sev_owner(user_id)
    risk = stathand.get_zap_risk_owner(user_id)
    pie_a = DataViz.bake_scan_bars_sev(sev)
    pie_b = DataViz.bake_pie_risks(risk)

    re_alert_count = scanUtil.get_retests_count(user_id)
    nmap_count,dns_count, vas_count, zap_count = scanUtil.count_all_scan_types(user_id)
    recon = nmap_count + dns_count
    pie_c = DataViz.bake_scancounts(recon,vas_count,zap_count)
    #print(retest_alerts)
    return render_template("PenTesterDashboard.html",recon=recon,vas_count=vas_count,zap_count=zap_count,scan_count=scan_count,tot_scans=tot_scans,retest_alerts=retest_alerts,pie_a=pie_a,pie_b=pie_b,pie_c=pie_c,re_alert_count=re_alert_count)
    
@app.route("/AnalystDashboard")
@role_required(1,3)
def renderAnalystDash():
    user_id = session.get("user_id")
    taskcount = stathand.get_count_tasks(user_id)
    allres = stathand.get_count_results()
    fav = stathand.find_ana_besto(user_id)
    fav_user = userManager.get_username(fav)
    #print("Session username:", session.get('username')) # Debug printing - DO NOT FORGET TO REMOVE
    #print("Session access level:", session.get('access_level')) # Debug printing  - DO NTOT FORGET TO REMOVE

    return render_template("AnalystDashboard.html", taskcount=taskcount,allres=allres, fav=fav,fav_user=fav_user)


@app.route("/EngineerDashboard")
@role_required(1,4)
def renderEngineerDash():
    user_id = session.get("user_id")
    cve_count = ScanUtils.count_CVES()
    pie = DataViz.bake_CVE_pie(cve_count)
    tot_scans = stathand.get_all_scans_no()
    fav = stathand.find_eng_besto(user_id)
    fav_user = userManager.get_username(fav)
    #print("Session username:", session.get('username')) # Debug printing - DO NOT FORGET TO REMOVE
    #print("Session access level:", session.get('access_level')) # Debug printing  - DO NTOT FORGET TO REMOVE

    return render_template("EngineerDashboard.html", pie=pie, tot_scans=tot_scans,fav=fav,fav_user=fav_user)
        
        
@app.route("/AddUser_Page")
@role_required(1)
def renderAddUserPage():
    nextUserId = userManager.get_next_userId()
    return render_template("NewUser.html",nextUserId = nextUserId )


@app.route("/addUserDb", methods=["POST"])
def addUserDb():
    userData = {
        "username": request.form.get("username"), #NONE
        "firstName": request.form.get("fname"), #E
        "lastName": request.form.get("lname"), #E
        "password": request.form.get("password"), #H+S
        "role": request.form.get("role"), #E
        "email": request.form.get("email"), #E
        "phone": request.form.get("phone"),#E
    }
    print("Recieved user data:", userData)

    if userManager.save_new_user(userData):
        return redirect(url_for("renderAdminDashboard"))
    else:
        return "Error adding user"

@app.route("/NewScan")
@role_required(1,2)
def renderNewScan():
    user_id = session.get('user_id')  
    if not user_id:
        raise Unauthorized()

    scans = scanUtil.snatch_scannames_by_id(user_id)
    print(scans)
    return render_template("NewScan.html", scans=scans)


@app.route("/ManageUsers")
@role_required(1)
def renderManageUsers():
    data = userManager.get_user_data()  
    access_level = session.get("access_level", None)
    return render_template('ManageUsers.html', users=data,access_level=access_level)

@app.route("/RetestAlerts")
@role_required(1,2)
def renderRetestAlerts():
    user_id = session.get('user_id')  
    retest_alerts = scanUtil.get_retests(user_id)
    return render_template('RetestAlerts.html',retest_alerts=retest_alerts )


# This route is used to recieve data from the manage user page and update the database with the new changes
# It also slaps in an entry into the audit log to show a User change ahs been made by x user.
@app.route('/updateUserData', methods=['POST'])
@role_required(1)
def update_user_data():
    updated_data = request.json
    userId = updated_data['userId']
    prim_user_id = session.get("user_id")
    
    success = userManager.update_user_data(userId, updated_data)

    if success:
        auditer.logUserDataChange(prim_user_id, userId, updated_data['username'])
        return jsonify({'success': True, 'message': 'User data updated successfully.'})
    else:
        return jsonify({'success': False, 'message': 'Failed to update user data.'})
    
    
@app.route('/auditLogs')
@role_required(1)
def render_audit_log():
    audit_data = auditer.get_audit_log_data()  
    return render_template('AuditLog.html', auditLogs=audit_data)



@app.route('/create_task', methods=['POST'])
def create_task_and_scan():
    
    user_id = session["user_id"]
    task_name = request.form['taskName']
    target_ip = request.form['scanTarget']
    retestOf = request.form.get('retestOf', 0)
    task_id = ScanUtils.create_VAS_task(task_name, target_ip)
    scan_id = scanUtil.create_new_scan(task_name, target_ip, task_id, user_id,retestOf)
    confirmation_message = f"Task '{task_name}' has been created successfully with Task ID: {task_id} and Scan ID: {scan_id}."

    return render_template('Message.html', message=confirmation_message)


@app.route('/RunScan', methods=['POST'])
def run_scan():
    """
    Handles the request to start up a scan process based on form data submitted by the user.
    It first checks if a scan with the given name already exists in the database to ensure that only one exists.
    If the scan name exists, it redirects to an error message page. Otherwise, it continues forward with the scan.
    
    The function includes creating a new scan task, performing DNS lookups if a domain is provided,
    starting Nmap scans if an IP address and scan type are provided, and starting a VAS scan if
    the conditions are met (recon_only flag is not set and both portlist and scanner are provided).
    
    Args:
        task_name (str): The name of the task to be created, extracted from the form data.
        target_ip (str): The target IP address for the scan, extracted from the form data.
        domain (str, optional): An optional domain name for DNS lookup, extracted from the form data.
        nmap_scan_type (int, optional): An optional Nmap scan type, extracted from the form data.
        portlist (str, optional): An optional list of ports for the VAS scan, extracted from the form data.
        scanner (str, optional): The scanner to be used for the VAS scan, extracted from the form data.
        recon_only (bool): A flag indicating whether only reconnaissance should be performed, derived from the form data.

    Returns:
        A redirect to 'Message.html' with an error message if the scan name already exists.
        A redirect to 'NewScan.html' upon successful initiation of the scan process or if any part of the process fails
        without a conflicting scan name.
    """
    task_name = request.form['taskName']
    target_ip = request.form['scanTarget']
    domain = request.form.get('domain')
    nmap_scan_type = request.form.get('nmapscan', type=int, default=None)
    portlist = request.form.get('portlist')
    scanner = request.form.get('scanner')
    recon_only = 'reconOnly' in request.form
    user_id = session['user_id']
    retestOf = request.form.get('retestOf')
    # Have to check if a scan name already exists in the databse
    # only one scan of name x can exist.
    if scanUtil.check_scan_already(task_name):
        # Redirect to the Message.html with an error message if the scan name already exists
            return render_template('Message.html', message="This Scan Already Exists. Try a different name.")
    

    task_id = None
    if task_name and target_ip:
        try:
            task_id = ScanUtils.create_VAS_task(task_name, target_ip)
            scan_id = scanUtil.create_new_scan(task_name, target_ip, task_id,user_id,retestOf)
        except Exception as e:
            if str(e) == "Failed to create target":
                message = f"Task '{task_name}' failed to insert, Task name may already exist."
                return render_template('Message.html', message=message)
            else:
                message = str(e)
                return render_template('Message.html', message=message)
    ################### DNS
    if domain:
        dns_servers = scanUtil.set_DNS_servers()
        dnsResults = scanUtil.do_DNS_scan(domain, dns_servers)
        if dnsResults:
            success = scanUtil.save_dns_records(scan_id, domain, dnsResults)
            if not success:
                print(f"Failed to save DNS records for domain {domain}")

    ################### NMAP
    if nmap_scan_type is not None:
        start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        nmapResults = scanUtil.doNmapScan(target_ip, nmap_scan_type)
         # Save Nmap results
        if nmapResults and 'error' not in nmapResults:
            success = scanUtil.save_nmap_res(scan_id, nmapResults, nmap_scan_type, start_time)
            if not success:
                print(f"Failed to save Nmap results for IP {target_ip}")

    
    #################### VAS
    if task_id and not recon_only and portlist and scanner:
        scanUtil.start_VAS(task_id, portlist, scanner)  


    return render_template('NewScan.html')

@app.route("/PendingScans")
@role_required(1,2)
def show_pending():
    user_id = session.get("user_id")
    tasks = scanUtil.get_VAS_tasks(user_id)
    print(tasks)
    return render_template('PendingScans.html', tasks=tasks)

@app.route("/VulnerabilityLibrary")
@role_required(1,2)
def render_vullib():
    cves = ScanUtils.snatch_CVES()
    cve_count = ScanUtils.count_CVES()
    cve_time = ScanUtils.snatch_CVES_by_time()
    pie = DataViz.bake_CVE_pie(cve_count)
    cve_time_pie = DataViz.bake_cve_creation_time_chart(cve_time)
    cve_by_year = ScanUtils.snatch_CVES_by_year()
    #print(cve_by_year[0])  
    cve_year_pie = DataViz.bake_cve_creation_by_year(cve_by_year)
    return render_template('VulnerabilityLibrary.html', cves=cves, cve_count=pie, cve_time_pie=cve_time_pie, cve_year_pie=cve_year_pie)

@app.route("/VulnerabilityLibraryEngineer")
@role_required(1,4)
def render_vullibEN():
    cves = ScanUtils.snatch_CVES()
    cve_count = ScanUtils.count_CVES()
    cve_time = ScanUtils.snatch_CVES_by_time()
    pie = DataViz.bake_CVE_pie(cve_count)
    cve_time_pie = DataViz.bake_cve_creation_time_chart(cve_time)
    cve_by_year = ScanUtils.snatch_CVES_by_year()
    #print(cve_by_year[0])  
    cve_year_pie = DataViz.bake_cve_creation_by_year(cve_by_year)
    return render_template('VulnerabilityLibrary_en.html', cves=cves, cve_count=pie, cve_time_pie=cve_time_pie, cve_year_pie=cve_year_pie)

@app.route("/NewZapScan")
@role_required(1,2)
def renderNewZapScan():
    user_id = session["user_id"]
    print(user_id)
    if user_id: 
        scan_details = scanUtil.get_scans_by_user(user_id)  
        print(scan_details)
        return render_template('NewZapScan.html', scan_details=scan_details)
    else:
        raise Unauthorized()
    
@app.route("/MyScans")
@role_required(1,2)
def render_myscans():
    user_id = session["user_id"]
    if user_id: 
        scans = scanUtil.snatch_my_scans(user_id) 
        return render_template('MyScans.html', scans=scans)
    else:
        raise Unauthorized()
    
@app.route("/MyTasks")
@role_required(1,3)
def render_mytasks():
    user_id = session.get("user_id")
    if user_id:
        reshand.is_note_validate(user_id)
        tasks = scanUtil.populate_ana_scans(user_id)
        print(tasks)
        return render_template('MyTasks.html', tasks=tasks)
    else:
        raise Unauthorized()
    
@app.route("/MyJobs")
@role_required(1,4)
def rendermyjobs():
    user_id = session.get("user_id")
    if user_id:
        tasks = scanUtil.populate_eng_scans(user_id)
        #print(tasks)
        return render_template('MyJobs.html', tasks=tasks)
    else:
        raise Unauthorized(401)

@app.route("/CompletedJobs")
@role_required(1,4)
def rendecompjobs():
    user_id = session.get("user_id")
    if user_id:
        tasks = scanUtil.populate_eng_scans(user_id)
        tasks = [task for task in tasks if task['Status'] == 'Closed'] # Gotta get rid of them non-closed jobs.

        print(tasks)
        return render_template('CompletedJobs.html', tasks=tasks)
    else:
        raise abort(401)


@app.route("/MyReports")
@role_required(1,3)
def renderMyResults():
    user_id = session.get("user_id")
    if user_id:
        reshand.is_note_validate(user_id)
        reports=reshand.snatch_reports_user_ana(user_id)

        print(reports)
        return render_template('MyReports.html', reports=reports)
    else:
        raise Unauthorized()
    
@app.route('/dlreport/<int:report_id>')
def dlreport(report_id):
    pdf_bytes_io = reshand.get_dl_report(report_id)  # This is already an io.BytesIO object
    
    if pdf_bytes_io:
        return send_file(
            pdf_bytes_io,  # Pass the io.BytesIO object directly
            mimetype='application/pdf',  # Specify the MIME type
            as_attachment=True,
            download_name=f"report_{report_id}.pdf"
        )
    else:
        abort(404)
    
@app.route('/ComparativeAnalysis')
@role_required(1,3)
def rendercompareana():
    # Could not finish
    # Post-College Implementation ?
    abort(503)



def sanitise_data(data):
    if not data:
        return [{'result': 'No Data Found'}]
    sanitized_data = []
    for entry in data:
        sanitized_entry = {}
        for k, v in entry.items():
            if isinstance(v, str):
                sanitized_entry[k] = escape(v)
            else:
                sanitized_entry[k] = v
        sanitized_data.append(sanitized_entry)
    return sanitized_data
    
@app.route('/generateReport/<int:scan_id>', methods=['POST'])
@role_required(1,4,3)
def generate_report(scan_id):
    user_id = session.get("user_id")
    if not user_id:
        raise Unauthorized()
    
    role = session.get('role')
    
    nmap_results = sanitise_data(reshand.pull_nmap(scan_id, reshand.scanID_to_nmapres(scan_id)))
    dns_results = sanitise_data(reshand.pull_dns(scan_id, reshand.scanID_to_dnsrec(scan_id)))
    vas_results = sanitise_data(reshand.pull_vas_results(scan_id))
    zap_results = sanitise_data(reshand.pull_zap_results(scan_id))
    spider_results = sanitise_data(reshand.pull_spider_results(scan_id))

    if not nmap_results:
        nmap_results = [{'result': 'No Nmap Scan Results Found'}]
    if not dns_results:
        dns_results = [{'result': 'No DNS Results Found'}]
    if not vas_results:
        vas_results = [{'result': 'No VAS Results Found'}]
    if not zap_results:
        zap_results = [{'result': 'No ZAP Results Found'}]
    if not spider_results:
        spider_results = [{'result': 'No Spider Results Found'}]

    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")  
    output_filename = os.path.join(os.getcwd(), f'Report_{scan_id}_{current_time}.pdf')
    
    reshand.generate_and_save_pdf(scan_id, nmap_results, dns_results, vas_results, zap_results, spider_results, output_filename)
    
    report_uid = f'Report_{scan_id}_{current_time}.pdf'
    report_id = reshand.insert_report(scan_id, report_uid, output_filename)
    
    if report_id is None:
        print("failed to create report record in the database")
        abort(500) 


    try:
        return send_file(output_filename, as_attachment=True, download_name=f'Report_{scan_id}_{current_time}.pdf')
    except Exception as e:
        print(f"error serving the pdf file: {str(e)}")
        abort(500)  



@app.route("/scanResults/<int:scan_id>")
@role_required(1,2)
def render_scan_resby(scan_id):
    nmapresid = reshand.scanID_to_nmapres(scan_id)
    nmap_results = reshand.pull_nmap(scan_id, nmapresid)
    dns_rec_id = reshand.scanID_to_dnsrec(scan_id)
    dns_results = reshand.pull_dns(scan_id , dns_rec_id)
    vas_results = reshand.pull_vas_results(scan_id)
    zap_results = reshand.pull_zap_results(scan_id)
    spider_results = reshand.pull_spider_results(scan_id)
    scan_name = request.args.get('scan_name')
    ScanDate = request.args.get('ScanDate')
    target = request.args.get('target')
    ass_analyst = None
    
    full_ddet = scanUtil.get_scan(scan_id)
    if full_ddet:
        for deet in full_ddet:
            status = deet['Status']
            ass_analyst = deet['AssignedAnalyst']
            restOf = deet['RetestOf']
    else:
        print("No Details found with the given ID")
        
    ass_analyst = userManager.get_username(ass_analyst)
        

    analysts = userManager.get_analysts()
    assigned_analyst_id = userManager.get_assigned_analyst(scan_id)

    # If there's an assigned analyst, reorder the list to make them appear first
    # Find the analyst in the list
    # Remove the assigned analyst from their current position
    # Insert the assigned analyst at the beginning of the list
    if assigned_analyst_id is not None:

        assigned_analyst = next((analyst for analyst in analysts if analyst['UserID'] == assigned_analyst_id), None)
        if assigned_analyst:
            analysts.remove(assigned_analyst)
            analysts.insert(0, assigned_analyst)

    return render_template('ScanResults.html',
                           nmap_results=nmap_results,
                           dns_results=dns_results,
                           vas_results=vas_results,
                           zap_results=zap_results,
                           spider_results=spider_results,
                           scan_id=scan_id,
                           scan_name=scan_name,
                           ScanDate=ScanDate, 
                           target=target,
                           analysts=analysts,
                           status=status,
                           restOf = restOf,ass_analyst=ass_analyst)
    

@app.route("/updateAssignedAnalyst", methods=["POST"])
def update_assigned_analyst_route():
    if request.method == "POST":
        scan_id = request.form.get("scan_id")
        new_assigned_analyst_id = request.form.get("analyst_id")
        success = userManager.update_assigned_analyst(scan_id, new_assigned_analyst_id)
        
        if success:
            message = "Assigned analyst updated successfully."
        else:
            message = "System failed to update assigned analyst."
        
        return render_template('Message.html', message=message)
    else:
        raise Unauthorized()


  
@app.route("/ScanResultsAna/<int:scan_id>")
@role_required(1,3)
def render_scanana_resby(scan_id):
    user_id = session.get("user_id")
    if user_id:
        scans = scanUtil.populate_ana_scans(user_id)
        my_notes = None
        my_notes_last_update = None
        engineer_notes = None  
        engineer_notes_last_update = None  
        engineers = userManager.get_engineers()
        status = scanUtil.get_status(scan_id)
        for scan in scans:
            if scan['ScanID'] == scan_id:
                my_notes = scan.get('AnaNotes', 'No notes available.')
                my_notes_last_update = scan.get('AnaNotesTimestamp', 'Not Updated')
                engineer_notes = scan.get('EngNotes' , 'Not Updated')
                engineer_notes_last_update = scan.get('EngNotesTimestamp', 'Not Updated')
                priority = scan.get('Priority', 'Default Priority')
                break
            
        nmapresid = reshand.scanID_to_nmapres(scan_id)
        nmap_results = reshand.pull_nmap(scan_id, nmapresid)
        dns_rec_id = reshand.scanID_to_dnsrec(scan_id)
        dns_results = reshand.pull_dns(scan_id , dns_rec_id)
        vas_results = reshand.pull_vas_results(scan_id)
        zap_results = reshand.pull_zap_results(scan_id)
        spider_results = reshand.pull_spider_results(scan_id)
        scan_name = request.args.get('scan_name')
        ScanDate = request.args.get('ScanDate')
        target = request.args.get('target')
        assigned_engin_id = userManager.get_assigned_engineer(scan_id)
        assigned_engin = userManager.get_username(assigned_engin_id)

        
        return render_template('ScanResultsAna.html',
                                nmap_results=nmap_results,
                                dns_results=dns_results,
                                vas_results=vas_results,
                                zap_results=zap_results,
                                spider_results=spider_results,
                                scan_id=scan_id,
                                scan_name=scan_name,
                                ScanDate=ScanDate,
                                target=target,
                                my_notes=my_notes,
                                my_notes_last_update=my_notes_last_update,
                                engineer_notes=engineer_notes,
                                engineer_notes_last_update=engineer_notes_last_update,
                                engineers=engineers,status=status,assigned_engin=assigned_engin,
                                assigned_engin_id=assigned_engin_id,priority=priority)
    else:
        raise Unauthorized()
   
@app.route("/ScanResultsEng/<int:scan_id>")
@role_required(1,4)
def render_scaneng_resby(scan_id):
    user_id = session.get("user_id")
    if user_id:
        scans = scanUtil.populate_eng_scans(user_id)
        my_notes = None
        my_notes_last_update = None
        analyst_notes = None
        analyst_notes_last_update = None
        engineers = userManager.get_engineers()
        status = scanUtil.get_status(scan_id)
        priority = None
        

        for scan in scans:
            if scan['ScanID'] == scan_id:
                analyst_notes = scan.get('AnaNotes', 'No notes available.')
                analyst_notes_last_update = scan.get('AnaNotesTimestamp', 'Not Updated')
                my_notes = scan.get('EngNotes', 'No notes available.')
                my_notes_last_update = scan.get('EngNotesTimeStamp', 'Not Updated')
                print(analyst_notes_last_update)
                priority = scan.get('Priority', 'Default Priority')
                print(priority)
                
                break  
            
        nmapresid = reshand.scanID_to_nmapres(scan_id)
        nmap_results = reshand.pull_nmap(scan_id, nmapresid)
        dns_rec_id = reshand.scanID_to_dnsrec(scan_id)
        dns_results = reshand.pull_dns(scan_id , dns_rec_id)
        vas_results = reshand.pull_vas_results(scan_id)
        zap_results = reshand.pull_zap_results(scan_id)
        spider_results = reshand.pull_spider_results(scan_id)
        scan_name = request.args.get('scan_name')
        ScanDate = request.args.get('ScanDate')
        target = request.args.get('target')
        assigned_analyst_id = userManager.get_assigned_analyst(scan_id)
        assigned_analyst = userManager.get_username(assigned_analyst_id)

        
        return render_template('ScanResultsEng.html',
                                nmap_results=nmap_results,
                                dns_results=dns_results,
                                vas_results=vas_results,
                                zap_results=zap_results,
                                spider_results=spider_results,
                                scan_id=scan_id,
                                scan_name=scan_name,
                                ScanDate=ScanDate,
                                target=target,
                                my_notes=my_notes,
                                my_notes_last_update=my_notes_last_update,
                                analyst_notes=analyst_notes,
                                analyst_notes_last_update=analyst_notes_last_update,
                                engineers=engineers,status=status,assigned_analyst=assigned_analyst,
                                assigned_analyst_id=assigned_analyst_id,priority=priority)
    else:
        raise Unauthorized()


@app.route('/UpdateAnalysis', methods=['POST'])
def update_analyst_scores():
    connection = None
    cursor = None
    try:
        connection = dbConnection.createConnection()
        cursor = connection.cursor(prepared=True)
        for key, score in request.form.items():
            if score not in ['None', 'Low', 'Medium', 'High', 'Ignore']:
                continue  # Skip invalid or irrelevant form fields

            parts = key.split('_')
            if len(parts) != 3 or parts[1] != 'score':
                continue  # Ensure the form field follows the naming convention

            table_abbr = parts[0]
            record_id = parts[2]

            # Map the abbreviation to the actual table name and primary key column
            table_mapping = {
                'nmap': ('NmapResults', 'NmapResID'),
                'dns': ('DNSRecords', 'DNSRecordID'),
                'vas': ('VAS_Results', 'VAS_Res_ID'),
                'spider': ('SpiderResults', 'SpiderResID'),
                'zap': ('Zap_Results', 'ZapResID'),
            }

            if table_abbr in table_mapping:
                table_name, primary_key_column = table_mapping[table_abbr]
                # Ensure the query is safe from SQL injections by using a prepared statement
                query = f"UPDATE {table_name} SET AnalystCVSS = %s WHERE {primary_key_column} = %s"
                cursor.execute(query, (score, record_id))

        connection.commit()  # Commit the changes after all updates are done
        success = True
    except Exception as e:
        print(f"Error updating analyst scores: {e}")
        if connection:
            connection.rollback()  # Rollback in case of any error
        success = False
        message = "Error updating the analyst scores"
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()
            
        if success:
            return redirect(url_for('render_mytasks'))  # Redirect back to the main page or wherever appropriate
        else:
            return render_template('Message.html', message=message)
        
    
@app.route("/updateAssignedEngineer", methods=["POST"])
def update_assigned_engineer():
    if request.method == "POST":
        scan_id = request.form.get("scan_id")
        new_assigned_engineer_id = request.form.get("engineer_id")

        # Assuming scanUtil has a method to update the assigned engineer
        update_success = userManager.update_assigned_engineer(scan_id, new_assigned_engineer_id)

        if update_success:
            return redirect(url_for('render_mytasks', scan_id=scan_id))
        else:
            message = "Failed to assign engineer."
            return render_template('Message.html', message=message)
    else:
        # If the request method is not POST, return unauthorized
        raise Unauthorized()      
   
    

@app.route("/update_notes", methods=["POST"])
def update_notes():
    if request.method == "POST":
        role = session.get('role')
        print(role)
        if role not in (3,4):
            abort(401)
            
        scan_id = request.form.get("scan_id")
        notes = request.form.get("new_notes_" + scan_id)

        if role == 3:
            note_success = scanUtil.ana_update_notes(scan_id, notes)
            print("Ana Land")
            link = "render_mytasks"
        elif role == 4:
            note_success = scanUtil.eng_update_notes(scan_id, notes)
            link = "rendermyjobs"
            print("landed")
        else:
            #print("issue with else (2)")
            raise Unauthorized("User role is not authorised to update notes.")

        if note_success:
            return redirect(url_for(link))
        else:
            message = "Failed to update notes"
            return render_template('Message.html', message=message)
    else:
       # print("issue with TOP If")
        raise Unauthorized()
    
@app.route("/updatePriority", methods=["POST"])
def update_status():
    if request.method == "POST":
        scan_id = request.form.get("scan_id")
        priority = request.form.get("priority") 
        status_success = scanUtil.ana_update_status(scan_id, priority)

        if status_success:
                return redirect(url_for('render_mytasks'))  
        else:
                message = "Failed to update the priority."
                return render_template('Message.html', message=message)
    else:
            raise Unauthorized()
        
        
@app.route("/retestSet", methods=["POST"])
def setRetest():
    if request.method == "POST":
        scan_id = request.form.get("scan_id")
        stat = request.form.get("stat") 
        status_success = scanUtil.set_status(scan_id,stat)

        if status_success:
                return redirect(url_for('rendermyjobs'))  
        else:
                message = "Failed to update the Retest Value."
                return render_template('Message.html', message=message)
    else:
            raise Unauthorized()
        
        
@app.route("/UpdateClose", methods=["POST"])
def updateClose():
    if request.method == "POST":
        scan_id = request.form.get("scan_id")
        stat = request.form.get("stat") 
        status_success = scanUtil.set_status(scan_id,stat)

        if status_success:
                return redirect(url_for('rendermyjobs'))  
        else:
                message = "Failed to update the Retest Value."
                return render_template('Message.html', message=message)
    else:
            raise Unauthorized()
    
######### Test Route for Page Testing ###########

@app.route('/SendTuDatabase', methods=['POST'])
def send_to_database():
    scan_name = request.form['task_name']
    success = scanUtil.process_scan_to_database(scan_name)
    if success:
        message = "Report successfully sent to the database."
        return render_template('Message.html', message=message)
    else:
        message = "Failed to send the report to the database."
    return render_template('Message.html', message=message)

@app.route("/RunZapScan", methods=["POST"])
def run_ZAP():
    try:
        # Extracting form data
        scan_target = request.form.get('scanTarget')
        zap_scan_type = request.form.get('zapScanType')
        use_crawler = 'enableSpider' in request.form
        exclusion_list = request.form.get('exclusionList').splitlines() if request.form.get('exclusionList') else []
        scan_id = request.form.get('scanId')
        userid = session['user_id']
        
        # Debugging stuff below
        print("Received form data:")
        print("Scan Target:", scan_target)
        print("ZAP Scan Type:", zap_scan_type)
        print("Use Crawler:", use_crawler)
        print("Exclusion List:", exclusion_list)

        scanUtil.run_zap_scan(scan_target, zap_scan_type, use_crawler, exclusion_list, scan_id, userid )
        message = "Scan was successful - check terminal for details."
    except Exception as e:
        message = f"Scan failed: {str(e)}"

    return render_template('Message.html', message=message)





@app.route('/resetUserPassword', methods=['POST'])
def reset_user_password():
    data = request.get_json()
    userId = data['userId']
    newPassword = data['password']

    if update_user_password(userId, newPassword):
        return jsonify(success=True, message="Password updated successfully")
    else:
        return jsonify(success=False, message="Failed to update password")

def update_user_password(userId, newPassword):
    connection = dbConnection.createConnection()
    if connection is None:
        print("Failed to connect to the database")
        return False

    hashed_pw = hash_salt_pw(newPassword)  

    try:
        cursor = connection.cursor(prepared=True)
        updateQuery = "UPDATE Users SET Password = %s WHERE UserID = %s"
        cursor.execute(updateQuery, (hashed_pw, userId))
        connection.commit()
        return True
    except Exception as e:
        print(f"Error updating password: {e}")
        return False
    finally:
        cursor.close()
        connection.close()












if __name__ == "__main__":
    app.run(debug=True)
