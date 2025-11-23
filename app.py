from flask import Flask, render_template, request, session, make_response, redirect, url_for
from modules.port_scanner import PortScanner
from modules.service_detect import ServiceDetector
from modules.os_detect import OSDetector
from modules.vuln_checks import VulnScanner
from xhtml2pdf import pisa
import socket
import io

app = Flask(__name__)
app.secret_key = 'HACKATHON_SECRET_KEY'

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/scan', methods=['POST'])
def scan():
    target_input = request.form.get('target')
    if not target_input: return redirect(url_for('dashboard'))

    target = target_input.replace('http://', '').replace('https://', '').split('/')[0]
    
    try:
        target_ip = socket.gethostbyname(target)
    except:
        return render_template('dashboard.html', error="Invalid Domain or IP Address")

    # 1. Port Scan
    scanner = PortScanner(target_ip)
    open_ports = scanner.run()
    
    # Initialize Stats with ALL potential keys
    scan_results = {
        'target': target, 'ip': target_ip, 'open_ports': open_ports,
        'services': {}, 'os_info': "Unknown", 'vulns': [],
        'stats': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'safe': 0}
    }

    if open_ports:
        serv_det = ServiceDetector(target_ip, open_ports)
        scan_results['services'] = serv_det.run()
        
        os_det = OSDetector(target_ip)
        scan_results['os_info'] = os_det.run()
        
        vuln_scan = VulnScanner(target_ip, open_ports, scan_results['services'])
        scan_results['vulns'] = vuln_scan.run()

        # Calculate Stats for the Graph (Safe Mode)
        for v in scan_results['vulns']:
            severity = v.get('severity', 'low').lower()
            if severity in scan_results['stats']:
                scan_results['stats'][severity] += 1
            else:
                # Fallback for unknown severities
                scan_results['stats']['low'] += 1
        
        if not scan_results['vulns']:
            scan_results['stats']['safe'] = 1

    session['last_scan'] = scan_results
    return render_template('report.html', data=scan_results)

@app.route('/download_pdf')
def download_pdf():
    if 'last_scan' not in session: return redirect(url_for('dashboard'))
    data = session['last_scan']
    rendered_html = render_template('pdf_template.html', data=data)
    pdf_buffer = io.BytesIO()
    pisa.CreatePDF(io.BytesIO(rendered_html.encode('utf-8')), dest=pdf_buffer)
    response = make_response(pdf_buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=Report_{data["target"]}.pdf'
    return response

if __name__ == '__main__':
    app.run(debug=True, port=5000)