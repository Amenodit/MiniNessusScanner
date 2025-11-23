import os
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from utils.logger import log_info, log_success

def generate_report(target_ip, scan_data):
    log_info("Generating HTML Report...")
    
    # Define paths
    report_dir = "reports"
    template_file = "template.html"
    output_file = os.path.join(report_dir, f"scan_report_{target_ip}.html")
    
    # Create report env
    env = Environment(loader=FileSystemLoader(report_dir))
    template = env.get_template(template_file)
    
    # Render
    html_content = template.render(
        target=target_ip,
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        open_ports=scan_data.get('open_ports', []),
        services=scan_data.get('services', {}),
        os_info=scan_data.get('os_info', "Unknown"),
        vulns=scan_data.get('vulns', [])
    )
    
    # Save
    with open(output_file, "w") as f:
        f.write(html_content)
        
    log_success(f"Report saved to: {output_file}")