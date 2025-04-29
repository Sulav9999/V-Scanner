import json
import os
import glob
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_LEFT
from reportlab.lib import colors

# Initialize stylesheet only once to prevent "Style already defined" errors
_styles = None

def get_styles():
    """Get stylesheet with custom styles (singleton pattern)"""
    global _styles
    if _styles is None:
        _styles = getSampleStyleSheet()
        # Add custom styles if they don't exist
        if 'Heading3' not in _styles:
            _styles.add(ParagraphStyle(
                name='Heading3',
                parent=_styles['Heading2'],
                fontSize=10,
                spaceAfter=6
            ))
    return _styles

def load_json_safe(file_path):
    """Safely load JSON data with extensive error handling"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            if not isinstance(data, dict):
                print(f"⚠️ File {file_path} doesn't contain a JSON object")
                return None
            return data
    except FileNotFoundError:
        print(f"⚠️ File not found: {file_path}")
        return None
    except json.JSONDecodeError:
        print(f"⚠️ Invalid JSON in file: {file_path}")
        return None
    except Exception as e:
        print(f"⚠️ Error reading {file_path}: {str(e)}")
        return None

def create_portscanner_table(data):
    """Create network scan table with validation"""
    if not data or not isinstance(data, dict):
        return []
    
    styles = get_styles()
    elements = []
    try:
        elements.append(Paragraph("Network Scan Report", styles['Heading1']))
        elements.append(Paragraph(f"Scan Time: {data.get('scan_time', 'Unknown')}", styles['Normal']))
        elements.append(Spacer(1, 12))

        table_data = [["IP Address", "MAC", "Hostname", "Port", "Service", "Banner"]]
        
        for device in data.get('devices', []):
            if not isinstance(device, dict):
                continue
                
            for port in device.get('open_ports', []):
                if not isinstance(port, dict):
                    continue
                    
                table_data.append([
                    str(device.get('ip', 'N/A')),
                    str(device.get('mac', 'N/A')),
                    str(device.get('hostname', 'N/A')),
                    str(port.get('port', 'N/A')),
                    str(port.get('service', 'N/A')),
                    str(port.get('banner', 'N/A'))[:50] + ('...' if len(str(port.get('banner', ''))) > 50 else '')
                ])

        table = Table(table_data, repeatRows=1, colWidths=[90, 100, 90, 50, 70, 140])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#003366")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTSIZE', (0, 0), (-1, -1), 8)
        ]))

        elements.append(table)
        elements.append(PageBreak())
    except Exception as e:
        print(f"⚠️ Error creating network table: {str(e)}")
        return []
        
    return elements

def create_vulnerability_table(data):
    """Create vulnerability table with validation"""
    if not data or not isinstance(data, dict):
        return []
    
    styles = get_styles()
    elements = []
    try:
        elements.append(Paragraph("Vulnerability Report", styles['Heading1']))
        
        target_info = f"Target: {data.get('ip', 'N/A')}"
        if 'port' in data:
            target_info += f":{data.get('port')}"
        elements.append(Paragraph(target_info, styles['Normal']))
        
        service_info = data.get('service', {})
        if isinstance(service_info, dict):
            service_text = f"Service: {service_info.get('service', 'N/A')}"
            if 'version' in service_info:
                service_text += f" {service_info.get('version')}"
            elements.append(Paragraph(service_text, styles['Normal']))
        
        elements.append(Spacer(1, 12))

        table_data = [["CVE ID", "CVSS", "Vector", "Description"]]
        
        for vuln in data.get('vulnerabilities', []):
            if not isinstance(vuln, dict):
                continue
                
            description = vuln.get('description', 'No description')
            if len(description) > 200:
                description = description[:200] + '...'
                
            table_data.append([
                vuln.get('cve_id', 'N/A'),
                vuln.get('cvss_score', 'N/A'),
                vuln.get('vector', 'N/A'),
                Paragraph(description, styles['BodyText'])
            ])

        table = Table(table_data, repeatRows=1, colWidths=[80, 50, 100, 250])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#660000")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ]))

        elements.append(table)
    except Exception as e:
        print(f"⚠️ Error creating vulnerability table: {str(e)}")
        return []
        
    return elements

def create_credential_table(data):
    """Create credential check table with validation"""
    if not data or not isinstance(data, dict):
        return []
    
    styles = get_styles()
    elements = []
    try:
        elements.append(Paragraph("Credential Check Report", styles['Heading1']))
        elements.append(Paragraph(f"Check Time: {data.get('scan_time', 'Unknown')}", styles['Normal']))
        elements.append(Paragraph(f"Type: {data.get('credential_type', 'N/A')}", styles['Normal']))
        elements.append(Spacer(1, 12))

        results = data.get('results', {})
        
        # Local breaches
        local_breaches = results.get('local_breaches', [])
        if local_breaches and isinstance(local_breaches, list):
            elements.append(Paragraph("Local Breaches Found:", styles['Heading2']))
            local_data = [["Breach Name", "Source File"]]
            
            for breach in local_breaches:
                if isinstance(breach, dict):
                    local_data.append([
                        breach.get('breach_name', 'N/A'),
                        breach.get('breach_file', 'N/A')
                    ])
            
            local_table = Table(local_data, colWidths=[200, 150])
            local_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#006600")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('FONTSIZE', (0, 0), (-1, -1), 8)
            ]))
            elements.append(local_table)
            elements.append(Spacer(1, 12))

        # Online breaches
        online_breaches = results.get('online_breaches', [])
        if online_breaches and isinstance(online_breaches, list):
            elements.append(Paragraph("Online Breaches Found:", styles['Heading2']))
            online_data = [["Breach Name", "Source", "Date"]]
            
            for breach in online_breaches:
                if isinstance(breach, dict):
                    online_data.append([
                        breach.get('breach_name', 'N/A'),
                        breach.get('source', 'N/A'),
                        breach.get('date', 'N/A')
                    ])
            
            online_table = Table(online_data, colWidths=[150, 100, 100])
            online_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#006600")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('FONTSIZE', (0, 0), (-1, -1), 8)
            ]))
            elements.append(online_table)
        else:
            elements.append(Paragraph("No online breaches found", styles['Normal']))
    except Exception as e:
        print(f"⚠️ Error creating credential table: {str(e)}")
        return []
        
    return elements

def find_latest_report(pattern):
    """Find the most recent report matching pattern"""
    try:
        files = glob.glob(os.path.join("reports", pattern))
        if not files:
            return None
        return max(files, key=os.path.getmtime)
    except Exception:
        return None

def generate_report():
    """Generate comprehensive PDF report with full error handling"""
    print("\n=== Generating Final Report ===\n")
    
    # Create reports directory if it doesn't exist
    os.makedirs("reports", exist_ok=True)
    
    # Find all available reports
    report_files = {
        "network": find_latest_report("portscanner*.json"),
        "vulnerability": find_latest_report("vuln_scan*.json"),
        "credential": find_latest_report("credential_scan*.json")
    }

    # Check if we have any reports
    if not any(report_files.values()):
        print("❌ No scan reports found in 'reports' directory")
        print("Please run scans first to generate reports")
        input("Press Enter to continue...")
        return

    try:
        # Prepare PDF document
        output_path = os.path.join("reports", "final_report.pdf")
        
        # Initialize document with our styles
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        elements = []

        # Add network scan results if available
        if report_files["network"]:
            print(f"📄 Including network scan: {os.path.basename(report_files['network'])}")
            network_data = load_json_safe(report_files["network"])
            if network_data:
                elements += create_portscanner_table(network_data)

        # Add vulnerability results if available
        if report_files["vulnerability"]:
            print(f"📄 Including vulnerability scan: {os.path.basename(report_files['vulnerability'])}")
            vuln_data = load_json_safe(report_files["vulnerability"])
            if vuln_data:
                elements += create_vulnerability_table(vuln_data)

        # Add credential check results if available
        if report_files["credential"]:
            print(f"📄 Including credential check: {os.path.basename(report_files['credential'])}")
            cred_data = load_json_safe(report_files["credential"])
            if cred_data:
                elements += create_credential_table(cred_data)

        # Build the PDF only if we have content
        if elements:
            try:
                doc.build(elements)
                print(f"\n✅ Successfully generated report: {output_path}")
            except Exception as e:
                print(f"❌ Failed to build PDF: {str(e)}")
        else:
            print("❌ No valid data found to generate report")
            print("Please check your scan reports for errors")

    except Exception as e:
        print(f"❌ Unexpected error during report generation: {str(e)}")
    
    input("\nPress Enter to continue...")