import os
import subprocess
import pdfkit
from flask import Blueprint, render_template, current_app, send_file

nipper_bp = Blueprint('nipper_bp', __name__)

@nipper_bp.route('/nipper_audit', methods=['GET'])
def nipper_audit():
    input_file = 'C:\\Users\\dsdem\\OneDrive\\Bureau\\Centralisation-audit\\Centralisation-audit\\device_running_config.txt'
    output_file = 'report.html'

    try:
        command = ['C:\\Users\\dsdem\\OneDrive\\Bureau\\Centralisation-audit\\Centralisation-audit\\nipper.exe', f'--input={input_file}', f'--output={output_file}']
        subprocess.run(command, check=True, capture_output=True)

        if os.path.exists(output_file):
            with open(output_file, 'r') as file:
                audit_content = file.read()

            return render_template('audit_report.html', audit_content=audit_content)
        else:
            return f"Nipper audit completed, but output file '{output_file}' not found.", 404

    except subprocess.CalledProcessError as e:
        return f"Error running nipper command: {e}", 500

    except Exception as e:
        return f"An error occurred: {e}", 500

config = pdfkit.configuration(wkhtmltopdf='c:\\Users\\dsdem\\Downloads\\wkhtmltox\\bin\\wkhtmltopdf.exe')
@nipper_bp.route('/download_audit', methods=['GET'])
def download_audit():
    html_file = './report.html'
    pdf_file = 'C:\\Users\\dsdem\\OneDrive\\Bureau\\Centralisation-audit\\report.pdf'

    try:
        if os.path.exists(html_file):
            pdfkit.from_file(html_file, pdf_file,configuration=config)
            return send_file(pdf_file, as_attachment=True)

        else:
            print(f"HTML file '{html_file}' not found.")
            return f"HTML file '{html_file}' not found.", 404

    except Exception as e:
        print(f"An error occurred while generating the PDF: {e}")
        return f"An error occurred while generating the PDF: {e}", 500
