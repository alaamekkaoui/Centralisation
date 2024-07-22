from flask import Blueprint, jsonify
from services.audit_service import AuditService

audit_bp = Blueprint('audit_bp', __name__)

@audit_bp.route('/audit', methods=['GET'])
def audit():
    result = AuditService.run_audit()
    return jsonify(result), 200
