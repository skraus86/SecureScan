"""
JSON Report Generator
"""

import json
from typing import Optional
from datetime import datetime

from .base import BaseReporter
from ..models import ScanResult


class JSONReporter(BaseReporter):
    """Generates JSON format reports"""
    
    def get_format_name(self) -> str:
        return "JSON"
    
    def generate(self, result: ScanResult, filename: Optional[str] = None) -> str:
        """Generate JSON report"""
        if filename is None:
            filename = f"securescan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        output_path = self.get_output_path(filename, "json")
        
        report_data = result.to_dict()
        report_data["report_metadata"] = {
            "tool": "SecureScan",
            "version": "1.0.0",
            "generated_at": datetime.utcnow().isoformat(),
            "format": "json"
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return str(output_path)
