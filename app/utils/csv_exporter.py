# backend/app/utils/csv_exporter.py
import pandas as pd
from typing import List, Dict, Any
import io

class CSVExporter:
    def export_data(self, data: List[Dict[str, Any]], filename: str) -> io.StringIO:
        """
        Converts a list of dictionaries (e.g., scan history) into an in-memory CSV file.
        Returns a StringIO object suitable for FastAPI FileResponse.
        """
        if not data:
            return io.StringIO("")
            
        df = pd.DataFrame(data)
        
        # Use StringIO to keep the file in memory
        csv_buffer = io.StringIO()
        df.to_csv(csv_buffer, index=False)
        csv_buffer.seek(0)
        
        return csv_buffer