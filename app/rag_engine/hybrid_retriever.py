# backend/app/rag_engine/hybrid_retriever.py

from langchain.docstore.document import Document

class HybridRetriever:
    """
    Takes scanner outputs (VT, URLScanner, FileScanner, IDS) and converts them
    into documents used by the RAG engine.
    """

    @staticmethod
    def vt_to_docs(vt: dict):
        docs = []
        if not vt:
            return docs

        verdict = vt.get("verdict", "unknown")
        malicious = vt.get("malicious_count", 0)

        summary = f"VirusTotal Verdict: {verdict}, Malicious Engines: {malicious}"
        docs.append(Document(page_content=summary))

        # Include per-engine malicious results
        engine_results = vt.get("engine_results", {})
        malicious_detected = []

        for engine, data in engine_results.items():
            if data.get("category") == "malicious":
                result = data.get("result", "malicious")
                malicious_detected.append(f"{engine} detected: {result}")

        if malicious_detected:
            docs.append(Document(page_content="; ".join(malicious_detected)))

        return docs

    @staticmethod
    def combine_all(context: dict):
        """
        Combines every detail from context_data into RAG-ready documents.
        """
        docs = []

        # Full raw context for the model
        docs.append(Document(page_content=str(context)))

        # Add VT details if present
        if "vt_details" in context:
            docs.extend(HybridRetriever.vt_to_docs(context["vt_details"]))

        # Add URL scanner details
        if "url_details" in context:
            docs.append(Document(page_content="URL Scan: " + str(context["url_details"])))

        # Add IDS Alert details
        if "ids_details" in context:
            docs.append(Document(page_content="IDS Alert: " + str(context["ids_details"])))

        return docs
