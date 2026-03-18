# backend/app/rag_engine/mitre_db.py

MITRE_DB = [
    {
        "id": "T1566",
        "name": "Phishing",
        "keywords": ["phishing", "credential", "email scam", "fake login", "social engineering"]
    },
    {
        "id": "T1589",
        "name": "Gather Victim Identity Information",
        "keywords": ["identity", "email harvesting", "userinfo", "profile data"]
    },
    {
        "id": "T1059",
        "name": "Command Execution",
        "keywords": ["cmd.exe", "powershell", "shell", "execute", "command", "script"]
    },
    {
        "id": "T1059.003",
        "name": "PowerShell",
        "keywords": ["powershell", "ps1", "psscript"]
    },
    {
        "id": "T1189",
        "name": "Drive-by Compromise",
        "keywords": ["browser exploit", "drive-by", "redirect", "malicious iframe"]
    },
    {
        "id": "T1204",
        "name": "User Execution",
        "keywords": ["clicked link", "opened attachment", "user opened", "execution"]
    },
    {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "keywords": ["dropper", "downloader", "payload", "file dropped"]
    },
    {
        "id": "T1071",
        "name": "Exfiltration Over Web Protocol",
        "keywords": ["dns", "c2 server", "beacon", "callback", "exfil"]
    },
    {
        "id": "T1056",
        "name": "Input Capture",
        "keywords": ["keylogger", "keystroke", "credential capture"]
    }
]

def find_mitre_techniques(text: str):
    text = text.lower()
    results = []

    for item in MITRE_DB:
        if any(keyword in text for keyword in item["keywords"]):
            results.append({
                "id": item["id"],
                "name": item["name"]
            })

    return results[:5]  # limit to top 5
