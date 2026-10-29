from database import lookup_ioc, get_iocs


def lookup_indicator(value):
    value = str(value or "").strip()
    return lookup_ioc(value) if value else None


def enrich_alert(alert):
    if not alert:
        return None
    return lookup_indicator(alert.get("source_ip"))


def get_ioc_summary(ioc):
    if not ioc:
        return {"found": False, "message": "No threat intelligence record found."}
    return {
        "found": True,
        "type": ioc.get("type", "UNKNOWN"),
        "value": ioc.get("value", ""),
        "reputation": ioc.get("reputation", "UNKNOWN"),
        "confidence": ioc.get("confidence", 0),
        "description": ioc.get("description", ""),
        "source": ioc.get("source", "CyberShield IOC Database"),
    }


def get_all_iocs():
    return get_iocs()
