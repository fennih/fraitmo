import xml.etree.ElementTree as ET

def extract_from_xml(path):
    tree = ET.parse(path)
    root = tree.getroot()

    trust_zones = {}
    components = {}
    connections = []

    id_to_name = {}

    for obj in root.iter():
        if obj.tag == "mxCell" and 'ir.type=TRUSTZONE' in obj.attrib.get('style', ''):
            name = obj.attrib.get("value", "")
            trust_zones[obj.attrib["id"]] = name

        elif obj.tag == "object" and "label" in obj.attrib:
            comp_id = obj.attrib["id"]
            name = obj.attrib["label"]
            zone_id = obj.attrib.get("parent", "")
            zone_name = trust_zones.get(zone_id, "Unknown")
            comp_type = obj.attrib.get("componentDefinition.ref", "Unknown")
            components[comp_id] = {
                "id": comp_id,
                "name": name,
                "type": comp_type,
                "zone": zone_name
            }
            id_to_name[comp_id] = name

        elif obj.tag == "mxCell" and obj.attrib.get("edge") == "1":
            source = obj.attrib.get("source")
            target = obj.attrib.get("target")
            if source and target:
                connections.append({
                    "from": id_to_name.get(source, source),
                    "to": id_to_name.get(target, target)
                })
    
    return {
        "trust_zones": trust_zones,
        "components": components,
        "connections": connections
    }
