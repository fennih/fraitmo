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

    for obj in root.iter():
        if obj.tag == "object" and "label" in obj.attrib:
            comp_id = obj.attrib["id"]
            name = obj.attrib["label"]
            
            zone_id = "Unknown"
            comp_type = "Unknown"
            
            mxcell = obj.find("mxCell")
            if mxcell is not None:
                zone_id = mxcell.attrib.get("parent", "Unknown")
                
                style = mxcell.attrib.get("style", "")
                if "ir.componentDefinition.ref=" in style:
                    start = style.find("ir.componentDefinition.ref=") + len("ir.componentDefinition.ref=")
                    end = style.find(";", start)
                    if end == -1:
                        comp_type = style[start:]
                    else:
                        comp_type = style[start:end]
            
            zone_name = trust_zones.get(zone_id, "Unknown")
            
            components[comp_id] = {
                "id": comp_id,
                "name": name,
                "type": comp_type,
                "zone": zone_name
            }
            id_to_name[comp_id] = name

    for obj in root.iter():
        if (obj.tag == "mxCell" and 
            "value" in obj.attrib and 
            'ir.type=TRUSTZONE' not in obj.attrib.get('style', '') and
            obj.attrib.get("edge") != "1" and  # Escludi le connessioni
            obj.attrib["id"] not in id_to_name):  # Non già processato
            
            comp_id = obj.attrib["id"]
            name = obj.attrib["value"]
            zone_id = obj.attrib.get("parent", "Unknown")
            
            comp_type = "Unknown"
            style = obj.attrib.get("style", "")
            if "ir.componentDefinition.ref=" in style:
                start = style.find("ir.componentDefinition.ref=") + len("ir.componentDefinition.ref=")
                end = style.find(";", start)
                if end == -1:
                    comp_type = style[start:]
                else:
                    comp_type = style[start:end]
            
            zone_name = trust_zones.get(zone_id, "Unknown")
            
            components[comp_id] = {
                "id": comp_id,
                "name": name,
                "type": comp_type,
                "zone": zone_name
            }
            id_to_name[comp_id] = name

    for obj in root.iter():
        if obj.tag == "mxCell" and obj.attrib.get("edge") == "1":
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
