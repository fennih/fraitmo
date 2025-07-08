import sys
import json
from dfd_parser.xml_parser import extract_from_xml
from models.builder import DFDBuilder
from rag import ThreatAnalyzer, print_threat_analysis

def main():
    if len(sys.argv) != 2:
        print("❌ Usage: python3 fraitmo.py <path_to_file.xml>")
        sys.exit(1)

    xml_path = sys.argv[1]
    
    try:
        print("🚀 FRAITMO - Framework for Robust AI Threat Modeling Operations")
        print("=" * 60)
        
        # Step 1: Parse DFD XML
        print(f"\n📋 Step 1: Parsing DFD from {xml_path}...")
        parsed_data = extract_from_xml(xml_path)
        
        print(f"✅ Successfully parsed DFD:")
        print(f"   📊 Components: {len(parsed_data.get('components', {}))}")
        print(f"   🔗 Connections: {len(parsed_data.get('connections', []))}")
        print(f"   🏰 Trust Zones: {len(parsed_data.get('trust_zones', {}))}")
        
        # Step 2: Build semantic model
        print(f"\n🏗️ Step 2: Building semantic model...")
        builder = DFDBuilder()
        dfd_model = builder.from_parser_output(parsed_data).build(
            name="Threat Model Analysis",
            description=f"Generated from {xml_path}"
        )
        
        print(f"✅ Semantic model built:")
        print(f"   📊 Components: {len(dfd_model.components)}")
        print(f"   🔗 Connections: {len(dfd_model.connections)}")
        print(f"   🚨 Cross-zone connections: {len(dfd_model.cross_zone_connections)}")
        
        # Step 3: RAG Threat Analysis  
        print(f"\n🛡️ Step 3: Initializing threat analysis...")
        threat_analyzer = ThreatAnalyzer()
        
        # Perform threat analysis
        threat_analysis = threat_analyzer.analyze_dfd(dfd_model)
        
        # Step 4: Display results
        print(f"\n📄 Step 4: Displaying results...")
        
        # Print DFD structure (original functionality)
        print("\n" + "="*60)
        print("📊 DFD STRUCTURE")
        print("="*60)
        print(json.dumps(parsed_data, indent=2))
        
        # Print threat analysis results (new functionality)
        print_threat_analysis(threat_analysis)
        
        print(f"\n🎉 Analysis complete!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()