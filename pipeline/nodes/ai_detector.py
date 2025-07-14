# AI Component Detection Node - Identifies AI/LLM/Agentic components in DFD

from typing import Dict, List, Any
from pipeline.state import ThreatAnalysisState

def ai_component_detector_node(state: ThreatAnalysisState) -> Dict[str, Any]:
    """
    AI Component Detector Node
    
    Automatically detects AI/LLM/Agentic components using pattern recognition
    as defined in the README architecture.
    
    Args:
        state: Current threat analysis state
        
    Returns:
        Updated state with component classification
    """
    print("🤖 AI Component Detector Node: Analyzing components...")
    
    try:
        dfd_model = state.get('dfd_model')
        if not dfd_model:
            return {
                "errors": state.get('errors', []) + ["No DFD model available for AI detection"],
                "processing_status": "error",
                "current_node": "ai_detector"
            }
        
        ai_components = []
        traditional_components = []
        component_classification = {}
        
        # AI Component Indicators from README
        ai_indicators = {
            'names': ['llm', 'gpt', 'claude', 'ai', 'agent', 'model', 'chatbot', 'openai', 'anthropic', 'ollama'],
            'types': ['llm service', 'ai agent', 'ml model', 'chatbot', 'language model'],
            'vendors': ['openai', 'anthropic', 'hugging face', 'ollama', 'cohere']
        }
        
        # Traditional Component Indicators
        traditional_indicators = {
            'names': ['database', 'api', 'cache', 'load balancer', 'web server', 'auth'],
            'types': ['database', 'web api', 'cache', 'load balancer', 'authentication'],
            'vendors': ['aws', 'gcp', 'azure']  # Non-AI services
        }
        
        # Analyze each component
        for comp_id, component in dfd_model.components.items():
            comp_name = component.name.lower()
            comp_type = component.component_type.lower()
            
            # Fix vendor handling - handle None values properly
            comp_vendor = ''
            if hasattr(component, 'vendor') and component.vendor:
                comp_vendor = str(component.vendor).lower()
            
            is_ai = False
            
            # Check AI indicators
            for indicator in ai_indicators['names']:
                if indicator in comp_name:
                    is_ai = True
                    break
            
            if not is_ai:
                for indicator in ai_indicators['types']:
                    if indicator in comp_type:
                        is_ai = True
                        break
            
            if not is_ai:
                for indicator in ai_indicators['vendors']:
                    if indicator in comp_vendor or indicator in comp_name:
                        is_ai = True
                        break
            
            # Create component entry
            comp_entry = {
                "id": comp_id,
                "name": component.name,
                "type": component.component_type,
                "trust_zone": component.trust_zone_name,
                "is_external": component.is_external,
                "vendor": comp_vendor,
                "classification_reason": []
            }
            
            if is_ai:
                # Add reasons for AI classification
                reasons = []
                for indicator in ai_indicators['names']:
                    if indicator in comp_name:
                        reasons.append(f"Name contains '{indicator}'")
                for indicator in ai_indicators['types']:
                    if indicator in comp_type:
                        reasons.append(f"Type contains '{indicator}'")
                for indicator in ai_indicators['vendors']:
                    if indicator in comp_vendor or indicator in comp_name:
                        reasons.append(f"Vendor/name contains '{indicator}'")
                
                comp_entry["classification_reason"] = reasons
                ai_components.append(comp_entry)
                component_classification[comp_id] = "ai"
            else:
                # Classify as traditional
                reasons = ["No AI indicators found"]
                comp_entry["classification_reason"] = reasons
                traditional_components.append(comp_entry)
                component_classification[comp_id] = "traditional"
        
        print(f"✅ AI Detection Complete:")
        print(f"   🤖 AI Components: {len(ai_components)}")
        print(f"   🏗️ Traditional Components: {len(traditional_components)}")
        
        # Log AI components found
        if ai_components:
            print("   🤖 AI Components detected:")
            for comp in ai_components:
                print(f"     - {comp['name']} ({comp['type']}) - {', '.join(comp['classification_reason'])}")
        
        return {
            "ai_components": ai_components,
            "traditional_components": traditional_components,
            "component_classification": component_classification,
            "processing_status": "ai_detection_complete",
            "current_node": "ai_detector"
        }
        
    except Exception as e:
        print(f"❌ AI Detection Error: {e}")
        import traceback
        traceback.print_exc()
        return {
            "errors": state.get('errors', []) + [f"AI Detection failed: {str(e)}"],
            "processing_status": "error",
            "current_node": "ai_detector"
        } 