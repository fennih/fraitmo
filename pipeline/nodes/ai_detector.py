# AI Component Detection Node - Identifies AI/LLM/Agentic components in DFD

from typing import Dict, Any, List
from utils.console import console
from rich.text import Text

def ai_component_detector_node(state: Dict[str, Any], progress_callback=None) -> Dict[str, Any]:
    """AI Component Detection Node - Detects AI/LLM components in the DFD"""
    console.print(Text("[INFO]", style="bold blue"), "AI Component Detector Node: Analyzing components...")

    if progress_callback:
        progress_callback(10, "🔍 Detecting AI components...")

    dfd_model = state.get('dfd_model')
    if not dfd_model:
        error_msg = "DFD model not found in state - cannot detect AI components"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        return {
            "ai_components": [],
            "traditional_components": [],
            "errors": [error_msg]
        }

    try:
        ai_components = []
        traditional_components = []

        # AI/LLM component detection keywords
        ai_keywords = [
            # Core AI/ML terms
            'ai', 'artificial intelligence', 'machine learning', 'ml', 'neural network',
            'deep learning', 'transformer', 'bert', 'gpt', 'llm', 'large language model',

            # AI services and frameworks
            'openai', 'anthropic', 'claude', 'chatgpt', 'gemini', 'palm', 'cohere',
            'huggingface', 'tensorflow', 'pytorch', 'scikit-learn', 'keras',

            # AI-specific components
            'inference', 'prediction', 'model', 'embedding', 'vector', 'semantic',
            'nlp', 'natural language', 'computer vision', 'speech', 'recommendation',

            # AI infrastructure
            'ml ops', 'mlops', 'model registry', 'feature store', 'data pipeline',
            'training', 'fine-tuning', 'prompt', 'agent', 'chatbot', 'assistant',

            # Specific AI services
            'aws bedrock', 'azure cognitive', 'google ai', 'vertex ai', 'sagemaker',
            'databricks', 'mlflow', 'kubeflow', 'ray', 'spark ml'
        ]

        for component in dfd_model.components.values():
            component_text = f"{component.name} {component.description}".lower()
            is_ai_component = any(keyword in component_text for keyword in ai_keywords)

            component_dict = {
                'id': component.id,
                'name': component.name,
                'description': component.description or '',
                'type': component.component_type,
                'trust_zone': component.trust_zone_id
            }

            if is_ai_component:
                # Enhanced AI component analysis
                component_dict['ai_type'] = _classify_ai_component(component_text)
                component_dict['risk_factors'] = _identify_ai_risk_factors(component_text)
                ai_components.append(component_dict)
            else:
                traditional_components.append(component_dict)

        # Enhanced component classification for better routing
        component_classification = {
            'total_components': len(dfd_model.components),
            'ai_components_count': len(ai_components),
            'traditional_components_count': len(traditional_components),
            'ai_percentage': (len(ai_components) / len(dfd_model.components)) * 100 if dfd_model.components else 0
        }

        console.print(Text("[OK]", style="bold green"), "AI Detection Complete:")
        console.print(Text("[INFO]", style="bold blue"), f"AI Components: {len(ai_components)}")
        console.print(Text("[INFO]", style="bold blue"), f"Traditional Components: {len(traditional_components)}")

        # Show detected AI components for visibility
        if ai_components:
            console.print(Text("[INFO]", style="bold blue"), "AI Components detected:")
            for comp in ai_components:
                ai_type = comp.get('ai_type', 'Unknown')
                console.print(f"  - {comp['name']} ({ai_type})")

                # Show risk factors if present
                risk_factors = comp.get('risk_factors', [])
                if risk_factors:
                    console.print(f"    Risk factors: {', '.join(risk_factors)}")

        # Return only the fields we're modifying
        return {
            "ai_components": ai_components,
            "traditional_components": traditional_components,
            "component_classification": component_classification
        }

    except Exception as e:
        error_msg = f"AI detection failed: {e}"
        console.print(Text("[ERROR]", style="bold red"), error_msg)
        return {
            "ai_components": [],
            "traditional_components": [],
            "errors": [error_msg]
        }


def _classify_ai_component(component_text: str) -> str:
    """Classify the type of AI component"""
    if any(term in component_text for term in ['llm', 'language model', 'gpt', 'bert', 'transformer']):
        return 'Language Model'
    elif any(term in component_text for term in ['computer vision', 'image', 'cv', 'object detection']):
        return 'Computer Vision'
    elif any(term in component_text for term in ['recommendation', 'recommender', 'collaborative filtering']):
        return 'Recommendation System'
    elif any(term in component_text for term in ['chatbot', 'assistant', 'conversational', 'dialogue']):
        return 'Conversational AI'
    elif any(term in component_text for term in ['prediction', 'forecasting', 'regression', 'classification']):
        return 'Predictive Model'
    elif any(term in component_text for term in ['embedding', 'vector', 'semantic search', 'similarity']):
        return 'Embedding/Vector System'
    elif any(term in component_text for term in ['agent', 'autonomous', 'decision making']):
        return 'AI Agent'
    else:
        return 'General AI/ML'


def _identify_ai_risk_factors(component_text: str) -> List[str]:
    """Identify specific risk factors for AI components"""
    risk_factors = []

    # Data-related risks
    if any(term in component_text for term in ['training data', 'dataset', 'data pipeline']):
        risk_factors.append('Data poisoning')

    # Model-related risks
    if any(term in component_text for term in ['model', 'inference', 'prediction']):
        risk_factors.append('Model extraction')
        risk_factors.append('Adversarial attacks')

    # Input-related risks
    if any(term in component_text for term in ['user input', 'prompt', 'query', 'request']):
        risk_factors.append('Prompt injection')
        risk_factors.append('Input manipulation')

    # Output-related risks
    if any(term in component_text for term in ['generation', 'response', 'output', 'result']):
        risk_factors.append('Hallucination')
        risk_factors.append('Bias amplification')

    # Privacy risks
    if any(term in component_text for term in ['personal', 'user data', 'private', 'sensitive']):
        risk_factors.append('Privacy leakage')
        risk_factors.append('Data reconstruction')

    # External service risks
    if any(term in component_text for term in ['api', 'service', 'external', 'third-party']):
        risk_factors.append('Supply chain attacks')
        risk_factors.append('Service dependency')

    return risk_factors
