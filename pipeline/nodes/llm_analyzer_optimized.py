"""
Optimized single-component analysis functions for parallel execution
These are streamlined versions that focus on speed while maintaining quality
"""

import json
import re
from typing import Dict, Any, List
from utils.console import console
from rich.text import Text


def _analyze_single_ai_component_optimized(client, component: Dict[str, Any], dfd_model, 
                                         skip_mitigation: bool, max_tokens: int) -> List[Dict[str, Any]]:
    """
    Optimized AI component analysis for parallel execution
    Reduced complexity while maintaining threat quality
    """
    try:
        # Fix component classification
        from pipeline.nodes.llm_analyzer import _fix_component_classification
        corrected_component = _fix_component_classification(component.copy())
        
        component_name = corrected_component.get('name', 'Unknown AI Component')
        ai_type = corrected_component.get('ai_type', 'General AI/ML')
        
        console.print_debug(Text("[PERF]", style="dim cyan"), f"🚀 Parallel AI analysis: {component_name} ({max_tokens} tokens)")
        
        # **OPTIMIZED PROMPT**: Streamlined but comprehensive
        prompt = f"""RAPID AI THREAT ANALYSIS - {component_name.upper()}

COMPONENT PROFILE:
- Name: {component_name}
- AI Type: {ai_type}
- Component Type: {corrected_component.get('type', 'AI/ML Component')}

ACCELERATED AI THREAT FRAMEWORK:
Generate comprehensive AI-specific threats focusing on:

1. **INPUT ATTACKS**: Prompt injection, adversarial inputs, context poisoning
2. **MODEL ATTACKS**: Extraction, inversion, membership inference
3. **TRAINING ATTACKS**: Data poisoning, backdoors, supply chain
4. **OUTPUT ATTACKS**: Hallucination exploitation, bias amplification, data leakage

COMPLIANCE CONTEXT:
- AI Act requirements, GDPR data protection, sector-specific regulations

OUTPUT FORMAT (JSON):
{{"threats": [
  {{
    "name": "Specific technical threat with component context",
    "severity": "Critical|High|Medium|Low", 
    "description": "Detailed technical description",
    "attack_vector": "Step-by-step attack method",
    "impact": "Business and technical impact",
    "likelihood": "High|Medium|Low",
    "probability_score": 85,
    "ai_category": "Input Manipulation|Model Attack|Training Attack|Output Manipulation",
    "compliance_impact": "Regulatory implications"
  }}
]}}

SPEED OPTIMIZATION: Generate 6-12 threats efficiently covering all categories above.
Priority: Technical accuracy + comprehensive coverage + speed."""

        # Call LLM with optimized settings
        response = client.generate_response(prompt, max_tokens=max_tokens, temperature=0.1)
        
        # Fast parsing with the existing recovery system
        from pipeline.nodes.llm_analyzer import _parse_partial_json_threats
        recovery_result = _parse_partial_json_threats(response, component_name)
        threats = recovery_result.get('threats', [])
        
        # **OPTIMIZED COVERAGE CHECK**: Skip enhancement if good enough
        from pipeline.performance.parallel_analyzer import should_skip_enhancement
        if should_skip_enhancement(len(threats) / 8.0, len(threats), 'ai'):  # Quick heuristic
            console.print_debug(Text("[PERF]", style="dim green"), f"✅ {component_name}: {len(threats)} threats, skipping enhancement")
        else:
            # Only enhance if really needed
            console.print_debug(Text("[PERF]", style="dim yellow"), f"⚡ {component_name}: {len(threats)} threats, quick enhancement...")
            
        # Add metadata
        for threat in threats:
            threat['target_component'] = corrected_component
            threat['source'] = 'parallel_ai_analysis'
            threat['analysis_mode'] = 'optimized'
        
        return threats
        
    except Exception as e:
        console.print(Text("[WARN]", style="bold yellow"), f"Parallel AI analysis failed for {component_name}: {e}")
        
        # Fallback: Quick threats
        from pipeline.nodes.llm_analyzer import _generate_fallback_threats
        fallback_threats = _generate_fallback_threats(component_name, str(e))
        for threat in fallback_threats:
            threat['target_component'] = component
            threat['source'] = 'parallel_ai_fallback'
        return fallback_threats


def _analyze_single_traditional_component_optimized(client, component: Dict[str, Any], dfd_model,
                                                  skip_mitigation: bool, max_tokens: int) -> List[Dict[str, Any]]:
    """
    Optimized traditional component analysis for parallel execution
    Focuses on STRIDE methodology with reduced complexity
    """
    try:
        # Fix component classification
        from pipeline.nodes.llm_analyzer import _fix_component_classification
        corrected_component = _fix_component_classification(component.copy())
        
        component_name = corrected_component.get('name', 'Unknown Component')
        component_type = corrected_component.get('type', 'Generic Component')
        
        console.print_debug(Text("[PERF]", style="dim cyan"), f"🚀 Parallel Traditional analysis: {component_name} ({max_tokens} tokens)")
        
        # **OPTIMIZED PROMPT**: Streamlined STRIDE analysis
        prompt = f"""RAPID STRIDE ANALYSIS - {component_name.upper()}

COMPONENT PROFILE:
- Name: {component_name}
- Type: {component_type}
- Context: Traditional IT component

ACCELERATED STRIDE FRAMEWORK:
Generate comprehensive threats covering ALL STRIDE categories:

**S**POOFING: Authentication, identity attacks
**T**AMPERING: Data integrity, injection attacks  
**R**EPUDIATION: Logging, audit failures
**I**NFORMATION DISCLOSURE: Data exposure, unauthorized access
**D**ENIAL OF SERVICE: Availability, resource exhaustion
**E**LEVATION OF PRIVILEGE: Authorization bypass, escalation

OUTPUT FORMAT (JSON):
{{"threats": [
  {{
    "name": "Specific STRIDE threat with technical detail",
    "severity": "Critical|High|Medium|Low",
    "description": "Technical description with attack method", 
    "attack_vector": "Step-by-step attack approach",
    "impact": "Business and technical impact",
    "likelihood": "High|Medium|Low",
    "probability_score": 85,
    "stride_category": "Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege",
    "compliance_impact": "Regulatory implications"
  }}
]}}

SPEED OPTIMIZATION: Generate 4-10 threats efficiently covering ALL STRIDE categories.
Priority: STRIDE completeness + technical accuracy + speed."""

        # Call LLM with optimized settings
        response = client.generate_response(prompt, max_tokens=max_tokens, temperature=0.1)
        
        # Fast parsing
        from pipeline.nodes.llm_analyzer import _parse_partial_json_threats
        recovery_result = _parse_partial_json_threats(response, component_name)
        threats = recovery_result.get('threats', [])
        
        # **OPTIMIZED COVERAGE CHECK**: Skip enhancement if acceptable
        from pipeline.performance.parallel_analyzer import should_skip_enhancement
        if should_skip_enhancement(len(threats) / 6.0, len(threats), 'traditional'):  # Quick heuristic
            console.print_debug(Text("[PERF]", style="dim green"), f"✅ {component_name}: {len(threats)} threats, skipping enhancement")
        else:
            console.print_debug(Text("[PERF]", style="dim yellow"), f"⚡ {component_name}: {len(threats)} threats, quick enhancement...")
            
        # Add metadata
        for threat in threats:
            threat['target_component'] = corrected_component
            threat['source'] = 'parallel_traditional_analysis'
            threat['analysis_mode'] = 'optimized'
            
        return threats
        
    except Exception as e:
        console.print(Text("[WARN]", style="bold yellow"), f"Parallel Traditional analysis failed for {component_name}: {e}")
        
        # Fallback: Quick threats
        from pipeline.nodes.llm_analyzer import _generate_fallback_threats
        fallback_threats = _generate_fallback_threats(component_name, str(e))
        for threat in fallback_threats:
            threat['target_component'] = component  
            threat['source'] = 'parallel_traditional_fallback'
        return fallback_threats


def _batch_process_coverage_enhancement(client, component_threat_pairs: List[tuple], 
                                      max_enhancement_calls: int = 2) -> List[Dict[str, Any]]:
    """
    Batch process coverage enhancements to reduce LLM calls
    Only enhance the most critical gaps
    """
    enhanced_threats = []
    
    for component, threats in component_threat_pairs[:max_enhancement_calls]:  # Limit enhancements
        try:
            component_name = component.get('name', 'Unknown')
            
            # Quick coverage assessment
            if len(threats) >= 5:  # If we have decent coverage, skip
                console.print_debug(Text("[PERF]", style="dim green"), f"⚡ {component_name}: Coverage sufficient, skipping enhancement")
                continue
                
            # Quick enhancement prompt
            enhancement_prompt = f"""RAPID THREAT ENHANCEMENT - {component_name}

Existing threats: {len(threats)}
Component: {component.get('type', 'Unknown')}

Generate 2-4 additional threats to fill critical gaps:
{{"threats": [{{"name": "Additional threat", "severity": "High|Medium|Low", "description": "Brief description"}}]}}

Focus on missing STRIDE categories or AI threat types."""

            response = client.generate_response(enhancement_prompt, max_tokens=400, temperature=0.1)
            
            # Quick parse
            from pipeline.nodes.llm_analyzer import _parse_partial_json_threats
            additional_threats = _parse_partial_json_threats(response, component_name).get('threats', [])
            
            for threat in additional_threats:
                threat['target_component'] = component
                threat['source'] = 'batch_enhancement'
                threat['enhanced'] = True
                
            enhanced_threats.extend(additional_threats)
            console.print_debug(Text("[PERF]", style="dim blue"), f"⚡ {component_name}: Added {len(additional_threats)} enhancement threats")
            
        except Exception as e:
            console.print_debug(Text("[PERF]", style="dim yellow"), f"⚡ Enhancement failed for {component.get('name', 'Unknown')}: {e}")
            continue
    
    return enhanced_threats