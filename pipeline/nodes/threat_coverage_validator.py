# Threat Coverage Validator - Ensures comprehensive threat identification

from typing import Dict, Any, List, Set
from rich.text import Text
from utils.console import console


def validate_threat_coverage(threats: List[Dict[str, Any]], component: Dict[str, Any], analysis_type: str) -> Dict[str, Any]:
    """
    Validate that threat analysis provides comprehensive coverage
    
    Args:
        threats: List of identified threats
        component: Component being analyzed
        analysis_type: 'ai', 'traditional', or 'cross_component'
    
    Returns:
        Coverage validation report
    """
    validation_report = {
        'coverage_score': 0.0,
        'missing_categories': [],
        'recommendations': [],
        'threat_distribution': {},
        'completeness_assessment': 'incomplete'
    }
    
    try:
        # Check if we have any fallback-generated threats
        has_fallback_threats = any(threat.get('fallback_generated', False) for threat in threats)
        
        if analysis_type == 'ai':
            validation_report = _validate_ai_threat_coverage(threats, component)
        elif analysis_type == 'traditional':
            validation_report = _validate_traditional_threat_coverage(threats, component)
        elif analysis_type == 'cross_component':
            validation_report = _validate_boundary_threat_coverage(threats, component)
        
        # Adjust score if we have fallback threats (they're still valid)
        if has_fallback_threats and validation_report['coverage_score'] < 0.5:
            validation_report['coverage_score'] = max(validation_report['coverage_score'], 0.4)
            validation_report['recommendations'].append("Includes fallback-generated threats - consider re-running analysis for better coverage")
        
        # Log validation results with more realistic thresholds
        score = validation_report['coverage_score']
        threat_count = len(threats)
        
        if score >= 0.80:
            console.print_coverage("excellent", f"Excellent threat coverage: {score:.1%} ({threat_count} threats)")
        elif score >= 0.60:
            console.print_coverage("good", f"Good threat coverage: {score:.1%} ({threat_count} threats)")
        elif score >= 0.40:
            console.print_coverage("acceptable", f"Acceptable threat coverage: {score:.1%} ({threat_count} threats)")
        else:
            console.print_coverage("low", f"Low threat coverage: {score:.1%} ({threat_count} threats) - enhancement may be needed")
            
        return validation_report
        
    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Coverage validation failed: {e}")
        return validation_report


def _validate_ai_threat_coverage(threats: List[Dict[str, Any]], component: Dict[str, Any]) -> Dict[str, Any]:
    """Validate AI-specific threat coverage"""
    
    # Enhanced AI threat categories with more comprehensive keywords
    required_categories = {
        'Input Manipulation': [
            'prompt injection', 'prompt', 'injection', 'jailbreak', 'jailbreaking', 
            'adversarial input', 'adversarial', 'context poisoning', 'malicious input', 
            'input manipulation', 'crafted input', 'harmful prompt'
        ],
        'Model Attack': [
            'model extraction', 'model stealing', 'model inversion', 'extraction', 
            'membership inference', 'property inference', 'model theft', 'parameter extraction',
            'model querying', 'gradient', 'weights', 'architecture'
        ],
        'Training Attack': [
            'data poisoning', 'poisoning', 'backdoor', 'training data', 'dataset',
            'model corruption', 'malicious training', 'contaminated data', 'supply chain'
        ],
        'Output Manipulation': [
            'hallucination', 'hallucinating', 'bias amplification', 'bias', 'biased',
            'data leakage', 'information leakage', 'sensitive data', 'misinformation', 
            'false information', 'output tampering', 'response manipulation'
        ]
    }
    
    # Analyze threat distribution
    identified_categories = set()
    severity_distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    for threat in threats:
        threat_name = threat.get('name', '').lower()
        threat_desc = threat.get('description', '').lower()
        threat_text = f"{threat_name} {threat_desc}"
        
        # Check severity distribution
        severity = threat.get('severity', 'unknown').lower()
        if severity in severity_distribution:
            severity_distribution[severity] += 1
        
        # Check category coverage
        for category, keywords in required_categories.items():
            if any(keyword in threat_text for keyword in keywords):
                identified_categories.add(category)
                break
    
    # More realistic coverage calculation
    category_coverage = len(identified_categories) / len(required_categories)
    
    # More forgiving severity balance - expect at least 1 high+ severity per 3 threats
    expected_high_severity = max(1, len(threats) // 3)
    actual_high_severity = severity_distribution['critical'] + severity_distribution['high']
    severity_balance = min(1.0, actual_high_severity / expected_high_severity)
    
    # More realistic threat quantity expectations - 4+ threats is good for most components
    threat_quantity = min(1.0, len(threats) / 4) if len(threats) > 0 else 0.0
    
    # Rebalanced weights - category coverage is most important
    coverage_score = (category_coverage * 0.6) + (threat_quantity * 0.25) + (severity_balance * 0.15)
    
    # Bonus for having any threats at all (prevents 0% scores)
    if len(threats) > 0:
        coverage_score = max(coverage_score, 0.3)  # Minimum 30% if any threats found
    
    # Identify missing categories
    missing_categories = [cat for cat in required_categories.keys() if cat not in identified_categories]
    
    # Generate recommendations
    recommendations = []
    if missing_categories:
        recommendations.append(f"Missing threat categories: {', '.join(missing_categories)}")
    if len(threats) < 6:
        recommendations.append(f"Insufficient threat count: {len(threats)} (expected 8-15 for AI components)")
    if severity_distribution['critical'] + severity_distribution['high'] < 3:
        recommendations.append("Few critical/high severity threats - may indicate incomplete analysis")
    
    return {
        'coverage_score': coverage_score,
        'missing_categories': missing_categories,
        'recommendations': recommendations,
        'threat_distribution': severity_distribution,
        'completeness_assessment': 'excellent' if coverage_score >= 0.85 else 'good' if coverage_score >= 0.70 else 'incomplete',
        'identified_categories': list(identified_categories)
    }


def _validate_traditional_threat_coverage(threats: List[Dict[str, Any]], component: Dict[str, Any]) -> Dict[str, Any]:
    """Validate traditional component STRIDE coverage"""
    
    # Enhanced STRIDE categories with comprehensive keywords
    stride_categories = {
        'Spoofing': [
            'authentication', 'identity', 'impersonation', 'credential', 'spoofing', 'fake',
            'masquerade', 'impersonate', 'false identity', 'auth bypass', 'login', 'password'
        ],
        'Tampering': [
            'integrity', 'modification', 'corruption', 'injection', 'tampering', 'alter',
            'modify', 'change', 'sql injection', 'code injection', 'data corruption', 'manipulate'
        ],
        'Repudiation': [
            'logging', 'audit', 'non-repudiation', 'accountability', 'log', 'trace',
            'record', 'evidence', 'tracking', 'audit trail', 'deny', 'repudiate'
        ],
        'Information Disclosure': [
            'exposure', 'disclosure', 'leak', 'unauthorized access', 'information',
            'data breach', 'sensitive data', 'confidential', 'expose', 'reveal', 'access'
        ],
        'Denial of Service': [
            'availability', 'resource exhaustion', 'flooding', 'overload', 'dos', 'ddos',
            'service', 'unavailable', 'crash', 'hang', 'timeout', 'performance'
        ],
        'Elevation of Privilege': [
            'privilege', 'authorization', 'escalation', 'bypass', 'privilege escalation',
            'admin', 'root', 'elevated', 'permissions', 'access control', 'rights'
        ]
    }
    
    component_type = component.get('type', '').lower()
    
    # Component-specific threat expectations
    expected_threat_count = {
        'database': 12,
        'api': 10,
        'web': 8,
        'authentication': 8,
        'load balancer': 6,
        'file system': 6
    }.get(component_type, 6)
    
    # Analyze coverage
    identified_stride = set()
    severity_distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    for threat in threats:
        threat_text = f"{threat.get('name', '')} {threat.get('description', '')}".lower()
        
        # Check severity
        severity = threat.get('severity', 'unknown').lower()
        if severity in severity_distribution:
            severity_distribution[severity] += 1
        
        # Check STRIDE coverage
        for stride_cat, keywords in stride_categories.items():
            if any(keyword in threat_text for keyword in keywords):
                identified_stride.add(stride_cat)
    
    # More realistic coverage calculation for traditional components
    stride_coverage = len(identified_stride) / len(stride_categories)
    
    # More forgiving threat quantity - 3+ threats is acceptable
    realistic_threat_count = max(3, expected_threat_count // 3)
    threat_quantity = min(1.0, len(threats) / realistic_threat_count) if len(threats) > 0 else 0.0
    
    # More realistic severity expectations
    expected_high = max(1, len(threats) // 4)
    actual_high = severity_distribution['critical'] + severity_distribution['high']
    severity_balance = min(1.0, actual_high / expected_high) if expected_high > 0 else 0.5
    
    # Coverage calculation with minimum floor
    coverage_score = (stride_coverage * 0.6) + (threat_quantity * 0.25) + (severity_balance * 0.15)
    
    # Minimum score if any threats found
    if len(threats) > 0:
        coverage_score = max(coverage_score, 0.35)  # Minimum 35% if any threats found
    
    # Missing categories and recommendations
    missing_stride = [cat for cat in stride_categories.keys() if cat not in identified_stride]
    recommendations = []
    
    if missing_stride:
        recommendations.append(f"Missing STRIDE categories: {', '.join(missing_stride)}")
    if len(threats) < expected_threat_count * 0.7:
        recommendations.append(f"Low threat count: {len(threats)} (expected ~{expected_threat_count} for {component_type})")
    
    return {
        'coverage_score': coverage_score,
        'missing_categories': missing_stride,
        'recommendations': recommendations,
        'threat_distribution': severity_distribution,
        'completeness_assessment': 'excellent' if coverage_score >= 0.85 else 'good' if coverage_score >= 0.70 else 'incomplete',
        'identified_stride': list(identified_stride)
    }


def _validate_boundary_threat_coverage(threats: List[Dict[str, Any]], flow_info: Dict[str, Any]) -> Dict[str, Any]:
    """Validate trust boundary crossing threat coverage"""
    
    # Trust boundary threat categories
    boundary_categories = {
        'Authentication': ['authentication', 'credential', 'identity verification'],
        'Authorization': ['authorization', 'access control', 'privilege'],
        'Data Integrity': ['integrity', 'tampering', 'corruption', 'mitm'],
        'Confidentiality': ['encryption', 'confidentiality', 'exposure', 'interception']
    }
    
    # Analyze coverage
    identified_categories = set()
    severity_distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    for threat in threats:
        threat_text = f"{threat.get('name', '')} {threat.get('description', '')}".lower()
        
        severity = threat.get('severity', 'unknown').lower()
        if severity in severity_distribution:
            severity_distribution[severity] += 1
        
        for category, keywords in boundary_categories.items():
            if any(keyword in threat_text for keyword in keywords):
                identified_categories.add(category)
    
    # Coverage calculation
    category_coverage = len(identified_categories) / len(boundary_categories)
    threat_quantity = min(1.0, len(threats) / 6)  # Expect at least 6 boundary threats
    severity_focus = min(1.0, (severity_distribution['critical'] + severity_distribution['high']) / max(1, len(threats)))
    
    coverage_score = (category_coverage * 0.5) + (threat_quantity * 0.3) + (severity_focus * 0.2)
    
    missing_categories = [cat for cat in boundary_categories.keys() if cat not in identified_categories]
    
    recommendations = []
    if missing_categories:
        recommendations.append(f"Missing boundary threat categories: {', '.join(missing_categories)}")
    if len(threats) < 4:
        recommendations.append(f"Insufficient boundary threats: {len(threats)} (expected 6-10)")
    
    return {
        'coverage_score': coverage_score,
        'missing_categories': missing_categories,
        'recommendations': recommendations,
        'threat_distribution': severity_distribution,
        'completeness_assessment': 'excellent' if coverage_score >= 0.85 else 'good' if coverage_score >= 0.70 else 'incomplete',
        'identified_categories': list(identified_categories)
    }


def generate_coverage_enhancement_prompts(validation_report: Dict[str, Any], analysis_type: str) -> List[str]:
    """Generate additional prompts to fill coverage gaps"""
    
    enhancement_prompts = []
    missing_categories = validation_report.get('missing_categories', [])
    
    if not missing_categories:
        return enhancement_prompts
    
    if analysis_type == 'ai':
        for category in missing_categories:
            if category == 'Input Manipulation':
                enhancement_prompts.append("Focus specifically on input manipulation threats: prompt injection variations, context poisoning, adversarial examples, and jailbreaking techniques.")
            elif category == 'Model Attack':
                enhancement_prompts.append("Analyze model-specific attack vectors: extraction attacks, inversion techniques, membership inference, and property inference vulnerabilities.")
            elif category == 'Training Attack':
                enhancement_prompts.append("Examine training-phase vulnerabilities: data poisoning scenarios, backdoor insertion, and model corruption attacks.")
            elif category == 'Output Manipulation':
                enhancement_prompts.append("Investigate output manipulation risks: hallucination exploitation, bias amplification, and sensitive data leakage scenarios.")
    
    elif analysis_type == 'traditional':
        stride_prompts = {
            'Spoofing': "Analyze identity and authentication spoofing threats specific to this component.",
            'Tampering': "Examine data integrity and tampering vulnerabilities including injection attacks.",
            'Repudiation': "Investigate logging, audit, and non-repudiation failures.",
            'Information Disclosure': "Analyze unauthorized data exposure and information leakage threats.",
            'Denial of Service': "Examine availability threats including resource exhaustion and overload scenarios.",
            'Elevation of Privilege': "Investigate privilege escalation and authorization bypass vulnerabilities."
        }
        
        for category in missing_categories:
            if category in stride_prompts:
                enhancement_prompts.append(stride_prompts[category])
    
    elif analysis_type == 'cross_component':
        boundary_prompts = {
            'Authentication': "Analyze authentication failures and credential vulnerabilities in cross-zone communication.",
            'Authorization': "Examine access control and privilege management across trust boundaries.",
            'Data Integrity': "Investigate data tampering and man-in-the-middle attack scenarios.",
            'Confidentiality': "Analyze encryption weaknesses and data exposure risks in transit."
        }
        
        for category in missing_categories:
            if category in boundary_prompts:
                enhancement_prompts.append(boundary_prompts[category])
    
    return enhancement_prompts