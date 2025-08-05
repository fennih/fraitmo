"""
Threat Analyzer using RAG for DFD components
Finds relevant threats from knowledge base based on components and connections
"""

import json
from typing import List, Dict, Any, Optional
from utils.console import console
from rich.text import Text

# Import our document loader and LLM client
from rag.document_loader import load_threat_knowledge_base, search_threats
from rag.llm_client import UnifiedLLMClient
from models.schema import DataFlowDiagram



class ThreatAnalyzer:
    """
    Enhanced threat analyzer with RAG capabilities
    Combines knowledge base lookup with LLM analysis
    """

    def __init__(self, kb_path: str = "knowledge_base"):
        """Initialize with knowledge base"""
        try:
            self.documents = load_threat_knowledge_base(kb_path)
            console.print(Text("[OK]", style="bold green"), f"Threat Analyzer initialized with {len(self.documents)} threats")
        except Exception as e:
            self.documents = []
            console.print(Text("[ERROR]", style="bold red"), f"Failed to load knowledge base: {e}")

        # Initialize LLM client
        try:
            self.llm_client = UnifiedLLMClient()
            if not self.documents:
                console.print(Text("[WARN]", style="bold yellow"), "No threat documents found in knowledge base")
            console.print(Text("[OK]", style="bold green"), "RAG client initialized")
        except Exception as e:
            console.print(Text("[ERROR]", style="bold red"), f"Failed to initialize RAG client: {e}")
            self.llm_client = None

    def analyze_component_threats(self, component: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze threats for a specific component using RAG

        Args:
            component: Component information

        Returns:
            List of relevant threats
        """
        threats = []

        # Extract component information
        comp_name = component.get('name', '')
        comp_type = component.get('type', '')
        comp_description = component.get('description', '')

        # Create search query from component characteristics
        search_terms = [comp_name, comp_type, comp_description]
        query = ' '.join(filter(None, search_terms))

        # Search knowledge base
        relevant_threats = search_threats(self.documents, query, max_results=10)

        for threat in relevant_threats:
            # Enhance threat with RAG analysis if LLM is available
            enhanced_threat = threat.copy()
            enhanced_threat['target_component'] = component
            enhanced_threat['relevance_score'] = threat.get('relevance_score', 0)

            # Add LLM-enhanced analysis
            if self.llm_client:
                try:
                    rag_analysis = self._get_llm_threat_analysis(component, threat)
                    enhanced_threat['rag_analysis'] = rag_analysis
                except Exception as e:
                    enhanced_threat['rag_analysis'] = f"Analysis failed: {e}"

            threats.append(enhanced_threat)

        return threats

    def _get_llm_threat_analysis(self, component: Dict[str, Any], threat: Dict[str, Any]) -> str:
        """Get LLM analysis of threat relevance to component"""
        prompt = f"""# Component-Specific Threat Relevance Analysis

## Target Component Context
- **Name**: {component.get('name', 'Unknown')}
- **Type**: {component.get('type', 'Unknown')}
- **Description**: {component.get('description', 'None')}

## Threat Assessment
- **Threat Name**: {threat.get('name', 'Unknown')}
- **Category**: {threat.get('category', 'Unknown')}
- **Description**: {threat.get('description', 'None')}
- **Severity**: {threat.get('severity', 'Unknown')}

## Analysis Instructions
Provide a concise technical assessment (2-3 sentences) covering:

### Required Analysis Points:
1. **Component Applicability**: How this threat specifically applies to this component type and configuration
2. **Risk Assessment**: Likelihood of exploitation and potential business/technical impact
3. **Context Considerations**: Key factors that increase or decrease threat relevance for this scenario

### Analysis Focus:
- Be specific to the component type and its role in the system
- Consider actual attack vectors and exploitation scenarios
- Factor in component exposure and protection mechanisms
- Provide actionable insights for threat prioritization

Generate a focused, technical analysis:"""

        return self.llm_client.generate_response(prompt, max_tokens=200, temperature=0.1)

    def analyze_dfd_threats(self, dfd: DataFlowDiagram) -> Dict[str, Any]:
        """
        Comprehensive threat analysis for entire DFD

        Args:
            dfd: DFD model to analyze

        Returns:
            Comprehensive threat analysis results
        """
        analysis_results = {
            'component_threats': [],
            'connection_threats': [],
            'cross_zone_threats': [],
            'summary': {}
        }

        console.print(Text("[INFO]", style="bold blue"), f"Analyzing {len(dfd.components)} components...")

        # Analyze individual components
        for component in dfd.components:
            threats = self.analyze_component_threats({
                'name': component.name,
                'type': component.component_type,
                'description': component.description,
                'trust_zone': component.trust_zone
            })

            if threats:
                console.print(Text("[WARN]", style="bold yellow"), f"{component.name}: {len(threats)} threats found")
                analysis_results['component_threats'].extend(threats)
            else:
                console.print(Text("[OK]", style="bold green"), f"{component.name}: No specific threats found")

        # Analyze connections
        for connection in dfd.connections:
            threats = self._analyze_connection_threats(connection)
            if threats:
                console.print(Text("[WARN]", style="bold yellow"), f"{connection.source_id} -> {connection.target_id}: {len(threats)} threats found")
                analysis_results['connection_threats'].extend(threats)

        # Analyze cross-zone connections (high priority)
        console.print(Text("[INFO]", style="bold blue"), f"Analyzing {len(dfd.cross_zone_connections)} cross-zone connections...")
        for connection_key in dfd.cross_zone_connections:
            threats = self._analyze_cross_zone_threats(connection_key, dfd.cross_zone_connections[connection_key])
            if threats:
                analysis_results['cross_zone_threats'].extend(threats)

        # Generate summary
        analysis_results['summary'] = self._generate_threat_summary(analysis_results)

        return analysis_results

    def _analyze_connection_threats(self, connection) -> List[Dict[str, Any]]:
        """Analyze threats specific to data flows/connections"""
        # Search for connection/flow related threats
        search_query = f"data flow connection {connection.label} {connection.protocol}"
        threats = search_threats(self.documents, search_query, max_results=5)

        # Enhance with connection context
        enhanced_threats = []
        for threat in threats:
            enhanced_threat = threat.copy()
            enhanced_threat['target_connection'] = {
                'source': connection.source_id,
                'target': connection.target_id,
                'label': connection.label,
                'protocol': connection.protocol
            }

            # Add LLM analysis for connection threats
            if self.llm_client:
                try:
                    prompt = f"""# Data Flow Connection Threat Analysis

## Connection Context
- **Data Flow**: {connection.source_id} → {connection.target_id}
- **Protocol**: {connection.protocol}
- **Data Type**: {connection.label}

## Threat Assessment
- **Threat Name**: {threat.get('name', 'Unknown')}
- **Description**: {threat.get('description', 'None')}

## Analysis Instructions
Analyze how this threat specifically applies to this data connection (2-3 sentences):

### Required Assessment:
1. **Connection Vulnerability**: How the threat exploits this specific data flow
2. **Protocol Risks**: Protocol-specific attack vectors and weaknesses
3. **Data Exposure**: Risk to data confidentiality, integrity, or availability during transit

### Analysis Focus:
- Consider the specific protocol and its security characteristics
- Factor in data sensitivity and exposure during transmission
- Evaluate attack feasibility given the connection type
- Provide concrete insights for this data flow scenario

Generate focused connection-specific threat analysis:"""
                    enhanced_threat['rag_analysis'] = self.llm_client.generate_response(prompt, max_tokens=150)
                except Exception as e:
                    console.print(Text("[WARN]", style="bold yellow"), f"RAG analysis failed for {threat.get('name', 'Unknown')}: {e}")

            enhanced_threats.append(enhanced_threat)

        return enhanced_threats

    def _analyze_cross_zone_threats(self, connection_key: str, connection_details: Dict) -> List[Dict[str, Any]]:
        """Analyze threats for cross-trust-zone connections (critical)"""
        # These are high-priority threats - search for trust boundary related issues
        search_query = "trust boundary cross zone privilege escalation unauthorized access"
        threats = search_threats(self.documents, search_query, max_results=8)

        enhanced_threats = []
        for threat in threats:
            enhanced_threat = threat.copy()
            enhanced_threat['threat_type'] = 'cross_zone'
            enhanced_threat['severity'] = 'HIGH'  # Elevate severity for cross-zone
            enhanced_threat['target_connection'] = connection_details
            enhanced_threat['connection_key'] = connection_key

            # LLM analysis for cross-zone threats
            if self.llm_client:
                try:
                    prompt = f"""# Cross-Trust Zone Threat Analysis

## Trust Boundary Context
- **Connection**: {connection_key}
- **Source Zone**: {connection_details.get('source_zone', 'Unknown')}
- **Target Zone**: {connection_details.get('target_zone', 'Unknown')}
- **Protocol**: {connection_details.get('protocol', 'Unknown')}

## Threat Assessment
- **Threat Name**: {threat.get('name', 'Unknown')}
- **Description**: {threat.get('description', 'None')}

## Analysis Instructions
Analyze the specific risks when this threat crosses trust boundaries:

### Required Assessment:
1. **Boundary Exploitation**: How the threat leverages trust zone differences
2. **Escalation Potential**: Risk of privilege or access escalation across zones
3. **Impact Amplification**: How crossing boundaries increases threat severity

### Trust Boundary Considerations:
- Different security controls between zones
- Zone-specific access privileges and restrictions
- Network segmentation and monitoring capabilities
- Data sensitivity differences across zones

### Risk Factors:
- **Likelihood**: Probability of successful cross-zone exploitation
- **Impact**: Business/technical consequences of boundary breach
- **Detection**: Visibility and monitoring across zone boundaries

Generate focused cross-zone threat analysis with specific risk assessment:"""
                    enhanced_threat['rag_analysis'] = self.llm_client.generate_response(prompt, max_tokens=200)
                except Exception as e:
                    console.print(Text("[WARN]", style="bold yellow"), f"RAG analysis failed for connection threat: {e}")

            enhanced_threats.append(enhanced_threat)

        return enhanced_threats

    def _generate_threat_summary(self, analysis_results: Dict) -> Dict[str, Any]:
        """Generate comprehensive threat analysis summary"""
        component_threats = analysis_results.get('component_threats', [])
        connection_threats = analysis_results.get('connection_threats', [])
        cross_zone_threats = analysis_results.get('cross_zone_threats', [])

        all_threats = component_threats + connection_threats + cross_zone_threats

        # Count by severity
        severity_counts = {}
        for threat in all_threats:
            severity = threat.get('severity', 'Unknown').upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Count by category
        category_counts = {}
        for threat in all_threats:
            category = threat.get('category', 'Unknown')
            category_counts[category] = category_counts.get(category, 0) + 1

        return {
            'total_threats': len(all_threats),
            'component_threats_count': len(component_threats),
            'connection_threats_count': len(connection_threats),
            'cross_zone_threats_count': len(cross_zone_threats),
            'severity_breakdown': severity_counts,
            'category_breakdown': category_counts,
            'high_priority_threats': len([t for t in all_threats if t.get('severity', '').upper() in ['HIGH', 'CRITICAL']]),
            'cross_zone_risk_level': 'HIGH' if cross_zone_threats else 'LOW'
        }

    def generate_threat_report(self, analysis_results: Dict) -> str:
        """Generate a comprehensive threat analysis report"""
        console.print(Text("[OK]", style="bold green"), "THREAT ANALYSIS RESULTS")
        console.print("=" * 50)

        summary = analysis_results.get('summary', {})
        console.print(Text("[INFO]", style="bold blue"), "SUMMARY:")
        console.print(f"Total Threats: {summary.get('total_threats', 0)}")
        console.print(f"Component Threats: {summary.get('component_threats_count', 0)}")
        console.print(f"Connection Threats: {summary.get('connection_threats_count', 0)}")
        console.print(f"Cross-Zone Threats: {summary.get('cross_zone_threats_count', 0)}")
        console.print(f"High Priority: {summary.get('high_priority_threats', 0)}")

        # Component threats
        component_threats = analysis_results.get('component_threats', [])
        if component_threats:
            console.print(Text("[WARN]", style="bold yellow"), "COMPONENT THREATS:")
            for threat in component_threats[:10]:  # Show top 10
                console.print(Text("[WARN]", style="bold yellow"), f"{threat.get('name', 'Unknown')}")
                console.print(f"Target: {threat.get('target_component', {}).get('name', 'Unknown')}")
                console.print(f"Severity: {threat.get('severity', 'Unknown')}")
                console.print(f"Description: {threat.get('description', '')}")

                if threat.get('rag_analysis'):
                    console.print(Text("[INFO]", style="bold blue"), f"Analysis: {threat['rag_analysis']}")
                    console.print(Text("[INFO]", style="bold blue"), f"Mitigation: {', '.join(threat.get('mitigation', []))}")
                console.print("-" * 40)

        # Connection threats
        connection_threats = analysis_results.get('connection_threats', [])
        if connection_threats:
            console.print(Text("[WARN]", style="bold yellow"), "CONNECTION THREATS:")
            for threat in connection_threats[:5]:  # Show top 5
                console.print(Text("[WARN]", style="bold yellow"), f"{threat.get('name', 'Unknown')}")
                console.print(f"Description: {threat.get('description', '')}")

                if threat.get('rag_analysis'):
                    console.print(Text("[INFO]", style="bold blue"), f"Analysis: {threat['rag_analysis']}")

        # Cross-zone threats (most critical)
        cross_zone_threats = analysis_results.get('cross_zone_threats', [])
        if cross_zone_threats:
            console.print(Text("[ERROR]", style="bold red"), "CROSS-ZONE THREATS:")
            for threat in cross_zone_threats:
                console.print(Text("[WARN]", style="bold yellow"), f"{threat.get('name', 'Unknown')}")
                console.print(f"Description: {threat.get('description', '')}")

        return "Threat analysis completed"


def main():
    """Test the threat analyzer"""
    analyzer = ThreatAnalyzer()

    # Test component analysis
    test_component = {
        'name': 'User Authentication API',
        'type': 'web service',
        'description': 'REST API for user login and authentication'
    }

    threats = analyzer.analyze_component_threats(test_component)
    console.print(Text("[INFO]", style="bold blue"), f"Found {len(threats)} threats for test component")


if __name__ == "__main__":
    main()
