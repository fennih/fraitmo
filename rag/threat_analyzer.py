"""
Threat Analyzer using RAG for DFD components
Finds relevant threats from knowledge base based on components and connections
"""

from typing import List, Dict, Set, Optional
from .document_loader import load_knowledge_base, search_documents
from .ollama_client import OllamaRAGClient
from models.schema import Component, Connection, DataFlowDiagram


class ThreatAnalyzer:
    """
    Analyzes DFD components and connections to find relevant threats using RAG
    """
    
    def __init__(self, knowledge_base_path: str = "knowledge_base"):
        """
        Initialize the threat analyzer
        
        Args:
            knowledge_base_path: Path to the knowledge base directory
        """
        self.kb_path = knowledge_base_path
        self.documents = []
        self.client = None
        
        # Load knowledge base
        self._load_knowledge_base()
        
        # Initialize RAG client
        self._initialize_rag_client()
        
        print(f"🛡️ Threat Analyzer initialized with {len(self.documents)} threats")
    
    def _load_knowledge_base(self):
        """Load threat knowledge base"""
        try:
            self.documents = load_knowledge_base(self.kb_path)
            if not self.documents:
                print("⚠️ No threat documents found in knowledge base")
            else:
                print(f"📚 Loaded {len(self.documents)} threat documents")
        except Exception as e:
            print(f"❌ Failed to load knowledge base: {e}")
            self.documents = []
    
    def _initialize_rag_client(self):
        """Initialize the RAG client"""
        try:
            self.client = OllamaRAGClient()
            print("🤖 RAG client initialized")
        except Exception as e:
            print(f"❌ Failed to initialize RAG client: {e}")
            self.client = None
    
    def analyze_component(self, component: Component) -> List[Dict]:
        """
        Analyze a single component for threats
        
        Args:
            component: DFD component to analyze
            
        Returns:
            List of relevant threats
        """
        if not self.documents:
            return []
        
        # Build query based on component characteristics
        query = self._build_component_query(component)
        
        # Search for relevant threats
        relevant_threats = search_documents(self.documents, query, max_results=3)
        
        # Enhance with RAG analysis if client available
        if self.client and relevant_threats:
            enhanced_threats = self._enhance_threats_with_rag(component, relevant_threats)
            return enhanced_threats
        
        return relevant_threats
    
    def analyze_connection(self, connection: Connection, source_comp: Component, target_comp: Component) -> List[Dict]:
        """
        Analyze a connection between components for threats
        
        Args:
            connection: DFD connection to analyze
            source_comp: Source component
            target_comp: Target component
            
        Returns:
            List of relevant threats
        """
        if not self.documents:
            return []
        
        # Build query based on connection characteristics
        query = self._build_connection_query(connection, source_comp, target_comp)
        
        # Search for relevant threats
        relevant_threats = search_documents(self.documents, query, max_results=2)
        
        # Enhance with RAG analysis if client available
        if self.client and relevant_threats:
            enhanced_threats = self._enhance_connection_threats_with_rag(connection, source_comp, target_comp, relevant_threats)
            return enhanced_threats
        
        return relevant_threats
    
    def analyze_dfd(self, dfd: DataFlowDiagram) -> Dict[str, List[Dict]]:
        """
        Analyze complete DFD for threats
        
        Args:
            dfd: DataFlowDiagram to analyze
            
        Returns:
            Dictionary with threats for components and connections
        """
        analysis_result = {
            'components': {},
            'connections': {},
            'cross_zone_threats': [],
            'summary': {}
        }
        
        print("\n🔍 Starting threat analysis...")
        
        # Analyze components
        print(f"\n📊 Analyzing {len(dfd.components)} components...")
        for comp_id, component in dfd.components.items():
            threats = self.analyze_component(component)
            if threats:
                analysis_result['components'][comp_id] = threats
                print(f"  ⚠️ {component.name}: {len(threats)} threats found")
            else:
                print(f"  ✅ {component.name}: No specific threats found")
        
        # Analyze connections
        print(f"\n🔗 Analyzing {len(dfd.connections)} connections...")
        for i, connection in enumerate(dfd.connections):
            source_comp = dfd.components.get(connection.source_id)
            target_comp = dfd.components.get(connection.target_id)
            
            if source_comp and target_comp:
                threats = self.analyze_connection(connection, source_comp, target_comp)
                if threats:
                    conn_key = f"{connection.source_name}→{connection.target_name}"
                    analysis_result['connections'][conn_key] = threats
                    print(f"  ⚠️ {conn_key}: {len(threats)} threats found")
        
        # Analyze cross-zone connections (higher risk)
        cross_zone_connections = dfd.cross_zone_connections
        if cross_zone_connections:
            print(f"\n🚨 Analyzing {len(cross_zone_connections)} cross-zone connections...")
            for connection in cross_zone_connections:
                source_comp = dfd.components.get(connection.source_id)
                target_comp = dfd.components.get(connection.target_id)
                
                if source_comp and target_comp:
                    # Cross-zone connections get special analysis
                    threats = self._analyze_cross_zone_threat(connection, source_comp, target_comp)
                    if threats:
                        analysis_result['cross_zone_threats'].extend(threats)
        
        # Summary
        total_threats = sum(len(threats) for threats in analysis_result['components'].values())
        total_threats += sum(len(threats) for threats in analysis_result['connections'].values())
        total_threats += len(analysis_result['cross_zone_threats'])
        
        analysis_result['summary'] = {
            'total_threats': total_threats,
            'components_with_threats': len(analysis_result['components']),
            'connections_with_threats': len(analysis_result['connections']),
            'cross_zone_threats': len(analysis_result['cross_zone_threats'])
        }
        
        return analysis_result
    
    def _build_component_query(self, component: Component) -> str:
        """Build search query for component threats"""
        query_parts = [
            component.component_type,
            component.component_category.value if hasattr(component.component_category, 'value') else str(component.component_category),
            component.vendor or '',
            'security threat vulnerability'
        ]
        
        # Add specific terms based on component type
        if 'api' in component.component_type.lower():
            query_parts.extend(['API', 'endpoint', 'injection'])
        elif 'database' in component.component_type.lower():
            query_parts.extend(['database', 'SQL', 'data breach'])
        elif 'llm' in component.component_type.lower() or 'ai' in component.component_type.lower():
            query_parts.extend(['LLM', 'AI', 'prompt injection', 'model'])
        elif 'cache' in component.component_type.lower():
            query_parts.extend(['cache', 'data leakage'])
        
        return ' '.join([part for part in query_parts if part])
    
    def _build_connection_query(self, connection: Connection, source: Component, target: Component) -> str:
        """Build search query for connection threats"""
        query_parts = [
            connection.connection_type or 'data flow',
            source.component_type,
            target.component_type,
            'communication threat attack'
        ]
        
        # Add specific terms based on connection type
        if connection.connection_type:
            if 'api' in connection.connection_type.lower():
                query_parts.extend(['API attack', 'injection'])
            elif 'database' in connection.connection_type.lower():
                query_parts.extend(['SQL injection', 'data breach'])
        
        return ' '.join([part for part in query_parts if part])
    
    def _enhance_threats_with_rag(self, component: Component, threats: List[Dict]) -> List[Dict]:
        """Enhance threat analysis with RAG reasoning"""
        if not self.client:
            return threats
        
        enhanced_threats = []
        
        for threat in threats:
            # Build context from threat
            context = f"""
Threat: {threat.get('name', 'Unknown')}
Description: {threat.get('description', '')}
Category: {threat.get('category', '')}
Impact: {', '.join(threat.get('impact', []))}
Mitigation: {', '.join(threat.get('mitigation', []))}
"""
            
            # Ask RAG for component-specific analysis
            question = f"How does this threat apply to a {component.component_type} component named '{component.name}' in a {component.trust_zone_name} trust zone?"
            
            try:
                rag_analysis = self.client.rag_query(question, context, max_tokens=150)
                
                # Add RAG analysis to threat
                enhanced_threat = threat.copy()
                enhanced_threat['rag_analysis'] = rag_analysis
                enhanced_threats.append(enhanced_threat)
                
            except Exception as e:
                print(f"⚠️ RAG analysis failed for {threat.get('name', 'Unknown')}: {e}")
                enhanced_threats.append(threat)
        
        return enhanced_threats
    
    def _enhance_connection_threats_with_rag(self, connection: Connection, source: Component, target: Component, threats: List[Dict]) -> List[Dict]:
        """Enhance connection threat analysis with RAG reasoning"""
        if not self.client:
            return threats
        
        enhanced_threats = []
        
        for threat in threats:
            # Build context from threat
            context = f"""
Threat: {threat.get('name', 'Unknown')}
Description: {threat.get('description', '')}
Category: {threat.get('category', '')}
Impact: {', '.join(threat.get('impact', []))}
"""
            
            # Ask RAG for connection-specific analysis
            question = f"How does this threat affect communication between {source.component_type} '{source.name}' and {target.component_type} '{target.name}'?"
            
            try:
                rag_analysis = self.client.rag_query(question, context, max_tokens=150)
                
                # Add RAG analysis to threat
                enhanced_threat = threat.copy()
                enhanced_threat['rag_analysis'] = rag_analysis
                enhanced_threats.append(enhanced_threat)
                
            except Exception as e:
                print(f"⚠️ RAG analysis failed for connection threat: {e}")
                enhanced_threats.append(threat)
        
        return enhanced_threats
    
    def _analyze_cross_zone_threat(self, connection: Connection, source: Component, target: Component) -> List[Dict]:
        """Analyze threats specific to cross-zone connections"""
        # Cross-zone connections are inherently higher risk
        cross_zone_query = f"trust boundary crossing {source.trust_zone_name} {target.trust_zone_name} security threat"
        
        threats = search_documents(self.documents, cross_zone_query, max_results=2)
        
        # Add generic cross-zone threat if none found
        if not threats:
            threats = [{
                'id': 'CROSS_ZONE_001',
                'name': 'Trust Boundary Crossing',
                'description': f'Data flow crosses trust boundary from {source.trust_zone_name} to {target.trust_zone_name}',
                'category': 'Trust Boundary Violation',
                'impact': ['Data Leakage', 'Privilege Escalation'],
                'mitigation': ['Authentication', 'Authorization', 'Encryption in transit']
            }]
        
        return threats


def print_threat_analysis(analysis: Dict):
    """Print threat analysis results in a readable format"""
    
    print("\n" + "="*60)
    print("🛡️  THREAT ANALYSIS RESULTS")
    print("="*60)
    
    summary = analysis.get('summary', {})
    print(f"\n📊 SUMMARY:")
    print(f"   Total threats found: {summary.get('total_threats', 0)}")
    print(f"   Components with threats: {summary.get('components_with_threats', 0)}")
    print(f"   Connections with threats: {summary.get('connections_with_threats', 0)}")
    print(f"   Cross-zone threats: {summary.get('cross_zone_threats', 0)}")
    
    # Component threats
    component_threats = analysis.get('components', {})
    if component_threats:
        print(f"\n🔧 COMPONENT THREATS:")
        for comp_id, threats in component_threats.items():
            print(f"\n   Component: {comp_id}")
            for threat in threats:
                print(f"   ⚠️  {threat.get('name', 'Unknown')}")
                print(f"      📝 {threat.get('description', '')}")
                if threat.get('rag_analysis'):
                    print(f"      🤖 Analysis: {threat['rag_analysis']}")
                print(f"      🛠️  Mitigation: {', '.join(threat.get('mitigation', []))}")
    
    # Connection threats
    connection_threats = analysis.get('connections', {})
    if connection_threats:
        print(f"\n🔗 CONNECTION THREATS:")
        for conn_name, threats in connection_threats.items():
            print(f"\n   Connection: {conn_name}")
            for threat in threats:
                print(f"   ⚠️  {threat.get('name', 'Unknown')}")
                print(f"      📝 {threat.get('description', '')}")
                if threat.get('rag_analysis'):
                    print(f"      🤖 Analysis: {threat['rag_analysis']}")
    
    # Cross-zone threats
    cross_zone_threats = analysis.get('cross_zone_threats', [])
    if cross_zone_threats:
        print(f"\n🚨 CROSS-ZONE THREATS:")
        for threat in cross_zone_threats:
            print(f"   ⚠️  {threat.get('name', 'Unknown')}")
            print(f"      📝 {threat.get('description', '')}")
    
    print("\n" + "="*60) 