from typing import Dict, List, Any, Optional
from .schema import (
    DataFlowDiagram, 
    TrustZone, 
    Component, 
    Connection,
    ComponentCategory,
    TrustZoneType
)


class DFDBuilder:
    """Builder for constructing DataFlowDiagram from XML parser output"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        """Reset builder for new construction"""
        self._trust_zones: Dict[str, TrustZone] = {}
        self._components: Dict[str, Component] = {}
        self._connections: List[Connection] = []
        self._id_to_name_map: Dict[str, str] = {}
    
    def from_parser_output(self, parser_data: Dict[str, Any]) -> 'DFDBuilder':
        """Build DFD from XML parser output"""
        self.reset()
        
        # Build trust zones first
        self._build_trust_zones(parser_data.get('trust_zones', {}))
        
        # Build components (reference trust zones)
        self._build_components(parser_data.get('components', {}))
        
        # Build connections (reference components)
        self._build_connections(parser_data.get('connections', []))
        
        return self
    
    def _build_trust_zones(self, zones_data: Dict[str, str]) -> None:
        """Build trust zones"""
        for zone_id, zone_name in zones_data.items():
            trust_zone = TrustZone(
                id=zone_id,
                name=zone_name
            )
            self._trust_zones[zone_id] = trust_zone
    
    def _build_components(self, components_data: Dict[str, Dict[str, Any]]) -> None:
        """Build components"""
        for comp_id, comp_data in components_data.items():
            # Map ID -> name for connections
            self._id_to_name_map[comp_id] = comp_data['name']
            
            # Find trust zone
            zone_id = self._find_zone_id_for_component(comp_data)
            trust_zone = self._trust_zones.get(zone_id)
            
            component = Component(
                id=comp_id,
                name=comp_data['name'],
                component_type=comp_data.get('type', 'Unknown'),
                trust_zone_id=zone_id,
                trust_zone_name=trust_zone.name if trust_zone else comp_data.get('zone', 'Unknown'),
                description=self._generate_description(comp_data)
            )
            
            self._components[comp_id] = component
    
    def _find_zone_id_for_component(self, comp_data: Dict[str, Any]) -> str:
        """Find trust zone ID for component"""
        zone_name = comp_data.get('zone', 'Unknown')
        
        # Search by zone name
        for zone_id, trust_zone in self._trust_zones.items():
            if trust_zone.name == zone_name:
                return zone_id
        
        return "unknown"
    
    def _generate_description(self, comp_data: Dict[str, Any]) -> Optional[str]:
        """Generate component description"""
        comp_type = comp_data.get('type', 'Unknown')
        name = comp_data.get('name', '')
        
        if comp_type == 'Unknown':
            return f"Component: {name}"
        
        # Simple descriptions for known types
        if 'API' in comp_type:
            return f"API endpoint: {name}"
        elif 'AWS-ECS' in comp_type:
            return f"AWS container service: {name}"
        elif 'AWS-AURORA' in comp_type:
            return f"AWS database: {name}"
        elif 'ELASTICACHE' in comp_type:
            return f"AWS cache: {name}"
        elif 'LLM' in comp_type:
            return f"AI/ML service: {name}"
        elif 'MOBILE' in comp_type:
            return f"Mobile interface: {name}"
        
        return f"Service: {name}"
    
    def _build_connections(self, connections_data: List[Dict[str, str]]) -> None:
        """Build connections"""
        for conn_data in connections_data:
            source_name = conn_data.get('from', '')
            target_name = conn_data.get('to', '')
            
            # Find IDs from names
            source_id = self._find_component_id_by_name(source_name)
            target_id = self._find_component_id_by_name(target_name)
            
            if source_id and target_id:
                connection = Connection(
                    source_id=source_id,
                    source_name=source_name,
                    target_id=target_id,
                    target_name=target_name,
                    connection_type=self._infer_connection_type(source_id, target_id)
                )
                
                self._connections.append(connection)
    
    def _find_component_id_by_name(self, name: str) -> Optional[str]:
        """Find component ID by name"""
        for comp_id, comp_name in self._id_to_name_map.items():
            if comp_name == name:
                return comp_id
        return None
    
    def _infer_connection_type(self, source_id: str, target_id: str) -> Optional[str]:
        """Infer connection type from components"""
        source_comp = self._components.get(source_id)
        target_comp = self._components.get(target_id)
        
        if not source_comp or not target_comp:
            return None
        
        # Simple connection type inference
        if target_comp.component_category == ComponentCategory.DATABASE:
            return "database"
        elif target_comp.component_category == ComponentCategory.CACHE:
            return "cache"
        elif target_comp.component_category == ComponentCategory.AI_ML:
            return "ai_api"
        elif target_comp.component_category == ComponentCategory.API:
            return "http_api"
        
        return "generic"
    
    def build(self, name: Optional[str] = None, description: Optional[str] = None) -> DataFlowDiagram:
        """Build final DataFlowDiagram"""
        return DataFlowDiagram(
            trust_zones=self._trust_zones,
            components=self._components,
            connections=self._connections,
            name=name,
            description=description,
            version="1.0"
        )


def build_dfd_from_parser(parser_output: Dict[str, Any], 
                         name: Optional[str] = None,
                         description: Optional[str] = None) -> DataFlowDiagram:
    """Factory function to build DFD from parser output"""
    return (DFDBuilder()
            .from_parser_output(parser_output)
            .build(name=name, description=description))


# Removed unused function analyze_security_boundaries - never called in codebase