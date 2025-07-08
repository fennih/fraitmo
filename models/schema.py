from typing import List, Dict, Optional, Set
from pydantic import BaseModel, Field, validator
from enum import Enum
import re


class TrustZoneType(str, Enum):
    """Trust zone types"""
    INTERNAL = "internal"
    EXTERNAL_TRUSTED = "external_trusted"
    EXTERNAL_PUBLIC = "external_public"
    UNKNOWN = "unknown"


class ComponentCategory(str, Enum):
    """Component categories"""
    API = "api"
    DATABASE = "database"
    CACHE = "cache"
    UI = "ui"
    COMPUTE = "compute"
    AI_ML = "ai_ml"
    EXTERNAL_SERVICE = "external_service"
    UNKNOWN = "unknown"


class TrustZone(BaseModel):
    """Represents a security zone"""
    id: str
    name: str
    zone_type: TrustZoneType = TrustZoneType.UNKNOWN
    
    @validator('zone_type', pre=True)
    def infer_zone_type(cls, v, values):
        if v != TrustZoneType.UNKNOWN:
            return v
            
        name = values.get('name', '').lower()
        if 'managed' in name or 'aws managed' in name:
            return TrustZoneType.INTERNAL
        elif name in ['internet', 'public']:
            return TrustZoneType.EXTERNAL_PUBLIC
        elif 'openai' in name or 'langchain' in name:
            return TrustZoneType.EXTERNAL_TRUSTED
        return TrustZoneType.UNKNOWN
    
    class Config:
        use_enum_values = True


class Component(BaseModel):
    """Represents a system component"""
    id: str
    name: str
    component_type: str = "Unknown"
    component_category: ComponentCategory = ComponentCategory.UNKNOWN
    trust_zone_id: str
    trust_zone_name: str = ""
    
    # Simple metadata
    description: Optional[str] = None
    tags: Set[str] = Field(default_factory=set)
    vendor: Optional[str] = None  # Only AWS or OpenAI
    
    @validator('component_category', pre=True, always=True)
    def classify_component(cls, v, values):
        if v != ComponentCategory.UNKNOWN:
            return v
            
        comp_type = values.get('component_type', '').lower()
        name = values.get('name', '').lower()
        
        if 'api' in comp_type or 'endpoint' in comp_type:
            return ComponentCategory.API
        elif 'aurora' in comp_type or 'database' in comp_type:
            return ComponentCategory.DATABASE
        elif 'cache' in comp_type or 'redis' in comp_type:
            return ComponentCategory.CACHE
        elif 'ui' in comp_type or 'mobile' in comp_type:
            return ComponentCategory.UI
        elif 'ecs' in comp_type or 'container' in comp_type:
            return ComponentCategory.COMPUTE
        elif 'llm' in comp_type or 'ai' in comp_type or 'openai' in name:
            return ComponentCategory.AI_ML
        elif 'saas' in comp_type or 'external' in name:
            return ComponentCategory.EXTERNAL_SERVICE
        
        return ComponentCategory.UNKNOWN
    
    @validator('vendor', pre=True, always=True)
    def extract_vendor(cls, v, values):
        if v:
            return v
            
        comp_type = values.get('component_type', '').lower()
        name = values.get('name', '').lower()
        
        if 'aws' in comp_type or 'aurora' in comp_type or 'ecs' in comp_type:
            return 'aws'
        elif 'openai' in name or 'openai' in comp_type:
            return 'openai'
        
        return None
    
    @property
    def is_external(self) -> bool:
        external_zones = ['openai', 'internet', 'langchain', 'external']
        return any(zone in self.trust_zone_name.lower() for zone in external_zones)
    
    @property
    def is_aws_service(self) -> bool:
        return self.vendor == 'aws'
    
    @property
    def is_ai_service(self) -> bool:
        return self.component_category == ComponentCategory.AI_ML
    
    class Config:
        use_enum_values = True


class Connection(BaseModel):
    """Represents a connection between components"""
    source_id: str
    source_name: str
    target_id: str  
    target_name: str
    
    connection_type: Optional[str] = None
    is_bidirectional: bool = False
    
    def __hash__(self):
        return hash((self.source_id, self.target_id))


class DataFlowDiagram(BaseModel):
    """Complete Data Flow Diagram model"""
    trust_zones: Dict[str, TrustZone] = Field(default_factory=dict)
    components: Dict[str, Component] = Field(default_factory=dict)
    connections: List[Connection] = Field(default_factory=list)
    
    name: Optional[str] = None
    description: Optional[str] = None
    version: Optional[str] = None
    
    @validator('connections')
    def validate_connections(cls, connections, values):
        components = values.get('components', {})
        
        valid_connections = []
        for conn in connections:
            if conn.source_id in components and conn.target_id in components:
                valid_connections.append(conn)
        
        return valid_connections
    
    def get_component_by_name(self, name: str) -> Optional[Component]:
        for comp in self.components.values():
            if comp.name == name:
                return comp
        return None
    
    def get_external_components(self) -> List[Component]:
        return [comp for comp in self.components.values() if comp.is_external]
    
    def get_aws_components(self) -> List[Component]:
        return [comp for comp in self.components.values() if comp.is_aws_service]
    
    @property
    def cross_zone_connections(self) -> List[Connection]:
        cross_zone = []
        for conn in self.connections:
            source_comp = self.components.get(conn.source_id)
            target_comp = self.components.get(conn.target_id)
            
            if (source_comp and target_comp and 
                source_comp.trust_zone_id != target_comp.trust_zone_id):
                cross_zone.append(conn)
        
        return cross_zone
    
    class Config:
        use_enum_values = True
