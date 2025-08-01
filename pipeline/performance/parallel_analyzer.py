"""
Parallel Analysis Module for FRAITMO
Provides concurrent execution of LLM analysis tasks to improve performance
"""

import asyncio
import concurrent.futures
from typing import Dict, Any, List, Callable, Optional
from utils.console import console
from rich.text import Text


class ParallelThreatAnalyzer:
    """Manages parallel execution of threat analysis tasks"""
    
    def __init__(self, max_workers: int = 4):
        """
        Initialize parallel analyzer
        
        Args:
            max_workers: Maximum number of concurrent LLM calls (default: 4)
                        Keep reasonable to avoid rate limits
        """
        self.max_workers = max_workers
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
    
    def analyze_components_parallel(self, 
                                  components: List[Dict[str, Any]], 
                                  analysis_function: Callable,
                                  component_type: str) -> List[Dict[str, Any]]:
        """
        Analyze multiple components in parallel
        
        Args:
            components: List of components to analyze
            analysis_function: Function to call for each component
            component_type: 'ai' or 'traditional' for logging
            
        Returns:
            Combined list of all threats from all components
        """
        if not components:
            return []
        
        console.print_debug(Text("[PERF]", style="bold cyan"), 
                          f"Starting parallel analysis of {len(components)} {component_type} components")
        
        # Submit all tasks concurrently
        futures = []
        for component in components:
            future = self.executor.submit(analysis_function, component)
            futures.append((future, component.get('name', 'Unknown')))
        
        # Collect results as they complete
        all_threats = []
        completed = 0
        
        for future, comp_name in futures:
            try:
                threats = future.result(timeout=300)  # 5 minute timeout per component
                all_threats.extend(threats)
                completed += 1
                
                console.print_debug(Text("[PERF]", style="dim green"), 
                                  f"✅ {comp_name} complete ({completed}/{len(components)}) - {len(threats)} threats")
                
            except concurrent.futures.TimeoutError:
                console.print(Text("[WARN]", style="bold yellow"), 
                            f"Analysis timeout for {comp_name} - skipping")
            except Exception as e:
                console.print(Text("[WARN]", style="bold yellow"), 
                            f"Analysis failed for {comp_name}: {e}")
        
        console.print(Text("[PERF]", style="bold green"), 
                     f"Parallel {component_type} analysis complete: {len(all_threats)} total threats")
        
        return all_threats
    
    def analyze_cross_components_parallel(self, 
                                        analysis_tasks: List[Dict[str, Any]], 
                                        analysis_function: Callable) -> List[Dict[str, Any]]:
        """
        Analyze cross-component relationships in parallel
        
        Args:
            analysis_tasks: List of analysis task dictionaries
            analysis_function: Function to call for each task
            
        Returns:
            Combined list of all cross-component threats
        """
        if not analysis_tasks:
            return []
        
        console.print_debug(Text("[PERF]", style="bold cyan"), 
                          f"Starting parallel cross-component analysis of {len(analysis_tasks)} tasks")
        
        # Submit all cross-component tasks concurrently
        futures = []
        for task in analysis_tasks:
            future = self.executor.submit(analysis_function, task)
            task_name = f"{task.get('source', 'Unknown')}→{task.get('target', 'Unknown')}"
            futures.append((future, task_name))
        
        # Collect results
        all_threats = []
        completed = 0
        
        for future, task_name in futures:
            try:
                threats = future.result(timeout=200)  # 3.3 minute timeout per cross-analysis
                all_threats.extend(threats)
                completed += 1
                
                console.print_debug(Text("[PERF]", style="dim green"), 
                                  f"✅ {task_name} complete ({completed}/{len(analysis_tasks)}) - {len(threats)} threats")
                
            except concurrent.futures.TimeoutError:
                console.print(Text("[WARN]", style="bold yellow"), 
                            f"Cross-analysis timeout for {task_name} - skipping")
            except Exception as e:
                console.print(Text("[WARN]", style="bold yellow"), 
                            f"Cross-analysis failed for {task_name}: {e}")
        
        console.print(Text("[PERF]", style="bold green"), 
                     f"Parallel cross-component analysis complete: {len(all_threats)} total threats")
        
        return all_threats
    
    def batch_coverage_validation(self, 
                                 component_threat_pairs: List[tuple], 
                                 validation_function: Callable) -> List[Dict[str, Any]]:
        """
        Perform coverage validation in parallel batches
        
        Args:
            component_threat_pairs: List of (component, threats) tuples
            validation_function: Coverage validation function
            
        Returns:
            List of validation reports
        """
        if not component_threat_pairs:
            return []
        
        console.print_debug(Text("[PERF]", style="bold cyan"), 
                          f"Starting parallel coverage validation for {len(component_threat_pairs)} components")
        
        # Submit validation tasks
        futures = []
        for component, threats in component_threat_pairs:
            future = self.executor.submit(validation_function, threats, component)
            comp_name = component.get('name', 'Unknown')
            futures.append((future, comp_name))
        
        # Collect validation reports
        validation_reports = []
        
        for future, comp_name in futures:
            try:
                report = future.result(timeout=60)  # 1 minute timeout per validation
                validation_reports.append(report)
                
                console.print_debug(Text("[PERF]", style="dim green"), 
                                  f"✅ Coverage validation complete for {comp_name}")
                
            except concurrent.futures.TimeoutError:
                console.print(Text("[WARN]", style="bold yellow"), 
                            f"Coverage validation timeout for {comp_name}")
            except Exception as e:
                console.print(Text("[WARN]", style="bold yellow"), 
                            f"Coverage validation failed for {comp_name}: {e}")
        
        return validation_reports
    
    def shutdown(self):
        """Cleanup executor resources"""
        self.executor.shutdown(wait=True)
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()


def optimize_token_allocation(components: List[Dict[str, Any]], 
                            base_tokens: int = 800, 
                            max_tokens: int = 1800) -> Dict[str, int]:
    """
    Optimize token allocation across components based on complexity
    Balances quality vs speed by reducing tokens for simpler components
    
    Args:
        components: List of components to analyze
        base_tokens: Minimum tokens per component
        max_tokens: Maximum tokens per component
        
    Returns:
        Dictionary mapping component names to optimal token counts
    """
    token_allocation = {}
    
    for component in components:
        comp_name = component.get('name', 'Unknown')
        comp_type = component.get('type', '').lower()
        
        # Complexity factors (simplified from original)
        complexity_factors = []
        
        # Component type complexity
        if any(db_type in comp_type for db_type in ['database', 'db', 'postgres', 'mysql']):
            complexity_factors.append(2)  # Databases are complex
        elif any(api_type in comp_type for api_type in ['api', 'gateway', 'service']):
            complexity_factors.append(1.5)  # APIs are moderately complex
        elif any(simple_type in comp_type for simple_type in ['file', 'storage', 'cache']):
            complexity_factors.append(0.5)  # Simple components
        else:
            complexity_factors.append(1)  # Default complexity
        
        # AI complexity
        if component.get('ai_type'):
            complexity_factors.append(1.5)  # AI components need more analysis
        
        # Calculate final complexity score
        complexity_score = sum(complexity_factors)
        
        # Optimize token allocation with reasonable limits
        # Reduced multiplier to balance quality vs speed
        optimal_tokens = int(base_tokens + (complexity_score * 150))  # Reduced from 200-300
        optimal_tokens = min(optimal_tokens, max_tokens)  # Cap at max_tokens
        optimal_tokens = max(optimal_tokens, base_tokens)  # Ensure minimum
        
        token_allocation[comp_name] = optimal_tokens
    
    console.print_debug(Text("[PERF]", style="dim blue"), 
                      f"Optimized token allocation: avg {sum(token_allocation.values()) // len(token_allocation)} tokens/component")
    
    return token_allocation


def should_skip_enhancement(coverage_score: float, threat_count: int, component_type: str) -> bool:
    """
    Intelligent decision on whether to skip coverage enhancement to save time
    
    Args:
        coverage_score: Coverage validation score (0.0-1.0)
        threat_count: Number of threats found
        component_type: Type of component being analyzed
        
    Returns:
        True if enhancement should be skipped for performance
    """
    # More lenient thresholds to reduce unnecessary enhancement calls
    if component_type == 'ai':
        # For AI components, accept lower thresholds but require minimum threats
        return coverage_score >= 0.35 and threat_count >= 3
    else:
        # For traditional components, slightly higher threshold
        return coverage_score >= 0.40 and threat_count >= 4


def batch_components_intelligently(components: List[Dict[str, Any]], 
                                 batch_size: int = 3) -> List[List[Dict[str, Any]]]:
    """
    Create intelligent batches of components for parallel processing
    Groups similar complexity components together
    
    Args:
        components: List of components to batch
        batch_size: Target size for each batch
        
    Returns:
        List of component batches
    """
    if not components:
        return []
    
    # Sort components by estimated complexity (simple heuristic)
    def complexity_estimate(comp):
        comp_type = comp.get('type', '').lower()
        ai_bonus = 2 if comp.get('ai_type') else 0
        
        if 'database' in comp_type:
            return 4 + ai_bonus
        elif 'api' in comp_type:
            return 3 + ai_bonus
        elif any(web_type in comp_type for web_type in ['web', 'ui', 'frontend']):
            return 2 + ai_bonus
        else:
            return 1 + ai_bonus
    
    # Sort by complexity (high first) for better load balancing
    sorted_components = sorted(components, key=complexity_estimate, reverse=True)
    
    # Create batches
    batches = []
    for i in range(0, len(sorted_components), batch_size):
        batch = sorted_components[i:i + batch_size]
        batches.append(batch)
    
    console.print_debug(Text("[PERF]", style="dim blue"), 
                      f"Created {len(batches)} batches with avg {len(components) // len(batches)} components each")
    
    return batches