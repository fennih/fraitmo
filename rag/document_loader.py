"""
Document loader for fraitmo knowledge base
Loads AI/LLM security threat documents from JSON files
Enhanced with vector store capabilities for semantic search
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from utils.console import console
from rich.text import Text



# Global vector store instance for caching
_vector_store_instance = None

def load_threat_knowledge_base(kb_path: str = "knowledge_base") -> List[Dict[str, Any]]:
    """
    Load threat knowledge base from JSON files

    Args:
        kb_path: Path to knowledge base directory

    Returns:
        List of threat documents with metadata
    """
    documents = []
    skipped_files = 0

    if not os.path.exists(kb_path):
        console.print(Text("[WARN]", style="bold yellow"), f"Knowledge base directory not found: {kb_path}")
        return documents

    kb_directory = Path(kb_path)
    json_files = list(kb_directory.glob("*.json"))

    if not json_files:
        console.print(Text("[WARN]", style="bold yellow"), f"No JSON files found in: {kb_path}")
        return documents

    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()

                if not content:
                    console.print(Text("[WARN]", style="bold yellow"), f"Skipping empty file: {json_file.name}")
                    skipped_files += 1
                    continue

                data = json.loads(content)

                # Handle different JSON structures
                if not data:
                    console.print(Text("[WARN]", style="bold yellow"), f"Skipping file with no content: {json_file.name}")
                    skipped_files += 1
                    continue

                # If it's a list, process each item
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and item:
                            doc = _process_threat_document(item, json_file.name)
                            if doc:
                                documents.append(doc)

                # If it's a single dict, process it
                elif isinstance(data, dict):
                    doc = _process_threat_document(data, json_file.name)
                    if doc:
                        documents.append(doc)

                else:
                    console.print(Text("[WARN]", style="bold yellow"), f"Skipping file with unexpected format: {json_file.name}")
                    skipped_files += 1
                    continue

        except json.JSONDecodeError as e:
            console.print(Text("[WARN]", style="bold yellow"), f"JSON parse error in {json_file.name}: {str(e)[:50]}...")
            skipped_files += 1
            continue
        except Exception as e:
            console.print(Text("[WARN]", style="bold yellow"), f"Error loading {json_file.name}: {str(e)[:50]}...")
            skipped_files += 1
            continue

    if skipped_files > 0:
        console.print(Text("[WARN]", style="bold yellow"), f"Skipped {skipped_files} problematic files")

    console.print(Text("[OK]", style="bold green"), f"Loaded {len(documents)} threat documents from {len(json_files)} files")

    return documents


def _process_threat_document(data: Dict[str, Any], filename: str) -> Optional[Dict[str, Any]]:
    """
    Process a single threat document and extract relevant information

    Args:
        data: Raw document data
        filename: Source filename for metadata

    Returns:
        Processed document or None if invalid
    """
    try:
        # Create a comprehensive text representation for search
        text_fields = []

        # Essential fields
        name = data.get('name', data.get('title', data.get('id', 'Unknown')))
        description = data.get('description', data.get('summary', ''))

        text_fields.append(f"Name: {name}")
        if description:
            text_fields.append(f"Description: {description}")

        # Category and classification
        category = data.get('category', data.get('type', ''))
        if category:
            text_fields.append(f"Category: {category}")

        # Severity and impact
        severity = data.get('severity', data.get('risk_level', ''))
        if severity:
            text_fields.append(f"Severity: {severity}")

        impact = data.get('impact', '')
        if impact:
            text_fields.append(f"Impact: {impact}")

        # Mitigation strategies
        mitigation = data.get('mitigation', data.get('mitigations', []))
        if mitigation:
            if isinstance(mitigation, list):
                text_fields.append(f"Mitigations: {'; '.join(mitigation)}")
            else:
                text_fields.append(f"Mitigation: {mitigation}")

        # Technical details
        technical_details = data.get('technical_details', data.get('details', ''))
        if technical_details:
            text_fields.append(f"Technical Details: {technical_details}")

        # Attack vectors
        attack_vectors = data.get('attack_vectors', data.get('vectors', []))
        if attack_vectors:
            if isinstance(attack_vectors, list):
                text_fields.append(f"Attack Vectors: {'; '.join(attack_vectors)}")
            else:
                text_fields.append(f"Attack Vectors: {attack_vectors}")

        # OWASP references
        owasp = data.get('owasp', data.get('owasp_reference', ''))
        if owasp:
            text_fields.append(f"OWASP: {owasp}")

        # CWE references
        cwe = data.get('cwe', data.get('cwe_id', ''))
        if cwe:
            text_fields.append(f"CWE: {cwe}")

        # Combine all text for searchable content
        searchable_text = ' '.join(text_fields)

        # Create processed document
        document = {
            'id': data.get('id', f"{filename}_{name}"),
            'name': name,
            'description': description,
            'category': category,
            'severity': severity,
            'impact': impact,
            'mitigation': mitigation,
            'technical_details': technical_details,
            'attack_vectors': attack_vectors,
            'owasp': owasp,
            'cwe': cwe,
            'ai_specific': data.get('ai_specific', False),  # Preserve AI-specific flag
            'affected_components': data.get('affected_components', []),  # Preserve affected components
            'source': data.get('source', filename),  # Preserve source information
            'searchable_text': searchable_text,
            'source_file': filename,
            'raw_data': data  # Keep original for reference
        }

        return document

    except Exception as e:
        console.print(Text("[WARN]", style="bold yellow"), f"Error processing document in {filename}: {e}")
        return None


def search_threats(documents: List[Dict[str, Any]], query: str, max_results: int = 10, use_vector_search: bool = True) -> List[Dict[str, Any]]:
    """
    Enhanced threat search with optional vector search capabilities

    Args:
        documents: List of threat documents (used for fallback)
        query: Search query
        max_results: Maximum number of results to return
        use_vector_search: Whether to use vector search (default: True)

    Returns:
        List of matching documents
    """
    if not query:
        return []

    # Try vector search first if enabled and available
    if use_vector_search and documents:
        try:
            vector_results = search_threats_vector(query, max_results, documents)
            if vector_results:
                console.print(Text("[OK]", style="bold green"), f"Vector search returned {len(vector_results)} results")
                return vector_results
        except Exception as e:
            console.print(Text("[WARN]", style="bold yellow"), f"Vector search failed, falling back to keyword: {e}")

    # Fallback to keyword search
    if not documents:
        return []

    query_lower = query.lower()
    matches = []

    for doc in documents:
        searchable_text = doc.get('searchable_text', '').lower()

        # Calculate simple relevance score
        score = 0
        query_terms = query_lower.split()

        for term in query_terms:
            if term in searchable_text:
                # Higher score for matches in name/title
                if term in doc.get('name', '').lower():
                    score += 3
                # Medium score for matches in description
                elif term in doc.get('description', '').lower():
                    score += 2
                # Base score for other matches
                else:
                    score += 1

        if score > 0:
            doc_copy = doc.copy()
            doc_copy['relevance_score'] = score
            matches.append(doc_copy)

    # Sort by relevance score (descending)
    matches.sort(key=lambda x: x['relevance_score'], reverse=True)

    console.print(Text("[INFO]", style="bold blue"), f"Keyword search returned {len(matches[:max_results])} results")
    return matches[:max_results]


def search_threats_vector(query: str, max_results: int = 10, documents: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """
    Vector-based semantic search for threats

    Args:
        query: Search query
        max_results: Maximum number of results to return
        documents: Optional documents to populate vector store if empty

    Returns:
        List of semantically similar documents
    """
    global _vector_store_instance

    try:
        # Initialize vector store if needed
        if _vector_store_instance is None:
            from rag.vector_store import ThreatVectorStore
            _vector_store_instance = ThreatVectorStore()

            # If vector store is empty and we have documents, populate it
            if _vector_store_instance.collection.count() == 0 and documents:
                console.print(Text("[INFO]", style="bold blue"), f"Populating vector store with {len(documents)} documents...")
                _vector_store_instance.add_documents(documents)

        # Perform vector search
        results = _vector_store_instance.search(query, max_results)

        return results

    except ImportError:
        console.print(Text("[WARN]", style="bold yellow"), "Vector search dependencies not available")
        return []
    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Vector search error: {e}")
        return []


def search_threats_hybrid(query: str, max_results: int = 10, documents: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """
    Hybrid search combining vector and keyword approaches

    Args:
        query: Search query
        max_results: Maximum number of results to return
        documents: Optional documents for fallback

    Returns:
        List of documents ranked by combined relevance
    """
    global _vector_store_instance

    try:
        # Initialize vector store if needed
        if _vector_store_instance is None:
            from rag.vector_store import ThreatVectorStore
            _vector_store_instance = ThreatVectorStore()

            if _vector_store_instance.collection.count() == 0 and documents:
                _vector_store_instance.add_documents(documents)

        # Use hybrid search from vector store
        results = _vector_store_instance.hybrid_search(query, max_results)

        console.print(Text("[OK]", style="bold green"), f"Hybrid search returned {len(results)} results")
        return results

    except ImportError:
        console.print(Text("[WARN]", style="bold yellow"), "Vector search dependencies not available, using keyword search")
        return search_threats(documents or [], query, max_results, use_vector_search=False)
    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Hybrid search error: {e}")
        # Fallback to keyword search
        return search_threats(documents or [], query, max_results, use_vector_search=False)


def get_vector_store_stats() -> Dict[str, Any]:
    """Get statistics about the vector store"""
    global _vector_store_instance

    try:
        if _vector_store_instance is None:
            return {"status": "not_initialized"}

        stats = _vector_store_instance.get_collection_stats()
        stats["status"] = "active"
        return stats

    except Exception as e:
        return {"status": "error", "error": str(e)}


def reset_vector_store() -> bool:
    """Reset the vector store (useful for testing or rebuilding)"""
    global _vector_store_instance

    try:
        if _vector_store_instance is not None:
            _vector_store_instance.reset_collection()
            console.print(Text("[OK]", style="bold green"), "Vector store reset successfully")
            return True
    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Failed to reset vector store: {e}")

    return False


def get_threat_by_id(documents: List[Dict[str, Any]], threat_id: str) -> Optional[Dict[str, Any]]:
    """
    Get a specific threat by ID

    Args:
        documents: List of threat documents
        threat_id: Threat identifier

    Returns:
        Threat document or None if not found
    """
    for doc in documents:
        if doc.get('id') == threat_id:
            return doc
    return None


def filter_threats_by_category(documents: List[Dict[str, Any]], category: str) -> List[Dict[str, Any]]:
    """
    Filter threats by category

    Args:
        documents: List of threat documents
        category: Category to filter by

    Returns:
        List of matching documents
    """
    if not category:
        return documents

    category_lower = category.lower()
    matches = []

    for doc in documents:
        doc_category = doc.get('category', '').lower()
        if category_lower in doc_category or doc_category in category_lower:
            matches.append(doc)

    return matches


def get_available_categories(documents: List[Dict[str, Any]]) -> List[str]:
    """
    Get all available threat categories

    Args:
        documents: List of threat documents

    Returns:
        List of unique categories
    """
    categories = set()

    for doc in documents:
        category = doc.get('category', '').strip()
        if category:
            categories.add(category)

    return sorted(list(categories))


if __name__ == "__main__":
    # Test the knowledge base loader
    docs = load_threat_knowledge_base()
    console.print(Text("[INFO]", style="bold blue"), f"Loaded {len(docs)} documents")

    if docs:
        # Test search
        results = search_threats(docs, "injection", 5)
        console.print(Text("[INFO]", style="bold blue"), f"Found {len(results)} results for 'injection'")

        # Show categories
        categories = get_available_categories(docs)
        console.print(Text("[INFO]", style="bold blue"), f"Available categories: {', '.join(categories)}")
