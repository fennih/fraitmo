"""
Document loader for fraitmo knowledge base
Loads AI/LLM security threat documents from JSON files
"""

import json
import os
from typing import List, Dict, Optional
from pathlib import Path


def load_knowledge_base(kb_path: str = "knowledge_base") -> List[Dict]:
    """
    Load all JSON documents from the knowledge base
    
    Args:
        kb_path: Path to the knowledge base directory
        
    Returns:
        List of loaded documents
    """
    docs = []
    kb_directory = Path(kb_path)
    
    if not kb_directory.exists():
        print(f"⚠️ Knowledge base directory not found: {kb_path}")
        return docs
    
    json_files = list(kb_directory.glob("*.json"))
    
    if not json_files:
        print(f"⚠️ No JSON files found in: {kb_path}")
        return docs
    
    loaded_files = 0
    skipped_files = 0
    
    for json_file in json_files:
        try:
            # Check if file is empty first
            if json_file.stat().st_size == 0:
                print(f"⚠️ Skipping empty file: {json_file.name}")
                skipped_files += 1
                continue
                
            with open(json_file, 'r', encoding='utf-8') as f:
                content = json.load(f)
                
                # Skip empty/null content
                if not content:
                    print(f"⚠️ Skipping file with no content: {json_file.name}")
                    skipped_files += 1
                    continue
                    
                # If it's a list, extend
                if isinstance(content, list):
                    docs.extend(content)
                # If it's a dict, add as single document
                elif isinstance(content, dict):
                    docs.append(content)
                else:
                    print(f"⚠️ Skipping file with unexpected format: {json_file.name}")
                    skipped_files += 1
                    continue
                        
            loaded_files += 1
            
        except json.JSONDecodeError as e:
            print(f"⚠️ JSON parse error in {json_file.name}: {str(e)[:50]}...")
            skipped_files += 1
        except Exception as e:
            print(f"⚠️ Error loading {json_file.name}: {str(e)[:50]}...")
            skipped_files += 1
    
    # Clean summary
    print(f"📚 Knowledge base loaded: {loaded_files} files, {len(docs)} documents")
    if skipped_files > 0:
        print(f"⚠️ Skipped {skipped_files} problematic files")
    
    return docs


def get_knowledge_base_stats(kb_path: str = "knowledge_base") -> Dict[str, any]:
    """
    Get statistics about the knowledge base
    
    Args:
        kb_path: Path to the knowledge base directory
        
    Returns:
        Dictionary with KB statistics
    """
    kb_directory = Path(kb_path)
    
    if not kb_directory.exists():
        return {"error": f"Directory not found: {kb_path}"}
    
    json_files = list(kb_directory.glob("*.json"))
    total_files = len(json_files)
    valid_files = 0
    empty_files = 0
    corrupted_files = 0
    total_documents = 0
    
    for json_file in json_files:
        try:
            if json_file.stat().st_size == 0:
                empty_files += 1
                continue
                
            with open(json_file, 'r', encoding='utf-8') as f:
                content = json.load(f)
                
                if not content:
                    empty_files += 1
                    continue
                    
                valid_files += 1
                
                if isinstance(content, list):
                    total_documents += len(content)
                elif isinstance(content, dict):
                    total_documents += 1
                    
        except json.JSONDecodeError:
            corrupted_files += 1
        except Exception:
            corrupted_files += 1
    
    return {
        "total_files": total_files,
        "valid_files": valid_files,
        "empty_files": empty_files,
        "corrupted_files": corrupted_files,
        "total_documents": total_documents,
        "success_rate": f"{(valid_files/total_files*100):.1f}%" if total_files > 0 else "0%"
    }


def search_documents(docs: List[Dict], query: str, max_results: int = 5) -> List[Dict]:
    """
    Search for relevant documents based on keyword matching
    
    Args:
        docs: List of documents
        query: Search query
        max_results: Maximum number of results
        
    Returns:
        List of relevant documents
    """
    relevant_docs = []
    query_lower = query.lower()
    query_keywords = query_lower.split()
    
    for doc in docs:
        score = 0
        
        # Search in various parts of the document
        searchable_text = [
            doc.get('name', ''),
            doc.get('description', ''),
            doc.get('category', ''),
            ' '.join(doc.get('impact', [])),
            doc.get('example', ''),
            ' '.join(doc.get('mitigation', []))
        ]
        
        combined_text = ' '.join(searchable_text).lower()
        
        # Calculate score based on keyword matches
        for keyword in query_keywords:
            if keyword in combined_text:
                score += combined_text.count(keyword)
        
        if score > 0:
            doc_with_score = doc.copy()
            doc_with_score['_relevance_score'] = score
            relevant_docs.append(doc_with_score)
    
    # Sort by relevance score
    relevant_docs.sort(key=lambda x: x['_relevance_score'], reverse=True)
    
    return relevant_docs[:max_results]


def format_document(doc: Dict) -> str:
    """
    Format a document for prompt context
    
    Args:
        doc: Document to format
        
    Returns:
        Formatted string
    """
    formatted = f"ID: {doc.get('id', 'N/A')}\n"
    formatted += f"Name: {doc.get('name', 'N/A')}\n"
    formatted += f"Description: {doc.get('description', 'N/A')}\n"
    formatted += f"Category: {doc.get('category', 'N/A')}\n"
    
    if doc.get('impact'):
        formatted += f"Impact: {', '.join(doc['impact'])}\n"
    
    if doc.get('example'):
        formatted += f"Example: {doc['example']}\n"
    
    if doc.get('mitigation'):
        formatted += f"Mitigation: {', '.join(doc['mitigation'])}\n"
    
    return formatted 