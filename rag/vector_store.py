"""
Vector Store for FRAITMO Knowledge Base
Handles ChromaDB integration and semantic search using embeddings
"""

import os
import uuid
from typing import List, Dict, Any, Optional, Union
from pathlib import Path

import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
import numpy as np
from utils.console import console
from rich.text import Text



class ThreatVectorStore:
    """
    Vector store for threat knowledge base using ChromaDB and sentence transformers
    Provides semantic search capabilities for threat documents
    """

    def __init__(self,
                 collection_name: str = "fraitmo_threats",
                 model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
                 persist_directory: str = "vector_db"):
        """
        Initialize the vector store

        Args:
            collection_name: Name of ChromaDB collection
            model_name: SentenceTransformer model name
            persist_directory: Directory for ChromaDB persistence
        """
        self.collection_name = collection_name
        self.model_name = model_name
        self.persist_directory = persist_directory

        # Initialize embedding model
        try:
            console.print(Text("[INFO]", style="bold blue"), f"Loading embedding model: {model_name}")
            self.embedding_model = SentenceTransformer(model_name)
            console.print(Text("[OK]", style="bold green"), "Embedding model loaded successfully")
        except Exception as e:
            console.print(Text("[ERROR]", style="bold red"), f"Failed to load embedding model: {e}")
            raise e

        # Initialize ChromaDB
        self._init_chromadb()

    def _init_chromadb(self):
        """Initialize ChromaDB client and collection"""
        try:
            # Create persist directory if it doesn't exist
            os.makedirs(self.persist_directory, exist_ok=True)

            # Initialize ChromaDB with persistence
            self.client = chromadb.PersistentClient(
                path=self.persist_directory,
                settings=Settings(
                    anonymized_telemetry=False,
                    allow_reset=True
                )
            )

            # Get or create collection
            try:
                self.collection = self.client.get_collection(
                    name=self.collection_name
                )
                console.print(Text("[OK]", style="bold green"), f"Loaded existing collection: {self.collection_name}")
                console.print(Text("[INFO]", style="bold blue"), f"Collection contains {self.collection.count()} documents")
            except Exception:
                # Collection doesn't exist, create it
                self.collection = self.client.create_collection(
                    name=self.collection_name,
                    metadata={"description": "FRAITMO threat knowledge base"}
                )
                console.print(Text("[OK]", style="bold green"), f"Created new collection: {self.collection_name}")

        except Exception as e:
            console.print(Text("[ERROR]", style="bold red"), f"Failed to initialize ChromaDB: {e}")
            raise e

    def add_documents(self, documents: List[Dict[str, Any]]) -> None:
        """
        Add documents to the vector store

        Args:
            documents: List of threat documents with metadata
        """
        if not documents:
            console.print(Text("[WARN]", style="bold yellow"), "No documents to add")
            return

        console.print(Text("[INFO]", style="bold blue"), f"Adding {len(documents)} documents to vector store...")

        # Prepare data for ChromaDB
        ids = []
        embeddings = []
        metadatas = []
        documents_text = []

        for doc in documents:
            # Generate unique ID
            doc_id = doc.get('id', str(uuid.uuid4()))
            ids.append(doc_id)

            # Extract searchable text for embedding
            searchable_text = doc.get('searchable_text', '')
            if not searchable_text:
                # Fallback: create searchable text from key fields
                text_parts = []
                for field in ['name', 'description', 'category', 'severity', 'technical_details']:
                    value = doc.get(field, '')
                    if value:
                        text_parts.append(str(value))
                searchable_text = ' '.join(text_parts)

            documents_text.append(searchable_text)

            # Create embedding
            try:
                embedding = self.embedding_model.encode(searchable_text).tolist()
                embeddings.append(embedding)
            except Exception as e:
                console.print(Text("[WARN]", style="bold yellow"), f"Failed to embed document {doc_id}: {e}")
                continue

            # Prepare metadata (ChromaDB requires string values)
            metadata = {
                'name': str(doc.get('name', '')),
                'category': str(doc.get('category', '')),
                'severity': str(doc.get('severity', '')),
                'source_file': str(doc.get('source_file', '')),
                'impact': str(doc.get('impact', '')),
                'owasp': str(doc.get('owasp', '')),
                'cwe': str(doc.get('cwe', ''))
            }
            metadatas.append(metadata)

        # Add to ChromaDB collection
        try:
            self.collection.add(
                ids=ids,
                embeddings=embeddings,
                metadatas=metadatas,
                documents=documents_text
            )
            console.print(Text("[OK]", style="bold green"), f"Successfully added {len(ids)} documents to vector store")
        except Exception as e:
            console.print(Text("[ERROR]", style="bold red"), f"Failed to add documents to ChromaDB: {e}")
            raise e

    def search(self,
               query: str,
               max_results: int = 10,
               filter_metadata: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """
        Search for relevant documents using semantic similarity

        Args:
            query: Search query
            max_results: Maximum number of results to return
            filter_metadata: Optional metadata filters

        Returns:
            List of relevant documents with similarity scores
        """
        if not query.strip():
            return []

        try:
            # Create query embedding
            query_embedding = self.embedding_model.encode(query).tolist()

            # Search in ChromaDB
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=max_results,
                where=filter_metadata if filter_metadata else None,
                include=['metadatas', 'documents', 'distances']
            )

            # Process results
            search_results = []
            for i in range(len(results['ids'][0])):
                doc_result = {
                    'id': results['ids'][0][i],
                    'text': results['documents'][0][i],
                    'metadata': results['metadatas'][0][i],
                    'similarity_score': 1 - results['distances'][0][i],  # Convert distance to similarity
                    'relevance_score': max(0, 1 - results['distances'][0][i])  # Ensure positive
                }

                # Add original document fields from metadata
                doc_result.update({
                    'name': doc_result['metadata'].get('name', ''),
                    'category': doc_result['metadata'].get('category', ''),
                    'severity': doc_result['metadata'].get('severity', ''),
                    'description': doc_result['text'],  # Use full document text as description
                    'source_file': doc_result['metadata'].get('source_file', '')
                })

                search_results.append(doc_result)

            console.print(Text("[OK]", style="bold green"), f"Found {len(search_results)} relevant documents")
            return search_results

        except Exception as e:
            console.print(Text("[ERROR]", style="bold red"), f"Search failed: {e}")
            return []

    def search_by_category(self, category: str, max_results: int = 10) -> List[Dict[str, Any]]:
        """Search documents by category"""
        return self.search(
            query=category,
            max_results=max_results,
            filter_metadata={"category": category}
        )

    def search_by_severity(self, severity: str, max_results: int = 10) -> List[Dict[str, Any]]:
        """Search documents by severity level"""
        return self.search(
            query=f"{severity} severity threats",
            max_results=max_results,
            filter_metadata={"severity": severity}
        )

    def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about the vector store collection"""
        try:
            count = self.collection.count()

            # Get sample of documents to analyze categories/severities
            sample_results = self.collection.get(limit=min(count, 100), include=['metadatas'])

            categories = set()
            severities = set()

            for metadata in sample_results['metadatas']:
                if metadata.get('category'):
                    categories.add(metadata['category'])
                if metadata.get('severity'):
                    severities.add(metadata['severity'])

            return {
                'total_documents': count,
                'categories': sorted(list(categories)),
                'severities': sorted(list(severities)),
                'embedding_model': self.model_name,
                'collection_name': self.collection_name
            }
        except Exception as e:
            console.print(Text("[ERROR]", style="bold red"), f"Failed to get collection stats: {e}")
            return {}

    def reset_collection(self) -> None:
        """Reset the collection (delete all documents)"""
        try:
            self.client.delete_collection(self.collection_name)
            self.collection = self.client.create_collection(
                name=self.collection_name,
                metadata={"description": "FRAITMO threat knowledge base"}
            )
            console.print(Text("[OK]", style="bold green"), f"Collection {self.collection_name} reset successfully")
        except Exception as e:
            console.print(Text("[ERROR]", style="bold red"), f"Failed to reset collection: {e}")

    def hybrid_search(self,
                     query: str,
                     max_results: int = 10,
                     semantic_weight: float = 0.7) -> List[Dict[str, Any]]:
        """
        Hybrid search combining semantic similarity with keyword matching

        Args:
            query: Search query
            max_results: Maximum number of results
            semantic_weight: Weight for semantic vs keyword results (0.0-1.0)

        Returns:
            Combined results from semantic and keyword search
        """
        # Get semantic results
        semantic_results = self.search(query, max_results * 2)  # Get more for mixing

        # Simple keyword scoring for hybrid approach
        query_terms = query.lower().split()

        for result in semantic_results:
            text_lower = result['text'].lower()
            keyword_score = 0

            for term in query_terms:
                if term in text_lower:
                    # More weight for exact matches in important fields
                    if term in result.get('name', '').lower():
                        keyword_score += 3
                    elif term in result.get('category', '').lower():
                        keyword_score += 2
                    else:
                        keyword_score += 1

            # Normalize keyword score
            keyword_score = min(keyword_score / (len(query_terms) * 3), 1.0)

            # Combine scores
            combined_score = (semantic_weight * result['similarity_score'] +
                            (1 - semantic_weight) * keyword_score)
            result['combined_score'] = combined_score
            result['keyword_score'] = keyword_score

        # Sort by combined score and return top results
        hybrid_results = sorted(semantic_results, key=lambda x: x['combined_score'], reverse=True)
        return hybrid_results[:max_results]


def test_vector_store():
    """Test the vector store implementation"""
    console.print(Text("[INFO]", style="bold blue"), "Testing Vector Store...")

    # Sample test documents
    test_documents = [
        {
            'id': 'test_1',
            'name': 'SQL Injection',
            'category': 'Web Application',
            'severity': 'High',
            'description': 'Attacker can execute arbitrary SQL commands through user input',
            'searchable_text': 'SQL Injection Web Application High severity database attack user input'
        },
        {
            'id': 'test_2',
            'name': 'Prompt Injection',
            'category': 'AI Security',
            'severity': 'Critical',
            'description': 'Malicious prompts can manipulate LLM behavior and outputs',
            'searchable_text': 'Prompt Injection AI Security Critical LLM manipulation malicious input'
        }
    ]

    try:
        # Initialize vector store
        vs = ThreatVectorStore(collection_name="test_collection")

        # Reset for clean test
        vs.reset_collection()

        # Add test documents
        vs.add_documents(test_documents)

        # Test semantic search
        results = vs.search("database security vulnerability", max_results=5)
        console.print(Text("[INFO]", style="bold blue"), f"Search results: {len(results)}")
        for result in results:
            console.print(f"  - {result['name']} (score: {result['similarity_score']:.3f})")

        # Test hybrid search
        hybrid_results = vs.hybrid_search("SQL database attack", max_results=3)
        console.print(Text("[INFO]", style="bold blue"), f"Hybrid search results: {len(hybrid_results)}")
        for result in hybrid_results:
            console.print(f"  - {result['name']} (combined: {result['combined_score']:.3f})")

        # Get stats
        stats = vs.get_collection_stats()
        console.print(Text("[OK]", style="bold green"), f"Collection stats: {stats}")

        console.print(Text("[OK]", style="bold green"), "Vector store test completed successfully!")

    except Exception as e:
        console.print(Text("[ERROR]", style="bold red"), f"Vector store test failed: {e}")


if __name__ == "__main__":
    test_vector_store()
