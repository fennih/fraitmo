# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FRAITMO (Framework for Robust AI Threat Modeling Operations) is a Python-based tool for automated threat modeling of AI/LLM systems. It parses Data Flow Diagrams (DFDs) from XML files, identifies AI and traditional components, and generates security threat assessments using local LLM providers.

## Common Development Commands

```bash
# Run threat analysis on a DFD file
python fraitmo.py diagram.xml

# Threats-only analysis (3x faster)
python fraitmo.py diagram.xml --threats

# Complete analysis with mitigations
python fraitmo.py diagram.xml --full-threat-modeling

# Generate mitigations from existing threat file
python fraitmo.py --mitigation threats.json

# Export results in different formats
python fraitmo.py diagram.xml --format json --output-dir ./reports
python fraitmo.py diagram.xml --format csv

# Filter by severity or component type
python fraitmo.py diagram.xml --severity critical
python fraitmo.py diagram.xml --component-type ai --severity high

# Validate DFD structure without analysis
python fraitmo.py diagram.xml --validate

# Dry run (test without execution)
python fraitmo.py diagram.xml --dry-run --threats

# Install dependencies
pip install -r requirements.txt
```

## Architecture Overview

### Core Components

- **fraitmo.py**: Main CLI entry point with argument parsing and result formatting
- **dfd_parser/**: XML parsing for Data Flow Diagrams (draw.io/IriusRisk format)
- **models/**: Pydantic schemas and semantic data models
- **rag/**: LLM client abstraction supporting LM Studio and Ollama
- **pipeline/**: LangGraph-based workflow orchestration with 9 specialized nodes
- **knowledge_base/**: Optional threat databases (ai_threats.json, infrastructure_threats.json, web_threats.json)
- **utils/**: Console utilities for Rich text output

### Pipeline Architecture

The system uses a dual-path LangGraph pipeline:

**Analysis Paths:**
1. **RAG Path**: Knowledge base search → threat matching → mitigation lookup
2. **LLM Path**: Direct LLM analysis → component-by-component threat assessment

**Key Nodes:**
- `ai_detector.py`: Identifies AI/LLM components automatically
- `llm_analyzer.py`: Performs direct threat analysis without knowledge base
- `rag_threat_searcher.py`: Vector-based threat search in knowledge bases
- `llm_quality_filter.py`: AI-powered deduplication and risk assessment
- `cross_component_analyzer.py`: Analyzes data flows between components

### LLM Provider Support

The system automatically detects and prioritizes local LLM providers:
1. **LM Studio** (localhost:1234) - Primary, optimized for Foundation-Sec models
2. **Ollama** (localhost:11434) - Fallback, supports various models

Recommended models: Foundation-Sec-8B, Cogito:14b, or any cybersecurity-focused model.

## File Structure Patterns

- Node files in `pipeline/nodes/` follow naming convention: `[rag_|llm_]function_name.py`
- All pipeline nodes use standard imports: `typing`, `utils.console`, `rich.text`
- State management handled through `pipeline/state.py` with unified schema
- Results exported via `exporter/export_results.py` in multiple formats

## Development Notes

- The system works entirely offline with local LLM providers
- No external API dependencies (OpenAI, etc.) - all processing is local
- Supports both AI-specific threats (prompt injection, model poisoning) and traditional security threats
- Uses ChromaDB for vector storage when knowledge bases are present
- Rich console output with progress bars and formatted results
- Graceful degradation when LLM providers are unavailable (--offline mode)

### Performance Optimizations (Latest)

- **Parallel Analysis**: Component analysis runs concurrently (4 workers max)
- **Smart Token Allocation**: Dynamic token allocation based on component complexity (700-1600 tokens)
- **Optimized Prompts**: Streamlined prompts for speed while maintaining quality
- **Enhanced Coverage**: Only enhance threats when truly necessary (coverage < 40%)
- **Cross-Component Parallelization**: Trust boundary, AI integration, and auth flow analysis run in parallel
- **Performance Monitoring**: Use `--verbose` to see parallel execution details

**Expected Performance**: ~4-7 minutes for typical analysis (vs previous 10+ minutes)

## Testing

Currently no formal test suite exists. Test individual components by running Python files directly:

```bash
# Test LLM client connectivity
python rag/llm_client.py

# Test individual pipeline nodes
python pipeline/nodes/llm_analyzer.py
python pipeline/nodes/rag_threat_searcher.py

# Test complete pipeline
python pipeline/workflows/threat_analysis.py
```

## Configuration

- `production-config.json`: Production settings template
- Command-line arguments override default behavior
- LLM provider detection is automatic with intelligent fallback
- Vector database stored in `vector_db/` directory (auto-created)