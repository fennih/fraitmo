
# FRAITMO - Framework for Robut AI Threat Modeling Operations

A modular framework to automate threat modeling for Agentic AI / LLM-based systems.  
It parses DFDs, builds semantic models, leverages GPT-4 and Retrieval-Augmented Generation (RAG) to identify and contextualize threats, and produces a documented threat model.

---

## 🎯 Objectives

- Parse DFD diagrams (XML format from draw.io or IriusRisk)
- Extract components, connections, and trust boundaries
- Build a semantic representation of the architecture
- Generate context-aware questions to explore risks
- Use RAG to retrieve relevant threats from a structured KB
- Use GPT-4 to validate and contextualize threats and mitigations
- Export a structured threat model in Markdown or JSON format

---

## 📂 Project Structure (simplified, LangGraph-based)

```
agentic-threat-modeler/
├── fraitmo.py                     # CLI entry point – runs the full pipeline
├── .env                           # API key (OpenAI, etc.)
├── requirements.txt
│
├── dfd_parser/                    # Parse DFD XML
│   └── xml_parser.py
│
├── architecture_model/            # Semantic model builder
│   ├── builder.py
│   └── schema.py
│
├── rag_engine/                    # Semantic reasoning + RAG
│   ├── summarizer.py
│   ├── questionnaire.py
│   ├── threat_surface.py
│   ├── retriever.py
│   └── threat_mitigator.py
│
├── kb/
│   └── threats.jsonl              # Knowledge base for retrieval
│
├── pipeline/
│   ├── graph.py                   # LangGraph pipeline definition
│   └── state.py                   # Shared state schema
│
├── exporter/
│   ├── json_exporter.py
│   └── markdown_exporter.py
│
└── utils/
    ├── io.py
    └── log.py
```

---

## 🧠 Technologies Used

- **Python 3.9+**
- **LangChain** – LLM interfaces, RetrievalQA, vector store retriever
- **LangGraph** – modular pipeline orchestration (state graph)
- **OpenAI GPT-4** – for summarization, reasoning, threat generation
- **Chroma / FAISS** – vector database for threat KB
- **Pydantic** – architecture model validation
- **JSONL** – threat knowledge base format
- **Markdown / JSON** – export formats

---

## 🗺️ Roadmap

- [x] Parse and normalize DFD diagrams
- [x] Build a semantic model from architecture
- [x] Generate context-based questions from components
- [x] Integrate KB and RAG-based threat matching
- [x] GPT-based reasoning over threat surfaces
- [x] Output generation (Markdown, JSON)
- [ ] Add scoring (DREAD / STRIDE)
- [ ] Implement interactive loop for user feedback
- [ ] Add Streamlit UI (optional)
- [ ] Add PDF export (optional)

---

## 🔜 Next Steps

1. Implement LangGraph nodes with working LangChain chains:
   - `summarizer`, `questionnaire`, `threat_mitigator`
2. Build and test `graph.py` to orchestrate full pipeline
3. Populate `threats.jsonl` with OWASP LLM + MITRE ATLAS examples
4. Finalize export formats and I/O validation
5. Iterate on prompts and refine threat output quality

---
