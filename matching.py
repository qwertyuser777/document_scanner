import os
from Levenshtein import distance as levenshtein_distance
from PyPDF2 import PdfReader
import spacy

# Load spaCy model
nlp = spacy.load('en_core_web_md')
DOC_CACHE = {}

def extract_text(filepath):
    """Extract text from a file based on its type."""
    ext = os.path.splitext(filepath)[1].lower()
    try:
        if ext == '.txt':
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        elif ext == '.pdf':
            reader = PdfReader(filepath)
            text = ""
            for page in reader.pages:
                text += page.extract_text() or ""
            return text
        else:
            return ""
    except Exception as e:
        print(f"Error extracting text from {filepath}: {e}")
        return ""

def find_similar_documents(new_text, db_session, Document, user_id, use_ai=False):
    """Find documents similar to the given text."""
    if not new_text:
        return []
    docs = db_session.query(Document).filter_by(user_id=user_id).all()
    matches = []

    if use_ai:
        print("Using AI (spaCy) matching")  # Debug log
        new_doc = nlp(new_text)
        for doc in docs:
            if doc.filepath in DOC_CACHE:
                doc_nlp = DOC_CACHE[doc.filepath]
            else:
                doc_text = extract_text(doc.filepath)
                if doc_text:
                    doc_nlp = nlp(doc_text)
                    DOC_CACHE[doc.filepath] = doc_nlp
                else:
                    continue
            similarity = new_doc.similarity(doc_nlp)
            print(f"AI Similarity {doc.filename}: {similarity}")  # Debug log
            if similarity > 0.5:  # Lowered threshold for spaCy
                matches.append({'id': doc.id, 'filename': doc.filename, 'similarity': similarity})
    else:
        print("Using Levenshtein matching")  # Debug log
        for doc in docs:
            doc_text = extract_text(doc.filepath)
            if doc_text:
                similarity = 1 - (levenshtein_distance(new_text, doc_text) / max(len(new_text), len(doc_text)))
                print(f"Levenshtein Similarity {doc.filename}: {similarity}")  # Debug log
                if similarity > 0.7:
                    matches.append({'id': doc.id, 'filename': doc.filename, 'similarity': similarity})

    matches.sort(key=lambda x: x['similarity'], reverse=True)
    return matches[:5]

def init_matching_routes(app, db_session, Document, login_required):
    @app.route('/matches/<int:doc_id>', methods=['GET'])
    @login_required
    def get_matches(doc_id):
        use_ai = request.args.get('use_ai', 'false').lower() == 'true'
        doc = db_session.query(Document).filter_by(id=doc_id, user_id=session['user_id']).first()
        if not doc:
            return jsonify({'error': 'Document not found or not authorized'}), 404
        text = extract_text(doc.filepath)
        matches = find_similar_documents(text, db_session, Document, session['user_id'], use_ai=use_ai)
        return jsonify(matches), 200