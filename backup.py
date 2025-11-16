import streamlit as st
import requests
import pandas as pd
import re
from google.oauth2 import service_account
from google.cloud import translate_v2 as translate

# --- CONFIGURATION ---
NEWS_API_KEY = "30fa0ab1cc764ba9974938b6b7c14152"  # NewsAPI
GOOGLE_CREDENTIALS_PATH = r"C:\Users\Asus\Desktop\my-streamlit-app\google_translate_key.json"
KEYWORDS_FILE = r"C:\Users\Asus\Desktop\my-streamlit-app\keywords.txt"

# Load Google Translate credentials
credentials = service_account.Credentials.from_service_account_file(GOOGLE_CREDENTIALS_PATH)
translate_client = translate.Client(credentials=credentials)
# ---------------------

# Load keywords
with open(KEYWORDS_FILE, "r", encoding="utf-8") as f:
    keywords = [line.strip() for line in f if line.strip()]

# Function to highlight keywords
def highlight_keywords(text):
    def repl(match):
        return f"**:red[{match.group(0)}]**"
    
    if not text:
        return ""
    
    # Combine keywords into a single regex pattern (case-insensitive)
    pattern = r"\b(" + "|".join(re.escape(k) for k in keywords) + r")\b"
    return re.sub(pattern, repl, text, flags=re.IGNORECASE)

# Function to search NewsAPI
def search_news(keyword):
    url = "https://newsapi.org/v2/everything"
    params = {'q': keyword, 'apiKey': NEWS_API_KEY, 'sortBy': 'publishedAt'}
    
    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            articles = data.get('articles', [])
            if not articles:
                st.warning("No articles found.")
                return None
            df = pd.DataFrame(articles)
            df = df[['source', 'title', 'description', 'url', 'publishedAt']]
            df['source'] = df['source'].apply(lambda s: s['name'])
            return df
        else:
            st.error(f"Error from API: {response.json().get('message')}")
            return None
    except Exception as e:
        st.error(f"An error occurred: {e}")
        return None

# Function to translate text
def translate_text(text, target_lang):
    if not text:
        return ""
    result = translate_client.translate(text, target_language=target_lang)
    return result['translatedText']

# --- STREAMLIT APP ---
st.title("PETRONAS CYBERSECURITY MONITOR")

# Initialize session state
if "results_df" not in st.session_state:
    st.session_state.results_df = None
if "translated" not in st.session_state:
    st.session_state.translated = False
if "translations" not in st.session_state:
    st.session_state.translations = None

# Search input
search_keyword = st.text_input(
    "Enter a keyword (any language, e.g., 'malware trend Malaysia', '马来西亚', 'الأمن السيبراني')"
)

# Search button
if st.button("Search"):
    if search_keyword:
        st.write(f"Searching for '{search_keyword}'...")
        st.session_state.results_df = search_news(search_keyword)
        st.session_state.translated = False
    else:
        st.warning("Please enter a keyword to search.")

# If search results exist
if st.session_state.results_df is not None:
    df = st.session_state.results_df
    st.success(f"Found {len(df)} results.")
    st.dataframe(df)

    # Translate all articles button
    if st.button("Translate All Articles"):
        with st.spinner("Translating articles..."):
            translations_en = {"title": [], "description": []}
            translations_ms = {"title": [], "description": []}
            for _, row in df.iterrows():
                translations_en["title"].append(translate_text(row['title'], "en"))
                translations_en["description"].append(translate_text(row['description'], "en"))
                translations_ms["title"].append(translate_text(row['title'], "ms"))
                translations_ms["description"].append(translate_text(row['description'], "ms"))
            st.session_state.translations = {"en": translations_en, "ms": translations_ms}
            st.session_state.translated = True

    # Display articles in 3 columns: Original | English | Malay with highlights
    for idx, row in df.iterrows():
        st.divider()
        col1, col2, col3 = st.columns(3)
        with col1:
            st.subheader("Original")
            st.markdown(highlight_keywords(row['title']), unsafe_allow_html=True)
            st.markdown(highlight_keywords(row['description']), unsafe_allow_html=True)
        with col2:
            st.subheader("English")
            if st.session_state.translated:
                st.markdown(highlight_keywords(st.session_state.translations["en"]["title"][idx]), unsafe_allow_html=True)
                st.markdown(highlight_keywords(st.session_state.translations["en"]["description"][idx]), unsafe_allow_html=True)
        with col3:
            st.subheader("Malay")
            if st.session_state.translated:
                st.markdown(highlight_keywords(st.session_state.translations["ms"]["title"][idx]), unsafe_allow_html=True)
                st.markdown(highlight_keywords(st.session_state.translations["ms"]["description"][idx]), unsafe_allow_html=True)
        
        st.write(f"Source: {row['source']} | Published: {row['publishedAt']}")
        st.write(f"[Read full article]({row['url']})")



