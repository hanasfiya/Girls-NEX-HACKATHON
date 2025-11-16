import streamlit as st
import requests
import pandas as pd
import re
from google.oauth2 import service_account
from google.cloud import translate_v2 as translate
import dateutil.parser
from datetime import timezone
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import functools
import plotly.express as px
import time

if "messages" not in st.session_state or st.session_state.messages is None:
    st.session_state.messages = [
        {"role": "system", "content": (
            "You are MAVIS Cybersecurity AI Agent. " # <<< UPDATED AGENT NAME
            "You analyze insecure URLs, domains, HTTPS/HTTP status, "
            "summaries, articles from Google Search, and language distributions. "
            "Provide cybersecurity risk assessments and insights."
        )}
    ]

# ------------------------------
# CONFIGURATION
# ------------------------------
GOOGLE_SEARCH_API_KEY = "AIzaSyBCE9-FI50B4_0MUT4q53nCKkj5vrUfOFI"
GOOGLE_CSE_ID = "02a660bcff43e4400"
GOOGLE_CREDENTIALS_PATH = r"C:\Users\Asus\Desktop\my-streamlit-app\google_translate_key.json"
LOGO_PATH = r"C:\Users\Asus\Desktop\my-streamlit-app\LOGO PETRONAS.png"

# ------------------------------
# INITIALIZE GOOGLE TRANSLATE
# ------------------------------
try:
    credentials = service_account.Credentials.from_service_account_file(GOOGLE_CREDENTIALS_PATH)
    translate_client = translate.Client(credentials=credentials)
except Exception as e:
    st.error(f"Error loading Google Translate credentials: {e}. Please check GOOGLE_CREDENTIALS_PATH.")
    translate_client = None

# ------------------------------
# LANGUAGE MAP
# ------------------------------
LANGUAGE_MAP = {
    "english": "en", "malay": "ms", "spanish": "es", "french": "fr",
    "german": "de", "japanese": "ja", "chinese": "zh", "arabic": "ar",
    "russian": "ru", "italian": "it", "korean": "ko", "portuguese": "pt",
    "hindi": "hi", "turkish": "tr"
}

# ------------------------------
# CACHING TRANSLATION
# ------------------------------
if translate_client:
    @st.cache_data(show_spinner=False)
    def cached_translate(text, target):
        if not text: return ""
        result = translate_client.translate(text, target_language=target)
        return result['translatedText']

    @st.cache_data(show_spinner=False)
    def cached_detect_language(text):
        if not text: return "unknown"
        result = translate_client.detect_language(text)
        return result['language']
else:
    def cached_translate(text, target): return "Translation Error: Client not initialized."
    def cached_detect_language(text): return "unknown"

# ------------------------------
# HELPER FUNCTIONS
# ------------------------------
def generate_keyword_variations(keyword, translations):
    kws = [keyword]
    for val in translations.values():
        if val:
            kws.append(val)
    return kws

def highlight_keywords_multi(text, keywords):
    if not text or not keywords:
        return text
    for kw in keywords:
        if not kw: continue
        try:
            pattern = re.escape(kw)
            text = re.sub(pattern, f"<mark>{kw}</mark>", text, flags=re.IGNORECASE)
        except:
            continue
    return text

def get_paragraph_snippet(text, keyword, target_length=3000):
    if not text: return ""
    sentences = re.split(r'(?<=[.!?])\s+', text)
    snippet_sentences, total_len = [], 0
    found = False
    for i, sentence in enumerate(sentences):
        if re.search(re.escape(keyword), sentence, re.IGNORECASE):
            found = True
            snippet_sentences.append(sentence)
            total_len += len(sentence)
            # Previous sentences
            j = i - 1
            while j >= 0 and total_len < target_length:
                snippet_sentences.insert(0, sentences[j])
                total_len += len(sentences[j])
                j -= 1
            # Next sentences
            j = i + 1
            while j < len(sentences) and total_len < target_length:
                snippet_sentences.append(sentences[j])
                total_len += len(sentences[j])
                j += 1
            break
    if not found: return ""
    return f"...{' '.join(snippet_sentences)}..."

def check_security(url):
    parsed = urlparse(url)
    return "Secure (HTTPS)" if parsed.scheme == "https" else "Not Secure (HTTP)"

def security_warning_label(security_status):
    return f":red[{security_status}] ⚠️ Potentially insecure site" if security_status != "Secure (HTTPS)" else security_status

# ------------------------------
# LM Studio AI
# ------------------------------
def ask_local_ai(messages, timeout=60):
    try:
        response = requests.post(
            "http://localhost:1234/v1/chat/completions",
            json={
                "model": "meta-llama-3.1-8b-instruct",
                "messages": messages,
                "temperature": 0.7,
                "max_tokens": 500
            },
            timeout=timeout
        )
        if response.status_code != 200:
            return f"Error from LM Studio: {response.text}"
        return response.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"⚠️ AI Error: {str(e)}"

# ------------------------------
# GOOGLE CSE SEARCH
# ------------------------------
def fetch_google_batch(keyword, start):
    url = "https://www.googleapis.com/customsearch/v1"
    params = {"key": GOOGLE_SEARCH_API_KEY, "cx": GOOGLE_CSE_ID, "q": keyword, "num": 10, "start": start}
    try:
        response = requests.get(url, params=params)
        return response.json()
    except Exception as e:
        return {"error": str(e)}

@st.cache_data(ttl=600, show_spinner="Searching Google...")
def search_google_cse_max(keyword, max_results=100):
    data = []
    start_indices = list(range(1, max_results, 10))
    with ThreadPoolExecutor(max_workers=10) as executor:
        all_results = list(executor.map(functools.partial(fetch_google_batch, keyword), start_indices))
    for result in all_results:
        if not result or "items" not in result or "error" in result: continue
        for item in result["items"]:
            title = item.get("title", "")
            snippet_text = item.get("snippet", "")
            link = item.get("link", "")
            combined_text = f"{title} {snippet_text}"
            extracted = get_paragraph_snippet(combined_text, keyword)
            if not extracted: continue
            try:
                published_at_raw = item.get("pagemap", {}).get("metatags", [{}])[0].get("article:published_time")
                parsed_date = dateutil.parser.isoparse(published_at_raw).astimezone(timezone.utc) if published_at_raw else None
            except:
                parsed_date = None
            data.append({
                "title": title,
                "snippet": extracted,
                "url": link,
                "source": item.get("displayLink", ""),
                "publishedAt": published_at_raw if published_at_raw else "N/A",
                "parsedDate": parsed_date,
                "security": check_security(link)
            })
    if not data: st.warning("No keyword matches found."); return None
    df = pd.DataFrame(data)
    df["parsedDate"] = df["parsedDate"].apply(lambda x: x if x is not None else pd.Timestamp.min.replace(tzinfo=timezone.utc))
    df = df.sort_values(by="parsedDate", ascending=False).reset_index(drop=True)
    return df

# ------------------------------
# VISUALIZATIONS
# ------------------------------
def display_visualizations(df, detected_languages, search_keyword):
    if df is None or df.empty:
        st.warning("⚠️ No data available to visualize.")
        return

    plot_df = df.copy()
    plot_df['Language'] = detected_languages
    plot_df['Base Source'] = plot_df['source'].apply(lambda x: urlparse(f"http://{x}").netloc.replace('www.', '') if x else 'N/A')

    # Filter keyword-relevant articles
    keywords = generate_keyword_variations(search_keyword, st.session_state.translated_keywords)
    keyword_filtered_df = plot_df[plot_df['snippet'].apply(lambda s: any(re.search(re.escape(kw), s, re.IGNORECASE) for kw in keywords))]

    # --- Existing Visualizations ---
    # Insecure Articles Timeline
    insecure_df = keyword_filtered_df[keyword_filtered_df['security'] != "Secure (HTTPS)"]
    if not insecure_df.empty:
        timeline_data = insecure_df.set_index('parsedDate').resample('D').size().reset_index(name='Insecure Article Count')
        fig = px.bar(timeline_data, x='parsedDate', y='Insecure Article Count',
                      title=f'MAVIS Cybersecurity: Insecure Articles Timeline',
                      template="plotly_dark", color_discrete_sequence=['#FF6347'])
        fig.update_xaxes(rangeselector_visible=True, rangeslider_visible=True)
        fig.update_layout(title_x=0.5)
        st.subheader("🛡️ Insecure Articles Timeline")
        st.plotly_chart(fig, use_container_width=True)
    else:
        # This is the st.info message that needs to be purple
        st.info("No insecure articles detected in the retrieved data.")

    # Top Reporting Domains
    domain_counts = keyword_filtered_df['Base Source'].value_counts().nlargest(10).reset_index()
    domain_counts.columns = ['Base Source', 'Count']
    fig = px.bar(domain_counts, x='Base Source', y='Count',
                  title='Top 10 Reporting Domains (Keyword Relevant)',
                  template="plotly_dark",
                  color='Count', color_continuous_scale=px.colors.sequential.Teal)
    fig.update_layout(xaxis={'categoryorder':'total descending'}, title_x=0.5)
    st.subheader("🌐 Top Reporting Domains")
    st.plotly_chart(fig, use_container_width=True)

    # Article Language Distribution
    lang_counts = keyword_filtered_df['Language'].value_counts().reset_index()
    lang_counts.columns = ['Language', 'Count']
    fig = px.pie(lang_counts, values='Count', names='Language',
                  title='Article Language Distribution (Keyword Relevant)',
                  template="plotly_dark", color_discrete_sequence=px.colors.sequential.Teal)
    fig.update_traces(textposition='inside', textinfo='percent+label')
    fig.update_layout(title_x=0.5)
    st.subheader("🈂️ Language Distribution")
    st.plotly_chart(fig, use_container_width=True)

    # Security Status
    security_counts = keyword_filtered_df['security'].value_counts().reset_index()
    security_counts.columns = ['Security Status', 'Count']
    fig = px.bar(security_counts, x='Security Status', y='Count',
                  title='Source Security Status (Keyword Relevant)',
                  template="plotly_dark",
                  color='Security Status',
                  color_discrete_map={'Secure (HTTPS)': '#20B1A9', 'Not Secure (HTTP)': '#FF6347'})
    fig.update_layout(title_x=0.5)
    st.subheader("🔒 Source Security Status")
    st.plotly_chart(fig, use_container_width=True)

    # --- New Additional Visualizations ---
    # 1. Articles Published Over Time (all articles)
    if not df.empty:
        timeline_all = df.set_index('parsedDate').resample('D').size().reset_index(name='Article Count')
        fig = px.line(timeline_all, x='parsedDate', y='Article Count',
                      title='All Articles Published Over Time',
                      template="plotly_dark", markers=True)
        fig.update_layout(title_x=0.5)
        st.subheader("📰 Articles Published Over Time")
        st.plotly_chart(fig, use_container_width=True)

    # 2. Security vs Top Domains (how many insecure per top domains)
    if not keyword_filtered_df.empty:
        insecure_domain = keyword_filtered_df.groupby(['Base Source', 'security']).size().reset_index(name='Count')
        fig = px.bar(insecure_domain, x='Base Source', y='Count', color='security',
                      title='Security Status Across Top Domains (Keyword Relevant)',
                      template="plotly_dark",
                      color_discrete_map={'Secure (HTTPS)': '#20B1A9', 'Not Secure (HTTP)': '#FF6347'})
        fig.update_layout(xaxis={'categoryorder':'total descending'}, title_x=0.5)
        st.subheader("🔗 Security Status Across Top Domains")
        st.plotly_chart(fig, use_container_width=True)


# ------------------------------
# STREAMLIT UI SETUP
# ------------------------------
PURPLE_COLOR = "#4B0082" # Define the consistent purple color

st.set_page_config(page_title="MAVIS Cybersecurity Monitor", layout="wide") 
st.image(LOGO_PATH, width=250)
st.markdown(f"""
<style>
[data-testid="stAppViewContainer"] {{ background-color: #20B1A9; }}
[data-testid="stSidebar"] {{ background-color: #21605d; color: white; }}
.stButton>button {{ background-color:{PURPLE_COLOR}; color:white; }}
.stButton>button:hover {{ background-color:#6A0DAD; color:white; }}
.stTextInput>div>input {{ background-color:#21605d; color:#fff; border:1px solid {PURPLE_COLOR}; }}
mark {{ background-color: #FFFF00; color: black; }}

/* --- Standardize all links to the button color (#4B0082) --- */
a, a:hover, a:visited {{
    color: {PURPLE_COLOR} !important;
}}

/* --- Change st.info background to purple --- */
[data-testid="stAlert"] {{ 
    background-color: {PURPLE_COLOR} !important;
    color: white !important;
    border-left: 8px solid {PURPLE_COLOR} !important;
}}
[data-testid="stAlert"].st-da {{ 
    background-color: {PURPLE_COLOR} !important;
    color: white !important;
    border-left: 8px solid {PURPLE_COLOR} !important;
}}
[data-testid="stAlert"] > div > div > div {{
    color: white !important;
}}

</style>
""", unsafe_allow_html=True)
st.title("MAVIS CYBER SECURITY MONITOR")

# ------------------------------
# Initialize session state for AI messages
# ------------------------------
if "messages" not in st.session_state:
    st.session_state.messages = [
        {"role": "system", "content": (
            "You are MAVIS Cybersecurity AI Agent. " # <<< UPDATED AGENT NAME
            "You analyze insecure URLs, domains, HTTPS/HTTP status, "
            "summaries, articles from Google Search, and language distributions. "
            "Provide cybersecurity risk assessments and insights."
        )}
    ]

# ------------------------------
# STREAMLIT SIDEBAR CHAT
# ------------------------------
import time

# Function to call your AI
def ask_local_ai(messages):
    # Replace this with your actual AI call to LM Studio
    try:
        response = requests.post(
            "http://localhost:1234/v1/chat/completions",
            json={
                "model": "meta-llama-3.1-8b-instruct",
                "messages": messages,
                "temperature": 0.7,
                "max_tokens": 500
            },
            timeout=60
        )
        if response.status_code != 200:
            return f"⚠️ AI Error: {response.text}"
        return response.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"⚠️ AI Error: {str(e)}"

# ------------------------------
# INITIALIZE SESSION STATE (CLEANED)
# ------------------------------
default_state = {
    "messages": [],
    "displayed_messages": 0,
    "chat_temp": "",
    "results_df": None,
    "translations": None,
    "original_languages": None,
    "user_target_lang": "",
    "translated_keywords": None,
    "search_keyword": None,
    "show_visuals": False
}

for key, default in default_state.items():
    if key not in st.session_state:
        st.session_state[key] = default

# ------------------------------
# HIDDEN SYSTEM MESSAGE (CLEANED)
# ------------------------------
system_message = {
    "role": "system",
    "content": (
        "You are MAVIS Cybersecurity AI Agent. " # <<< UPDATED AGENT NAME
        "Answer concisely (3-5 sentences), directly, and only what the user asks. "
        "Do not include greetings or repetitive text. "
        "Always give complete and logical answers."
    )
}

# ------------------------------
# STREAMLIT SIDEBAR CHAT (CLEANED)
# ------------------------------
st.sidebar.header("💬 MAVIS Cybersecurity AI Assistant") # <<< UPDATED SIDEBAR HEADER

# Chat input form
with st.sidebar.form(key="chat_form"):
    chat_input = st.text_input(
        "Ask a question:",
        value=st.session_state.chat_temp,
        placeholder="Type your question here..."
    )
    submitted = st.form_submit_button("Send")

if submitted and chat_input.strip():
    # Save user message
    st.session_state.messages.append({"role": "user", "content": chat_input})

    # Prepare messages (system + last 4 messages)
    messages_to_send = [system_message] + st.session_state.messages[-4:]

    # Get AI reply
    ai_reply = ask_local_ai(messages_to_send)

    # Smart truncation (never cut mid-sentence)
    max_chars = 800
    if len(ai_reply) > max_chars:
        end_idx = ai_reply[:max_chars].rfind('.')
        if end_idx != -1:
            ai_reply = ai_reply[:end_idx+1]
        else:
            ai_reply = ai_reply[:max_chars] + "..."

    # Save AI reply
    st.session_state.messages.append({"role": "assistant", "content": ai_reply})

    # Clear temporary input for next question
    st.session_state.chat_temp = ""

# ------------------------------
# DISPLAY CHAT WITH TYPING ANIMATION
# ------------------------------
st.sidebar.write("### Conversation:")

for msg in st.session_state.messages[st.session_state.displayed_messages:]:
    placeholder = st.sidebar.empty()
    role = "**User:**" if msg["role"] == "user" else "**Assistant:**"
    content = msg["content"]

    bubble_style = """
        display:inline-block;
        background-color:{bg};
        color:white;
        border-radius:16px;
        padding:10px;
        margin-bottom:8px;
        max-width:90%;
        word-wrap:break-word;
    """

    if msg["role"] == "assistant":
        bg = "#20B1A9"
        displayed_text = ""
        for char in content:
            displayed_text += char
            placeholder.markdown(f'<div style="{bubble_style.format(bg=bg)}">{displayed_text}</div>',
                                 unsafe_allow_html=True)
            time.sleep(0.02)  # typing animation speed
    else:
        bg = "#4B0082"
        placeholder.markdown(f'<div style="{bubble_style.format(bg=bg)}">{role} {content}</div>',
                             unsafe_allow_html=True)

# Update displayed messages count
st.session_state.displayed_messages = len(st.session_state.messages)

# ------------------------------
# AUTO-SCROLL SIDEBAR TO BOTTOM
# ------------------------------
st.sidebar.markdown(
    """
    <script>
    const sidebar = document.querySelector('section[data-testid="stSidebar"]');
    if (sidebar) { sidebar.scrollTop = sidebar.scrollHeight; }
    </script>
    """,
    unsafe_allow_html=True
)
# ------------------------------
# INPUTS
# ------------------------------
search_keyword_input = st.text_input("Enter a keyword (any language)")
user_target_lang_name = st.text_input("Optional: target language (full name)")
if user_target_lang_name.lower() in LANGUAGE_MAP:
    st.session_state.user_target_lang = LANGUAGE_MAP[user_target_lang_name.lower()]
else:
    st.session_state.user_target_lang = ""

# ------------------------------
# GOOGLE SEARCH
# ------------------------------
if st.button("Search Google"):
    if translate_client is None:
        st.error("Cannot proceed. Google Translate client failed to initialize.")
    elif search_keyword_input:
        st.session_state.search_keyword = search_keyword_input
        st.session_state.results_df = search_google_cse_max(st.session_state.search_keyword, max_results=100)
        st.session_state.translations = None
        st.session_state.original_languages = None
        st.session_state.show_visuals = False
    else:
        st.warning("Please enter a keyword.")

# ------------------------------
# TRANSLATIONS
# ------------------------------
if st.session_state.results_df is not None and st.session_state.translations is None:
    df = st.session_state.results_df
    if not df.empty and st.session_state.search_keyword:
        with st.spinner("Detecting languages and translating snippets..."):
            translations_en, translations_ms, translations_user = [], [], []
            original_languages = []
            search_keyword = st.session_state.search_keyword
            translated_keyword_en = cached_translate(search_keyword, "en")
            translated_keyword_ms = cached_translate(search_keyword, "ms")
            translated_keyword_user = (cached_translate(search_keyword, st.session_state.user_target_lang)
                                               if st.session_state.user_target_lang else None)
            st.session_state.translated_keywords = {"en": translated_keyword_en, "ms": translated_keyword_ms, "user": translated_keyword_user}

            for snippet in df["snippet"]:
                orig_lang = cached_detect_language(snippet)
                original_languages.append(orig_lang)
                en_text = snippet if orig_lang=="en" else cached_translate(snippet, "en")
                ms_text = cached_translate(en_text, "ms")
                user_text = cached_translate(en_text, st.session_state.user_target_lang) if st.session_state.user_target_lang else None
                translations_en.append(en_text)
                translations_ms.append(ms_text)
                translations_user.append(user_text)

            st.session_state.translations = {"en": translations_en, "ms": translations_ms, "user": translations_user}
            st.session_state.original_languages = original_languages

# ------------------------------
# DISPLAY ARTICLES
# ------------------------------
if st.session_state.results_df is not None and st.session_state.translations is not None:
    df = st.session_state.results_df
    for idx, row in df.iterrows():
        snippet = row["snippet"]
        keywords = generate_keyword_variations(st.session_state.search_keyword, st.session_state.translated_keywords)
        if not any(re.search(re.escape(kw), snippet, re.IGNORECASE) for kw in keywords):
            continue

        st.divider()
        detected_lang = st.session_state.original_languages[idx]
        st.subheader(f"Original ({detected_lang.upper()})")
        st.markdown(highlight_keywords_multi(snippet, keywords), unsafe_allow_html=True)

        cols = [1, 1, 1] if st.session_state.user_target_lang else [1, 1]
        if st.session_state.user_target_lang:
            col1, col2, col3 = st.columns(cols)
        else:
            col1, col2 = st.columns(cols)
            col3 = None

        with col1:
            st.subheader("English")
            st.markdown(highlight_keywords_multi(st.session_state.translations["en"][idx], keywords), unsafe_allow_html=True)
        with col2:
            st.subheader("Malay")
            st.markdown(highlight_keywords_multi(st.session_state.translations["ms"][idx], keywords), unsafe_allow_html=True)
        if col3:
            with col3:
                user_text = st.session_state.translations["user"][idx]
                if user_text:
                    st.markdown(highlight_keywords_multi(user_text, keywords), unsafe_allow_html=True)

        # Links are now guaranteed to be purple due to the CSS fix above.
        # We still use st.markdown with <a> tags to embed the links.
        st.markdown(f"Source: <a href='{row['url']}'>{row['source']}</a>", unsafe_allow_html=True)
        st.write(f"Published at: {row['publishedAt']}") 
        st.markdown(f"Security: {security_warning_label(row['security'])}", unsafe_allow_html=True)
        st.markdown(f"[<a href='{row['url']}'>Read full article</a>]({row['url']})", unsafe_allow_html=True)


# ------------------------------
# SHOW VISUALIZATIONS
# ------------------------------
if st.session_state.results_df is not None and st.session_state.original_languages is not None:
    if st.button("📊 Show Visualizations"):
        st.session_state.show_visuals = True
    if st.session_state.show_visuals:
        display_visualizations(st.session_state.results_df,
                               st.session_state.original_languages,
                               st.session_state.search_keyword)