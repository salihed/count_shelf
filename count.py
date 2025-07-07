import streamlit as st
import pandas as pd
import gspread
from google.oauth2.service_account import Credentials
import json
import hashlib
from datetime import datetime
from google.auth.transport.requests import Request

# Sayfa konfigürasyonu
st.set_page_config(
    page_title="Depo Sayım Programı",
    page_icon="📦",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# CSS ile mobil uyumlu tasarım
st.markdown("""
<style>
    .login-container {
        max-width: 400px;
        margin: 2rem auto;
        padding: 2rem;
        background-color: #F8FAFC;
        border-radius: 20px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    
    .login-header {
        text-align: center;
        color: #2E86AB;
        font-size: 2rem;
        margin-bottom: 2rem;
    }
    
    .user-info {
        background-color: #E8F4FD;
        padding: 0.5rem 1rem;
        border-radius: 10px;
        text-align: center;
        margin-bottom: 1rem;
        font-size: 1rem;
        color: #1E3A8A;
    }
    
    .logout-button {
        background-color: #EF4444 !important;
        color: white !important;
        border: none !important;
        padding: 0.5rem 1rem !important;
        border-radius: 5px !important;
        font-size: 0.9rem !important;
    }
    
    .current-address {
        background-color: #E8F4FD;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        margin-bottom: 1rem;
        font-size: 1.2rem;
        color: #1E3A8A;
    }
    
    .main-header {
        text-align: center;
        color: #2E86AB;
        font-size: 2.5rem;
        margin-bottom: 2rem;
    }
    
    .counter-display {
        background-color: #F0F9FF;
        padding: 2rem;
        border-radius: 15px;
        text-align: center;
        margin-bottom: 2rem;
        border: 3px solid #2E86AB;
    }
    
    .counter-text {
        font-size: 3rem;
        font-weight: bold;
        color: #2E86AB;
    }
    
    .success-message {
        background-color: #D1FAE5;
        color: #065F46;
        padding: 1rem;
        border-radius: 10px;
        margin: 1rem 0;
        border-left: 4px solid #10B981;
    }
    
    .warning-message {
        background-color: #FEF3C7;
        color: #92400E;
        padding: 1rem;
        border-radius: 10px;
        margin: 1rem 0;
        border-left: 4px solid #F59E0B;
    }
    
    .error-message {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 1rem;
        border-radius: 10px;
        margin: 1rem 0;
        border-left: 4px solid #EF4444;
    }
    
    .input-section {
        background-color: #F8FAFC;
        padding: 2rem;
        border-radius: 15px;
        margin-bottom: 2rem;
    }
    
    .stButton > button {
        width: 100%;
        background-color: #2E86AB;
        color: white;
        border: none;
        padding: 1rem;
        border-radius: 10px;
        font-size: 1.2rem;
        margin: 0.5rem 0;
    }
    
    .stTextInput > div > div > input {
        font-size: 1.2rem;
        padding: 1rem;
        border-radius: 10px;
    }
    
    .spreadsheet-info {
        background-color: #F0F9FF;
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 1rem;
        border-left: 4px solid #2E86AB;
    }
    
    @media (max-width: 768px) {
        .main-header {
            font-size: 2rem;
        }
        .counter-text {
            font-size: 2.5rem;
        }
        .current-address {
            font-size: 1rem;
        }
    }
</style>
""", unsafe_allow_html=True)

# Kullanıcı doğrulama fonksiyonları
def get_users():
    """Kullanıcıları secrets.toml'dan yükler"""
    try:
        users = st.secrets.get("users", {})
        return users
    except Exception as e:
        st.error(f"Kullanıcılar yüklenemedi: {str(e)}")
        return {}

def verify_user(username, password):
    """Kullanıcıyı doğrular"""
    users = get_users()
    if username in users:
        # Şifreyi hash'le ve karşılaştır
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return users[username] == password_hash
    return False

def login_page():
    """Login sayfasını gösterir"""
    st.markdown('<div class="login-container">', unsafe_allow_html=True)
    st.markdown('<h2 class="login-header">🔐 Giriş Yap</h2>', unsafe_allow_html=True)
    
    with st.form("login_form"):
        username = st.text_input("👤 Kullanıcı Adı:", placeholder="Kullanıcı adınızı girin")
        password = st.text_input("🔒 Şifre:", type="password", placeholder="Şifrenizi girin")
        submit_button = st.form_submit_button("🚪 Giriş Yap", use_container_width=True)
        
        if submit_button:
            if username and password:
                if verify_user(username, password):
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    st.session_state.login_time = datetime.now()
                    st.success("✅ Giriş başarılı! Yönlendiriliyorsunuz...")
                    st.rerun()
                else:
                    st.error("❌ Geçersiz kullanıcı adı veya şifre!")
            else:
                st.warning("⚠️ Lütfen tüm alanları doldurun!")
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Kullanım bilgisi
    st.markdown("""
    ---
    ### 📋 Kullanım Bilgileri
    - Sistem yöneticisinden kullanıcı adı ve şifrenizi alın
    - Güvenli bir şifre kullanın
    - Oturumunuzu kapattığınızda tekrar giriş yapmanız gerekecektir
    """)

def logout():
    """Kullanıcıyı çıkış yapar"""
    st.session_state.authenticated = False
    st.session_state.username = None
    st.session_state.current_address = None
    st.session_state.messages = []
    st.rerun()

# Google Sheets bağlantısı için fonksiyonlar
@st.cache_resource
def init_google_sheets():
    """Google Sheets bağlantısını başlatır"""
    try:
        # Service account credentials kontrol et
        if "gcp_service_account" not in st.secrets:
            st.error("❌ Google Service Account bilgileri bulunamadı!")
            st.markdown("""
            ### 🔧 Çözüm:
            `secrets.toml` dosyanızda aşağıdaki yapıyı eklemelisiniz:
            
            ```toml
            [gcp_service_account]
            type = "service_account"
            project_id = "your_project_id"
            private_key_id = "your_private_key_id"
            private_key = "-----BEGIN PRIVATE KEY-----\\nYOUR_PRIVATE_KEY\\n-----END PRIVATE KEY-----\\n"
            client_email = "your_service_account@project.iam.gserviceaccount.com"
            client_id = "your_client_id"
            auth_uri = "https://accounts.google.com/o/oauth2/auth"
            token_uri = "https://oauth2.googleapis.com/token"
            auth_provider_x509_cert_url = "https://www.googleapis.com/oauth2/v1/certs"
            client_x509_cert_url = "your_client_cert_url"
            ```
            """)
            return None
            
        creds_dict = st.secrets["gcp_service_account"]

        # Gerekli scope'ları tanımla
        scopes = [
            'https://www.googleapis.com/auth/spreadsheets',
            'https://www.googleapis.com/auth/drive'
        ]
        # Service account credentials'ı doğru şekilde oluştur
        creds = Credentials.from_service_account_info(
            creds_dict, 
            scopes=scopes
        )
        
        # Credentials'ı refresh et
        if not creds.valid:
            if creds.expired and creds.refresh_token:
                creds.refresh(Request())
        
        # gspread client'ı oluştur
        client = gspread.authorize(creds)
        
        return client
        
    except Exception as e:
        st.error(f"Google Sheets bağlantısı kurulamadı: {str(e)}")
        return None

@st.cache_resource
def get_spreadsheet():
    """Spreadsheet'i secrets'tan alır"""
    try:
        client = init_google_sheets()
        if client is None:
            return None, None
        
        # Spreadsheet ID'sini secrets'tan al
        if "spreadsheet" not in st.secrets:
            st.error("❌ Spreadsheet bilgileri bulunamadı!")
            st.markdown("""
            ### 🔧 Çözüm:
            `secrets.toml` dosyanızda aşağıdaki yapıyı eklemelisiniz:
            
            ```toml
            [spreadsheet]
            id = "your_spreadsheet_id_here"
            ```
            
            **Spreadsheet ID'sini nasıl bulursunuz:**
            1. Google Sheets'te dosyanızı açın
            2. URL'den ID'yi kopyalayın: `https://docs.google.com/spreadsheets/d/**SPREADSHEET_ID**/edit`
            """)
            return None, None
            
        if "id" not in st.secrets["spreadsheet"]:
            st.error("❌ Spreadsheet ID bulunamadı!")
            st.markdown("secrets.toml dosyasında `[spreadsheet]` altında `id` parametresi eksik!")
            return None, None
            
        spreadsheet_id = st.secrets["spreadsheet"]["id"]
        spreadsheet = client.open_by_key(spreadsheet_id)
        
        return spreadsheet, spreadsheet_id
    except Exception as e:
        st.error(f"Spreadsheet erişim hatası: {str(e)}")
        return None, None

@st.cache_data(ttl=60)  # 1 dakika cache
def load_data():
    """Google Sheets'ten veri yükler"""
    try:
        spreadsheet, spreadsheet_id = get_spreadsheet()
        if spreadsheet is None:
            return None, None
        
        # Ana sayfa (worksheet) al
        sheet = spreadsheet.sheet1
        data = sheet.get_all_records()
        df = pd.DataFrame(data)
        
        # Boş satırları temizle
        if not df.empty:
            df = df.dropna(subset=['Depo Adresi', 'Taşıma Birimi (TB)'])
        
        return df, sheet
    except Exception as e:
        st.error(f"Veri yükleme hatası: {str(e)}")
        return None, None

def ensure_required_columns(sheet):
    """Gerekli sütunların var olduğundan emin olur"""
    try:
        # Başlık satırını al
        header_row = sheet.row_values(1)
        
        # Gerekli sütunları kontrol et
        required_columns = ['Sayım Durumu', 'Sayım Yapan', 'Sayım Tarihi', 'Sayım Başlama Tarihi', 'Sayım Bitiş Tarihi']
        
        # Eksik sütunları bul
        missing_columns = [col for col in required_columns if col not in header_row]
        
        # Eksik sütunları tek tek ekle
        if missing_columns:
            current_col = len(header_row) + 1
            for col in missing_columns:
                sheet.update_cell(1, current_col, col)
                current_col += 1
                # Kısa bekleme
                import time
                time.sleep(0.1)
        
        return True
    except Exception as e:
        st.error(f"Sütun kontrol hatası: {str(e)}")
        return False

def update_sayim_durumu(sheet, tb_value, durum, username):
    """Sayım durumunu günceller"""
    try:
        # Gerekli sütunları kontrol et
        if not ensure_required_columns(sheet):
            return False
        
        # Tüm verileri al
        all_values = sheet.get_all_values()
        if not all_values:
            st.error("Spreadsheet boş!")
            return False
            
        # Sütun indekslerini bul
        header_row = all_values[0]
        
        # Sütun indekslerini güvenli şekilde bul
        try:
            tb_col = header_row.index('Taşıma Birimi (TB)') + 1
            durum_col = header_row.index('Sayım Durumu') + 1
            sayim_yapan_col = header_row.index('Sayım Yapan') + 1
            sayim_tarihi_col = header_row.index('Sayım Tarihi') + 1
        except ValueError as e:
            st.error(f"Gerekli sütun bulunamadı: {str(e)}")
            return False
        
        # TB'yi bul ve güncelle
        tb_found = False
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        for i, row in enumerate(all_values[1:], start=2):
            if len(row) > tb_col-1:  # Satır uzunluğu kontrolü
                # TB değerini string olarak karşılaştır
                row_tb = str(row[tb_col-1]).strip()
                input_tb = str(tb_value).strip()
                
                if row_tb == input_tb:
                    tb_found = True
                    
                    # Tek tek hücre güncelleme
                    sheet.update_cell(i, durum_col, durum)
                    sheet.update_cell(i, sayim_yapan_col, username)
                    sheet.update_cell(i, sayim_tarihi_col, current_time)
                    
                    break
        
        if not tb_found:
            st.error(f"TB bulunamadı: {tb_value}")
            return False
        
        return True
    except Exception as e:
        st.error(f"Güncelleme hatası: {str(e)}")
        return False

def update_address_sayim_durumu(sheet, address, durum, username):
    """Adres bazında sayım durumunu günceller"""
    try:
        # Gerekli sütunları kontrol et
        if not ensure_required_columns(sheet):
            return False
        
        # Tüm verileri al
        all_values = sheet.get_all_values()
        if not all_values:
            return False
            
        # Sütun indekslerini bul
        header_row = all_values[0]
        
        try:
            address_col = header_row.index('Depo Adresi') + 1
            sayim_baslama_col = header_row.index('Sayım Başlama Tarihi') + 1
            sayim_bitis_col = header_row.index('Sayım Bitiş Tarihi') + 1
        except ValueError as e:
            st.error(f"Gerekli sütun bulunamadı: {str(e)}")
            return False
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Adrese ait tüm satırları bul ve güncelle
        for i, row in enumerate(all_values[1:], start=2):
            if len(row) > address_col-1 and row[address_col-1] == address:
                if durum == 'Başladı':
                    # Sayım başlama tarihini güncelle
                    sheet.update_cell(i, sayim_baslama_col, current_time)
                elif durum == 'Tamamlandı':
                    # Sayım bitiş tarihini güncelle
                    sheet.update_cell(i, sayim_bitis_col, current_time)
        
        return True
    except Exception as e:
        st.error(f"Adres durumu güncelleme hatası: {str(e)}")
        return False

def update_address_sayim_durumu_fallback(sheet, address, durum, username):
    """Adres durumu fallback güncelleme"""
    try:
        all_values = sheet.get_all_values()
        header_row = all_values[0]
        
        address_col = header_row.index('Depo Adresi') + 1
        sayim_baslama_col = header_row.index('Sayım Başlama Tarihi') + 1
        sayim_bitis_col = header_row.index('Sayım Bitiş Tarihi') + 1
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        for i, row in enumerate(all_values[1:], start=2):
            if len(row) > address_col-1 and row[address_col-1] == address:
                if durum == 'Başladı':
                    sheet.update_cell(i, sayim_baslama_col, current_time)
                elif durum == 'Tamamlandı':
                    sheet.update_cell(i, sayim_bitis_col, current_time)
        
        return True
    except Exception as e:
        st.error(f"Adres durumu fallback hatası: {str(e)}")
        return False

def get_address_tbs(df, address):
    """Bir adrese ait TB'leri döndürür"""
    if df is not None and not df.empty:
        address_data = df[df['Depo Adresi'] == address]
        return address_data
    return pd.DataFrame()

def tb_exists_in_address(df, address, tb_input):
    """TB'nin belirtilen adreste var olup olmadığını kontrol eder"""
    address_data = get_address_tbs(df, address)
    if address_data.empty:
        return False, None
    
    # TB sütununu string'e çevir ve karşılaştır
    address_data_copy = address_data.copy()
    address_data_copy['TB_String'] = address_data_copy['Taşıma Birimi (TB)'].astype(str)
    
    # Hem string hem de sayı olarak arama yap
    tb_input_str = str(tb_input).strip()
    
    # Exact match ara
    exact_match = address_data_copy[address_data_copy['TB_String'] == tb_input_str]
    
    if not exact_match.empty:
        return True, exact_match.iloc[0]
    
    # Eğer exact match bulunamazsa, numeric karşılaştırma dene
    try:
        tb_input_num = float(tb_input_str)
        numeric_match = address_data_copy[address_data_copy['Taşıma Birimi (TB)'].astype(float) == tb_input_num]
        if not numeric_match.empty:
            return True, numeric_match.iloc[0]
    except:
        pass
    
    return False, None

def debug_address_data(df, address):
    """Debug için adres verilerini göster"""
    address_data = get_address_tbs(df, address)
    if not address_data.empty:
        st.write(f"**{address} adresindeki TB'ler:**")
        for idx, row in address_data.iterrows():
            tb_value = row['Taşıma Birimi (TB)']
            tb_type = type(tb_value).__name__
            st.write(f"- TB: {tb_value} (Tür: {tb_type})")
    else:
        st.write(f"**{address} adresinde TB bulunamadı**")

def count_sayilan_tbs(df, address):
    """Sayılan TB sayısını döndürür"""
    address_data = get_address_tbs(df, address)
    if not address_data.empty:
        sayilan_count = len(address_data[address_data['Sayım Durumu'] == 'Sayıldı'])
        return sayilan_count
    return 0

# Session state başlatma
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'current_address' not in st.session_state:
    st.session_state.current_address = None
if 'messages' not in st.session_state:
    st.session_state.messages = []

# Kullanıcı doğrulama kontrolü
if not st.session_state.authenticated:
    login_page()
    st.stop()

# Kullanıcı bilgisi ve çıkış butonu
col1, col2 = st.columns([3, 1])
with col1:
    st.markdown(f'<div class="user-info">👤 Hoşgeldin, <strong>{st.session_state.username}</strong></div>', 
                unsafe_allow_html=True)
with col2:
    if st.button("🚪 Çıkış", key="logout_btn"):
        logout()

# Ana başlık
st.markdown('<h1 class="main-header">📦 Depo Sayım Programı</h1>', unsafe_allow_html=True)

# Spreadsheet bilgisi göster
try:
    spreadsheet, spreadsheet_id = get_spreadsheet()
    if spreadsheet:
        st.markdown(f'''
        <div class="spreadsheet-info">
            <strong>📊 Aktif Spreadsheet:</strong> {spreadsheet.title}<br>
            <strong>🆔 ID:</strong> {spreadsheet_id}
        </div>
        ''', unsafe_allow_html=True)
except:
    pass

# Sidebar - Kontrol Paneli
with st.sidebar:
    st.header("🎛️ Kontrol Paneli")
    
    if st.button("🔄 Verileri Yenile"):
        st.cache_data.clear()
        st.cache_resource.clear()
        st.rerun()
    
    if st.button("🗑️ Oturumu Temizle"):
        st.session_state.current_address = None
        st.session_state.messages = []
        st.rerun()
    
    st.markdown("---")
    
    # Spreadsheet bilgileri
    st.subheader("📊 Spreadsheet Bilgileri")
    try:
        spreadsheet, spreadsheet_id = get_spreadsheet()
        if spreadsheet:
            st.write(f"**Başlık:** {spreadsheet.title}")
            st.write(f"**ID:** {spreadsheet_id}")
            st.write(f"**Sayfa Sayısı:** {len(spreadsheet.worksheets())}")
        else:
            st.error("Spreadsheet'e erişilemiyor!")
    except Exception as e:
        st.error(f"Spreadsheet bilgisi alınamadı: {str(e)}")

# Ana uygulama
# Verileri yükle
data_result = load_data()

if data_result[0] is not None:
    df, sheet = data_result
    
    # Mevcut adres gösterimi
    if st.session_state.current_address:
        st.markdown(f'<div class="current-address">📍 Aktif Adres: <strong>{st.session_state.current_address}</strong></div>', 
                   unsafe_allow_html=True)
        
        # Sayaç gösterimi
        address_tbs = get_address_tbs(df, st.session_state.current_address)
        total_tbs = len(address_tbs)
        sayilan_tbs = count_sayilan_tbs(df, st.session_state.current_address)
        
        st.markdown(f'''
        <div class="counter-display">
            <div class="counter-text">{sayilan_tbs} / {total_tbs}</div>
            <div>Sayılan TB / Toplam TB</div>
        </div>
        ''', unsafe_allow_html=True)
    
    # Giriş bölümü
    st.markdown('<div class="input-section">', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📍 Adres Okutma")
        address_input = st.text_input(
            "Adres Barkodu:",
            placeholder="Adres barkodunu okutun veya yazın",
            key="address_input"
        )
        
        if st.button("🎯 Adres Seç"):
            if address_input:
                # Adresi kontrol et
                if address_input in df['Depo Adresi'].values:
                    # Önceki adresin sayımını tamamla
                    if st.session_state.current_address:
                        update_address_sayim_durumu(sheet, st.session_state.current_address, 'Tamamlandı', st.session_state.username)
                    
                    # Yeni adresi seç ve sayımı başlat
                    st.session_state.current_address = address_input
                    st.session_state.messages = []
                    update_address_sayim_durumu(sheet, address_input, 'Başladı', st.session_state.username)
                    st.cache_data.clear()
                    st.rerun()
                else:
                    st.error("❌ Bu adres sistemde bulunamadı!")
    
    with col2:
        st.subheader("📦 TB Okutma")
        tb_input = st.text_input(
            "TB Barkodu:",
            placeholder="TB barkodunu okutun veya yazın",
            key="tb_input",
            disabled=st.session_state.current_address is None
        )
        
        if st.button("✅ TB Kaydet", disabled=st.session_state.current_address is None):
            if tb_input and st.session_state.current_address:
                # TB'yi kontrol et - YENİ FONKSİYON KULLAN
                tb_exists, tb_row = tb_exists_in_address(df, st.session_state.current_address, tb_input)
                
                if tb_exists:
                    # TB bu adreste var
                    current_durum = tb_row['Sayım Durumu'] if pd.notna(tb_row['Sayım Durumu']) else ''
                    
                    if current_durum == 'Sayıldı':
                        # Daha önce sayılmış
                        st.session_state.messages.append({
                            'type': 'warning',
                            'message': f"Bu TB daha önce sayıldı: {tb_input}"
                        })
                    else:
                        # TB'yi sayıldı olarak işaretle
                        # Güncelleme için orijinal TB değerini kullan
                        original_tb = tb_row['Taşıma Birimi (TB)']
                        if update_sayim_durumu(sheet, str(original_tb), 'Sayıldı', st.session_state.username):
                            st.session_state.messages.append({
                                'type': 'success',
                                'message': f"TB başarıyla kaydedildi: {tb_input}"
                            })
                            st.cache_data.clear()  # Cache'i temizle
                            st.rerun()
                else:
                    # TB bu adreste yok
                    st.session_state.messages.append({
                        'type': 'error',
                        'message': f"Bu TB bu adreste bulunamadı: {tb_input}"
                    })
                    
                    # DEBUG: Adres verilerini göster
                    with st.expander("🔍 Debug Bilgileri"):
                        debug_address_data(df, st.session_state.current_address)
    
    # Mesajları göster
    for msg in st.session_state.messages:
        if msg['type'] == 'success':
            st.markdown(f'<div class="success-message">✅ {msg["message"]}</div>', unsafe_allow_html=True)
        elif msg['type'] == 'warning':
            st.markdown(f'<div class="warning-message">⚠️ {msg["message"]}</div>', unsafe_allow_html=True)
        elif msg['type'] == 'error':
            st.markdown(f'<div class="error-message">❌ {msg["message"]}</div>', unsafe_allow_html=True)
    
    # Sayımı bitirme butonu
    if st.session_state.current_address:
        st.markdown("---")
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("🏁 Bu Adresin Sayımını Bitir", type="primary"):
                # Sayılmayan TB'leri "Bulunamadı" olarak işaretle
                address_tbs = get_address_tbs(df, st.session_state.current_address)
                sayilmayan_tbs = address_tbs[address_tbs['Sayım Durumu'].isna() | (address_tbs['Sayım Durumu'] == '')]
                
                if not sayilmayan_tbs.empty:
                    for _, row in sayilmayan_tbs.iterrows():
                        update_sayim_durumu(sheet, row['Taşıma Birimi (TB)'], 'Bulunamadı', st.session_state.username)
                    
                    st.warning(f"⚠️ {len(sayilmayan_tbs)} adet TB bulunamadı olarak işaretlendi:")
                    
                    # Bulunamayan TB'leri göster
                    for _, row in sayilmayan_tbs.iterrows():
                        st.write(f"- **TB:** {row['Taşıma Birimi (TB)']} | **Parti:** {row['Parti']} | **Miktar:** {row['Miktar']}")
                else:
                    st.success("✅ Bu adresteki tüm TB'ler sayıldı!")
                
                # Adres sayımını tamamla
                update_address_sayim_durumu(sheet, st.session_state.current_address, 'Tamamlandı', st.session_state.username)
                
                st.cache_data.clear()
                st.session_state.current_address = None
                st.session_state.messages = []
                st.rerun()
    
    # Rapor sekmesi
    st.markdown("---")
    st.subheader("📊 Sayım Durumu Raporu")
    
    # Filtreler
    col1, col2 = st.columns(2)
    with col1:
        selected_address = st.selectbox(
            "Adres Seçin:",
            options=["Tümü"] + list(df['Depo Adresi'].unique()),
            index=0
        )
    
    with col2:
        selected_durum = st.selectbox(
            "Sayım Durumu:",
            options=["Tümü", "Sayıldı", "Bulunamadı", "Sayılmadı"],
            index=0
        )
    
    # Filtrelenmiş veri
    filtered_df = df.copy()
    
    if selected_address != "Tümü":
        filtered_df = filtered_df[filtered_df['Depo Adresi'] == selected_address]
    
    if selected_durum == "Sayıldı":
        filtered_df = filtered_df[filtered_df['Sayım Durumu'] == 'Sayıldı']
    elif selected_durum == "Bulunamadı":
        filtered_df = filtered_df[filtered_df['Sayım Durumu'] == 'Bulunamadı']
    elif selected_durum == "Sayılmadı":
        filtered_df = filtered_df[filtered_df['Sayım Durumu'].isna() | (filtered_df['Sayım Durumu'] == '')]
    
    # Rapor tablosu
    if not filtered_df.empty:
        # Görüntülenecek sütunları belirle
        display_columns = ['Depo Adresi', 'Taşıma Birimi (TB)', 'Parti', 'Miktar', 'Sayım Durumu']
        
        # Opsiyonel sütunları ekle
        optional_columns = ['Sayım Yapan', 'Sayım Tarihi', 'Sayım Başlama Tarihi', 'Sayım Bitiş Tarihi']
        for col in optional_columns:
            if col in filtered_df.columns:
                display_columns.append(col)
        
        # Mevcut sütunları filtrele
        available_columns = [col for col in display_columns if col in filtered_df.columns]
        
        st.dataframe(
            filtered_df[available_columns],
            use_container_width=True
        )
        
        # Özet istatistikler
        st.markdown("### 📈 Özet İstatistikler")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Toplam TB", len(df))
        
        with col2:
            sayilan_count = len(df[df['Sayım Durumu'] == 'Sayıldı'])
            st.metric("Sayılan TB", sayilan_count)
        
        with col3:
            bulunamayan_count = len(df[df['Sayım Durumu'] == 'Bulunamadı'])
            st.metric("Bulunamayan TB", bulunamayan_count)
        
        with col4:
            sayilmayan_count = len(df[df['Sayım Durumu'].isna() | (df['Sayım Durumu'] == '')])
            st.metric("Sayılmayan TB", sayilmayan_count)
    else:
        st.info("Seçilen filtrelere uygun veri bulunamadı.")

else:
    st.error("❌ Veriler yüklenemedi. Lütfen aşağıdaki kontrolleri yapın:")
    st.markdown("""
    ## 🔧 Kurulum Rehberi
    
    ### 1. Google Service Account Oluşturma
    1. [Google Cloud Console](https://console.cloud.google.com/) gidin
    2. Yeni bir proje oluşturun veya mevcut projeyi seçin
    3. **APIs & Services > Credentials** bölümüne gidin
    4. **Create Credentials > Service Account** seçin
    5. Service account oluşturun
    6. **Keys** sekmesinden **Add Key > Create New Key > JSON** seçin
    7. JSON dosyasını indirin
    
    ### 2. Google Sheets API Etkinleştirme
    1. **APIs & Services > Library** bölümüne gidin
    2. "Google Sheets API" arayın ve etkinleştirin
    3. "Google Drive API" arayın ve etkinleştirin
    
    ### 3. Spreadsheet Erişim İzni
    1. Google Sheets dosyanızı açın
    2. **Share** butonuna tıklayın
    3. Service account email adresini ekleyin (JSON'da `client_email`)
    4. **Editor** yetkisi verin
    
    ### 4. secrets.toml Dosyası
    Proje dizininizde `.streamlit/secrets.toml` dosyası oluşturun:
    """)
    
    # secrets.toml örneği göster
    st.code("""
[gcp_service_account]
type = "service_account"
project_id = "your-project-id"
private_key_id = "your-private-key-id"
private_key = "-----BEGIN PRIVATE KEY-----\\nYOUR_PRIVATE_KEY_HERE\\n-----END PRIVATE KEY-----\\n"
client_email = "your-service-account@your-project.iam.gserviceaccount.com"
client_id = "your-client-id"
auth_uri = "https://accounts.google.com/o/oauth2/auth"
token_uri = "https://oauth2.googleapis.com/token"
auth_provider_x509_cert_url = "https://www.googleapis.com/oauth2/v1/certs"
client_x509_cert_url = "https://www.googleapis.com/robot/v1/metadata/x509/your-service-account%40your-project.iam.gserviceaccount.com"

[spreadsheet]
id = "your_spreadsheet_id_here"

[users]
admin = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"  # password: hello
user1 = "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"  # password: secret123
    """, language="toml")
    
    st.markdown("""
    ### 5. Spreadsheet Yapısı
    Excel/Google Sheets dosyanızda şu sütunlar olmalı:
    - `Depo Adresi` (zorunlu)
    - `Taşıma Birimi (TB)` (zorunlu)
    - `Parti` (opsiyonel)
    - `Miktar` (opsiyonel)
    
    Diğer sütunlar otomatik olarak eklenecek:
    - `Sayım Durumu`
    - `Sayım Yapan`
    - `Sayım Tarihi`
    - `Sayım Başlama Tarihi`
    - `Sayım Bitiş Tarihi`
    """)
    
    # Hata ayıklama bilgileri
    with st.expander("🔧 Detaylı Hata Ayıklama"):
        st.write("**Mevcut secrets kontrol ediliyor...**")
        
        # Secrets kontrol et
        try:
            secrets_keys = list(st.secrets.keys())
            st.write(f"**Mevcut secrets anahtarları:** {secrets_keys}")
            
            if "gcp_service_account" in st.secrets:
                st.success("✅ gcp_service_account bulundu")
                gcp_keys = list(st.secrets["gcp_service_account"].keys())
                st.write(f"**GCP Service Account anahtarları:** {gcp_keys}")
            else:
                st.error("❌ gcp_service_account bulunamadı")
                
            if "spreadsheet" in st.secrets:
                st.success("✅ spreadsheet bulundu")
                if "id" in st.secrets["spreadsheet"]:
                    st.success("✅ spreadsheet ID bulundu")
                else:
                    st.error("❌ spreadsheet ID bulunamadı")
            else:
                st.error("❌ spreadsheet bulunamadı")
                
            if "users" in st.secrets:
                st.success("✅ users bulundu")
                users_list = list(st.secrets["users"].keys())
                st.write(f"**Kullanıcılar:** {users_list}")
            else:
                st.error("❌ users bulunamadı")
                
        except Exception as e:
            st.error(f"❌ Secrets kontrol hatası: {str(e)}")
            
        st.markdown("---")
        st.markdown("""
        ### 📚 Faydalı Linkler:
        - [Google Sheets API Python Hızlı Başlangıç](https://developers.google.com/sheets/api/quickstart/python)
        - [Streamlit Secrets Management](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/secrets-management)
        - [gspread Dokumentasyonu](https://docs.gspread.org/en/latest/)
        """)
    
    # Test amaçlı manuel veri girişi seçeneği
    st.markdown("---")
    st.subheader("🧪 Test Modu")
    st.info("Google Sheets bağlantısı kurulamadığında test için kullanabilirsiniz.")
    
    if st.button("📝 Test Verisi Oluştur"):
        # Test verisi oluştur
        test_data = {
            'Depo Adresi': ['A01-01-01', 'A01-01-02', 'A01-01-03', 'B02-01-01'],
            'Taşıma Birimi (TB)': ['TB001', 'TB002', 'TB003', 'TB004'],
            'Parti': ['P001', 'P002', 'P003', 'P004'],
            'Miktar': [100, 200, 150, 300],
            'Sayım Durumu': ['', '', '', ''],
            'Sayım Yapan': ['', '', '', ''],
            'Sayım Tarihi': ['', '', '', '']
        }
        
        test_df = pd.DataFrame(test_data)
        st.dataframe(test_df, use_container_width=True)
        st.success("✅ Test verisi oluşturuldu! (Sadece görüntüleme amaçlı)")