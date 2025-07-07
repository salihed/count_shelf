import streamlit as st
import pandas as pd
import gspread
from google.oauth2 import service_account
import json
import hashlib
from datetime import datetime
import time
import random
from typing import Dict, List, Optional, Tuple

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
    
    .rate-limit-warning {
        background-color: #FEF3C7;
        color: #92400E;
        padding: 1rem;
        border-radius: 10px;
        margin: 1rem 0;
        border-left: 4px solid #F59E0B;
        text-align: center;
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

# Rate Limiter sınıfı
class RateLimiter:
    def __init__(self, max_calls=30, time_window=60):
        self.max_calls = max_calls
        self.time_window = time_window
        if 'api_calls' not in st.session_state:
            st.session_state.api_calls = []
    
    def wait_if_needed(self):
        now = time.time()
        # Eski çağrıları temizle
        st.session_state.api_calls = [
            call_time for call_time in st.session_state.api_calls 
            if now - call_time < self.time_window
        ]
        
        if len(st.session_state.api_calls) >= self.max_calls:
            sleep_time = self.time_window - (now - st.session_state.api_calls[0])
            if sleep_time > 0:
                st.warning(f"⏳ Rate limit koruması: {int(sleep_time)} saniye bekleniyor...")
                time.sleep(sleep_time)
                st.session_state.api_calls = []
        
        st.session_state.api_calls.append(now)

# Global rate limiter
rate_limiter = RateLimiter(max_calls=30, time_window=60)

# Retry decorator
def retry_on_quota_error(max_retries=3, base_delay=2):
    def decorator(func):
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    error_str = str(e).lower()
                    if "quota" in error_str or "429" in error_str or "rate" in error_str:
                        if attempt < max_retries - 1:
                            delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                            st.warning(f"⏳ Rate limit hatası, {int(delay)} saniye beklenip tekrar denenecek...")
                            time.sleep(delay)
                            continue
                        else:
                            st.error("⚠️ Rate limit hatası: Lütfen birkaç dakika bekleyip tekrar deneyin.")
                            return None
                    else:
                        raise e
            return None
        return wrapper
    return decorator

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

def logout():
    """Kullanıcıyı çıkış yapar"""
    for key in ['authenticated', 'username', 'current_address', 'messages', 'data_cache', 'sheet_cache']:
        if key in st.session_state:
            del st.session_state[key]
    st.rerun()

# Google Sheets bağlantısı
@st.cache_resource
def init_google_sheets():
    """Google Sheets bağlantısını başlatır - optimize edilmiş versiyon"""
    try:
        if "gcp_service_account" not in st.secrets:
            st.error("❌ Google Service Account bilgileri bulunamadı!")
            return None
        
        # Service account credentials'ı oluştur
        credentials = service_account.Credentials.from_service_account_info(
            st.secrets["gcp_service_account"],
            scopes=[
                'https://www.googleapis.com/auth/spreadsheets',
                'https://www.googleapis.com/auth/drive'
            ]
        )
        
        # gspread client'ı oluştur
        client = gspread.authorize(credentials)
        return client
        
    except Exception as e:
        st.error(f"Google Sheets bağlantısı kurulamadı: {str(e)}")
        return None

@st.cache_resource
def get_spreadsheet():
    """Spreadsheet'i cache'li olarak alır"""
    try:
        client = init_google_sheets()
        if client is None:
            return None, None
        
        if "spreadsheet" not in st.secrets or "id" not in st.secrets["spreadsheet"]:
            st.error("❌ Spreadsheet ID bulunamadı!")
            return None, None
        
        spreadsheet_id = st.secrets["spreadsheet"]["id"]
        spreadsheet = client.open_by_key(spreadsheet_id)
        
        return spreadsheet, spreadsheet_id
    except Exception as e:
        st.error(f"Spreadsheet erişim hatası: {str(e)}")
        return None, None

@st.cache_data(ttl=300)  # 5 dakika cache
@retry_on_quota_error(max_retries=3, base_delay=2)
def load_data_cached():
    """Google Sheets'ten veri yükler - cache'li ve optimize edilmiş"""
    try:
        rate_limiter.wait_if_needed()
        
        spreadsheet, spreadsheet_id = get_spreadsheet()
        if spreadsheet is None:
            return None
        
        sheet = spreadsheet.sheet1
        
        # Tüm verileri tek seferde al
        all_values = sheet.get_all_values()
        if not all_values:
            return None
        
        # DataFrame'e çevir
        df = pd.DataFrame(all_values[1:], columns=all_values[0])
        
        # Boş satırları temizle
        df = df.dropna(subset=['Depo Adresi', 'Taşıma Birimi (TB)'])
        
        # Veri tiplerini optimize et
        df = df.reset_index(drop=True)
        
        return df
        
    except Exception as e:
        st.error(f"Veri yükleme hatası: {str(e)}")
        return None

def ensure_required_columns():
    """Gerekli sütunların var olduğundan emin olur"""
    try:
        rate_limiter.wait_if_needed()
        
        spreadsheet, _ = get_spreadsheet()
        if spreadsheet is None:
            return False
        
        sheet = spreadsheet.sheet1
        
        # Başlık satırını al
        header_row = sheet.row_values(1)
        
        # Gerekli sütunları kontrol et
        required_columns = [
            'Sayım Durumu', 'Sayım Yapan', 'Sayım Tarihi', 
            'Sayım Başlama Tarihi', 'Sayım Bitiş Tarihi'
        ]
        
        # Eksik sütunları bul
        missing_columns = [col for col in required_columns if col not in header_row]
        
        if missing_columns:
            # Batch update ile eksik sütunları ekle
            current_col = len(header_row) + 1
            batch_updates = []
            
            for col in missing_columns:
                batch_updates.append({
                    'range': f'{chr(64 + current_col)}1',
                    'values': [[col]]
                })
                current_col += 1
            
            if batch_updates:
                sheet.batch_update(batch_updates)
                st.cache_data.clear()  # Cache'i temizle
        
        return True
        
    except Exception as e:
        st.error(f"Sütun kontrol hatası: {str(e)}")
        return False

@retry_on_quota_error(max_retries=3, base_delay=2)
def batch_update_sayim_durumu(updates_list: List[Dict]):
    """Sayım durumunu batch update ile günceller"""
    try:
        rate_limiter.wait_if_needed()
        
        spreadsheet, _ = get_spreadsheet()
        if spreadsheet is None:
            return False
        
        sheet = spreadsheet.sheet1
        
        # Gerekli sütunları kontrol et
        if not ensure_required_columns():
            return False
        
        # Başlık satırını al
        header_row = sheet.row_values(1)
        
        # Sütun indekslerini bul
        column_indices = {}
        for col_name in ['Depo Adresi', 'Taşıma Birimi (TB)', 'Sayım Durumu', 
                        'Sayım Yapan', 'Sayım Tarihi', 'Sayım Başlama Tarihi', 'Sayım Bitiş Tarihi']:
            if col_name in header_row:
                column_indices[col_name] = header_row.index(col_name)
        
        # Tüm verileri al
        all_values = sheet.get_all_values()
        
        # Batch updates hazırla
        batch_updates = []
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        for update in updates_list:
            # İlgili satırı bul
            for i, row in enumerate(all_values[1:], start=2):
                if (len(row) > column_indices['Taşıma Birimi (TB)'] and 
                    str(row[column_indices['Taşıma Birimi (TB)']]).strip() == str(update['tb']).strip()):
                    
                    # Güncelleme verilerini hazırla
                    if update['type'] == 'sayim':
                        batch_updates.extend([
                            {
                                'range': f'{chr(65 + column_indices["Sayım Durumu"])}{i}',
                                'values': [[update['durum']]]
                            },
                            {
                                'range': f'{chr(65 + column_indices["Sayım Yapan"])}{i}',
                                'values': [[update['username']]]
                            },
                            {
                                'range': f'{chr(65 + column_indices["Sayım Tarihi"])}{i}',
                                'values': [[current_time]]
                            }
                        ])
                    elif update['type'] == 'address_start':
                        batch_updates.append({
                            'range': f'{chr(65 + column_indices["Sayım Başlama Tarihi"])}{i}',
                            'values': [[current_time]]
                        })
                    elif update['type'] == 'address_end':
                        batch_updates.append({
                            'range': f'{chr(65 + column_indices["Sayım Bitiş Tarihi"])}{i}',
                            'values': [[current_time]]
                        })
                    break
        
        # Batch update'i gerçekleştir
        if batch_updates:
            # Batch'leri 100'lük gruplar halinde böl (API limitinden dolayı)
            for i in range(0, len(batch_updates), 100):
                batch_chunk = batch_updates[i:i+100]
                sheet.batch_update(batch_chunk)
                time.sleep(0.1)  # Kısa bekleme
        
        # Cache'i temizle
        st.cache_data.clear()
        
        return True
        
    except Exception as e:
        st.error(f"Batch güncelleme hatası: {str(e)}")
        return False

def update_sayim_durumu(tb_value: str, durum: str, username: str):
    """Tekil sayım durumu güncelleme"""
    updates = [{
        'tb': tb_value,
        'durum': durum,
        'username': username,
        'type': 'sayim'
    }]
    return batch_update_sayim_durumu(updates)

def update_address_sayim_durumu(address: str, durum: str, username: str):
    """Adres bazında sayım durumu güncelleme"""
    try:
        df = load_data_cached()
        if df is None:
            return False
        
        # Adrese ait TB'leri bul
        address_tbs = df[df['Depo Adresi'] == address]
        
        if address_tbs.empty:
            return False
        
        # Update listesini hazırla
        updates = []
        update_type = 'address_start' if durum == 'Başladı' else 'address_end'
        
        for _, row in address_tbs.iterrows():
            updates.append({
                'tb': row['Taşıma Birimi (TB)'],
                'durum': durum,
                'username': username,
                'type': update_type
            })
        
        return batch_update_sayim_durumu(updates)
        
    except Exception as e:
        st.error(f"Adres durumu güncelleme hatası: {str(e)}")
        return False

def finish_address_sayim(address: str, username: str):
    """Adres sayımını bitir - sayılmayan TB'leri 'Bulunamadı' yap"""
    try:
        df = load_data_cached()
        if df is None:
            return False, []
        
        # Adrese ait sayılmayan TB'leri bul
        address_tbs = df[df['Depo Adresi'] == address]
        sayilmayan_tbs = address_tbs[
            address_tbs['Sayım Durumu'].isna() | 
            (address_tbs['Sayım Durumu'] == '') |
            (address_tbs['Sayım Durumu'] == 'Sayılmadı')
        ]
        
        if not sayilmayan_tbs.empty:
            # Sayılmayan TB'leri 'Bulunamadı' olarak işaretle
            updates = []
            for _, row in sayilmayan_tbs.iterrows():
                updates.append({
                    'tb': row['Taşıma Birimi (TB)'],
                    'durum': 'Bulunamadı',
                    'username': username,
                    'type': 'sayim'
                })
            
            # Batch güncelleme
            if batch_update_sayim_durumu(updates):
                # Adres bitiş tarihini güncelle
                update_address_sayim_durumu(address, 'Tamamlandı', username)
                return True, sayilmayan_tbs.to_dict('records')
        else:
            # Adres bitiş tarihini güncelle
            update_address_sayim_durumu(address, 'Tamamlandı', username)
            return True, []
            
    except Exception as e:
        st.error(f"Adres sayımı bitirme hatası: {str(e)}")
        return False, []

def get_address_tbs(df: pd.DataFrame, address: str) -> pd.DataFrame:
    """Bir adrese ait TB'leri döndürür"""
    if df is not None and not df.empty:
        return df[df['Depo Adresi'] == address]
    return pd.DataFrame()

def tb_exists_in_address(df: pd.DataFrame, address: str, tb_input: str) -> Tuple[bool, Optional[pd.Series]]:
    """TB'nin belirtilen adreste var olup olmadığını kontrol eder"""
    address_data = get_address_tbs(df, address)
    if address_data.empty:
        return False, None
    
    # TB sütununu string'e çevir ve karşılaştır
    tb_input_str = str(tb_input).strip()
    
    # Exact match ara
    for idx, row in address_data.iterrows():
        if str(row['Taşıma Birimi (TB)']).strip() == tb_input_str:
            return True, row
    
    return False, None

def count_sayilan_tbs(df: pd.DataFrame, address: str) -> int:
    """Sayılan TB sayısını döndürür"""
    address_data = get_address_tbs(df, address)
    if not address_data.empty:
        return len(address_data[address_data['Sayım Durumu'] == 'Sayıldı'])
    return 0

# Session state başlatma
def init_session_state():
    """Session state'i başlatır"""
    defaults = {
        'authenticated': False,
        'username': None,
        'current_address': None,
        'messages': [],
        'api_calls': [],
        'data_cache': None,
        'last_data_update': None
    }
    
    for key, default_value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default_value

# Session state'i başlat
init_session_state()

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

# Rate limit durumunu göster
if len(st.session_state.api_calls) > 20:
    st.markdown(f'''
    <div class="rate-limit-warning">
        ⚠️ API Kullanım Durumu: {len(st.session_state.api_calls)}/30 (Son 1 dakika)
    </div>
    ''', unsafe_allow_html=True)

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
    
    # API kullanım durumu
    st.subheader("📊 API Durumu")
    st.write(f"**Son 1 dakika:** {len(st.session_state.api_calls)}/30 çağrı")
    
    # Spreadsheet bilgileri
    st.subheader("📋 Spreadsheet")
    try:
        spreadsheet, spreadsheet_id = get_spreadsheet()
        if spreadsheet:
            st.write(f"**Başlık:** {spreadsheet.title}")
            st.write(f"**Sayfa:** {len(spreadsheet.worksheets())}")
        else:
            st.error("Bağlantı hatası!")
    except Exception as e:
        st.error(f"Hata: {str(e)}")

# Ana uygulama
# Verileri yükle
df = load_data_cached()

if df is not None and not df.empty:
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
                if address_input in df['Depo Adresi'].values:
                    # Önceki adresin sayımını tamamla
                    if st.session_state.current_address:
                        success, bulunamayan_list = finish_address_sayim(
                            st.session_state.current_address, 
                            st.session_state.username
                        )
                        
                        if success and bulunamayan_list:
                            st.session_state.messages.append({
                                'type': 'warning',
                                'message': f"Önceki adres tamamlandı. {len(bulunamayan_list)} TB bulunamadı olarak işaretlendi."
                            })
                    
                    # Yeni adresi seç ve sayımı başlat
                    st.session_state.current_address = address_input
                    st.session_state.messages = []
                    
                    # Adres sayımını başlat
                    if update_address_sayim_durumu(address_input, 'Başladı', st.session_state.username):
                        st.session_state.messages.append({
                            'type': 'success',
                            'message': f"Adres seçildi ve sayım başlatıldı: {address_input}"
                        })
                    
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
            # TB'yi kontrol et
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
                    original_tb = tb_row['Taşıma Birimi (TB)']
                    if update_sayim_durumu(str(original_tb), 'Sayıldı', st.session_state.username):
                        st.session_state.messages.append({
                            'type': 'success',
                            'message': f"TB başarıyla kaydedildi: {tb_input}"
                        })
                        st.cache_data.clear()  # Cache'i temizle
                        st.rerun()
                    else:
                        st.session_state.messages.append({
                            'type': 'error',
                            'message': f"TB kaydedilirken hata oluştu: {tb_input}"
                        })
            else:
                # TB bu adreste yok
                st.session_state.messages.append({
                    'type': 'error',
                    'message': f"Bu TB bu adreste bulunamadı: {tb_input}"
                })

    st.markdown('</div>', unsafe_allow_html=True)

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
                success, bulunamayan_list = finish_address_sayim(
                    st.session_state.current_address, 
                    st.session_state.username
                )

                if success:
                    if bulunamayan_list:
                        st.warning(f"⚠️ {len(bulunamayan_list)} adet TB bulunamadı olarak işaretlendi:")

                        # Bulunamayan TB'leri göster
                        for tb_data in bulunamayan_list:
                            st.write(f"- **TB:** {tb_data['Taşıma Birimi (TB)']} | **Parti:** {tb_data.get('Parti', 'N/A')} | **Miktar:** {tb_data.get('Miktar', 'N/A')}")
                    else:
                        st.success("✅ Bu adresteki tüm TB'ler sayıldı!")

                    st.cache_data.clear()
                    st.session_state.current_address = None
                    st.session_state.messages = []
                    st.rerun()
                else:
                    st.error("❌ Adres sayımı bitirilemedi. Lütfen tekrar deneyin.")

   
    # Rapor sekmesi
    st.markdown("---")
    st.subheader("📊 Sayım Durumu Raporu")
    
    # Filtreler
    col1, col2 = st.columns(2)
    with col1:
        selected_address = st.selectbox(
            "Adres Seçin:",
            options=["Tümü"] + sorted(df['Depo Adresi'].unique()),
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
            use_container_width=True,
            hide_index=True
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
        
        # İlerleme yüzdesi
        if len(df) > 0:
            completion_rate = (sayilan_count + bulunamayan_count) / len(df) * 100
            st.progress(completion_rate / 100)
            st.write(f"**Tamamlanma Oranı:** {completion_rate:.1f}%")
    else:
        st.info("Seçilen filtrelere uygun veri bulunamadı.")
    
    # Adres bazında özet
    st.markdown("### 📍 Adres Bazında Özet")
    address_summary = df.groupby('Depo Adresi').agg({
        'Taşıma Birimi (TB)': 'count',
        'Sayım Durumu': lambda x: (x == 'Sayıldı').sum()
    }).rename(columns={
        'Taşıma Birimi (TB)': 'Toplam_TB',
        'Sayım Durumu': 'Sayılan_TB'
    })
    
    address_summary['Bulunamayan_TB'] = df.groupby('Depo Adresi')['Sayım Durumu'].apply(lambda x: (x == 'Bulunamadı').sum())
    address_summary['Sayılmayan_TB'] = address_summary['Toplam_TB'] - address_summary['Sayılan_TB'] - address_summary['Bulunamayan_TB']
    address_summary['Tamamlanma_Oranı'] = ((address_summary['Sayılan_TB'] + address_summary['Bulunamayan_TB']) / address_summary['Toplam_TB'] * 100).round(1)
    
    st.dataframe(address_summary, use_container_width=True)

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
    
    ### 4. Gerekli Kütüphaneler
    Aşağıdaki kütüphaneleri yükleyin:
    """)
    
    st.code("""
    pip install --upgrade gspread>=5.12.0 google-auth>=2.17.0 google-auth-oauthlib>=1.0.0 google-auth-httplib2>=0.1.0 pandas>=1.5.0 streamlit>=1.28.0
    """, language="bash")
    
    st.markdown("""
    ### 5. secrets.toml Dosyası
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
    ### 6. Spreadsheet Yapısı
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

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666; font-size: 0.9em;">
    <p>📦 Depo Sayım Programı v2.0 | Geliştirici: AI Assistant</p>
    <p>⚡ Streamlit ile geliştirilmiştir</p>
    </div>
    """, unsafe_allow_html=True)