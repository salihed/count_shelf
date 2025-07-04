import streamlit as st
import pandas as pd
import gspread
from google.oauth2.service_account import Credentials
import json
import hashlib
from datetime import datetime

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
    .current-address {
    
    .main-header {
        text-align: center;
        color: #2E86AB;
        font-size: 2.5rem;
        margin-bottom: 2rem;
    }
        background-color: #E8F4FD;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        margin-bottom: 1rem;
        font-size: 1.2rem;
        color: #1E3A8A;
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
        # Service account credentials (secrets.toml'da saklanmalı)
        creds_dict = st.secrets["gcp_service_account"]
        creds = Credentials.from_service_account_info(creds_dict)
        client = gspread.authorize(creds)
        return client
    except Exception as e:
        st.error(f"Google Sheets bağlantısı kurulamadı: {str(e)}")
        return None

@st.cache_data(ttl=60)  # 1 dakika cache
def load_data(sheet_url):
    """Google Sheets'ten veri yükler"""
    try:
        client = init_google_sheets()
        if client is None:
            return None
        
        sheet = client.open_by_url(sheet_url).sheet1
        data = sheet.get_all_records()
        df = pd.DataFrame(data)
        
        # Boş satırları temizle
        df = df.dropna(subset=['Depo Adresi', 'Taşıma Birimi (TB)'])
        
        return df, sheet
    except Exception as e:
        st.error(f"Veri yükleme hatası: {str(e)}")
        return None, None

def update_sayim_durumu(sheet, tb_value, durum, username):
    """Sayım durumunu günceller"""
    try:
        # Tüm verileri al
        all_values = sheet.get_all_values()
        
        # Sütun indekslerini bul
        header_row = all_values[0]
        tb_col = header_row.index('Taşıma Birimi (TB)') + 1
        durum_col = header_row.index('Sayım Durumu') + 1
        
        # Sayım yapan kullanıcı sütunu var mı kontrol et
        sayim_yapan_col = None
        if 'Sayım Yapan' in header_row:
            sayim_yapan_col = header_row.index('Sayım Yapan') + 1
        
        # Sayım tarihi sütunu var mı kontrol et
        sayim_tarihi_col = None
        if 'Sayım Tarihi' in header_row:
            sayim_tarihi_col = header_row.index('Sayım Tarihi') + 1
        
        # TB'yi bul ve güncelle
        for i, row in enumerate(all_values[1:], start=2):
            if row[tb_col-1] == tb_value:
                # Sayım durumunu güncelle
                sheet.update_cell(i, durum_col, durum)
                
                # Sayım yapan kullanıcıyı güncelle
                if sayim_yapan_col:
                    sheet.update_cell(i, sayim_yapan_col, username)
                
                # Sayım tarihini güncelle
                if sayim_tarihi_col:
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    sheet.update_cell(i, sayim_tarihi_col, current_time)
                
                break
        
        return True
    except Exception as e:
        st.error(f"Güncelleme hatası: {str(e)}")
        return False

def get_address_tbs(df, address):
    """Bir adrese ait TB'leri döndürür"""
    address_data = df[df['Depo Adresi'] == address]
    return address_data

def count_sayilan_tbs(df, address):
    """Sayılan TB sayısını döndürür"""
    address_data = get_address_tbs(df, address)
    sayilan_count = len(address_data[address_data['Sayım Durumu'] == 'Sayıldı'])
    return sayilan_count

# Session state başlatma
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'username' not in st.session_state:
    st.session_state.username = None
if 'current_address' not in st.session_state:
    st.session_state.current_address = None
if 'messages' not in st.session_state:
    st.session_state.messages = []
if 'sheet_url' not in st.session_state:
    st.session_state.sheet_url = ""

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

# Sidebar - Konfigürasyon
with st.sidebar:
    st.header("⚙️ Konfigürasyon")
    
    sheet_url = st.text_input(
        "Google Sheets URL:",
        value=st.session_state.sheet_url,
        placeholder="https://docs.google.com/spreadsheets/d/...",
        help="Sayım verilerinin bulunduğu Google Sheets URL'sini girin"
    )
    
    if sheet_url != st.session_state.sheet_url:
        st.session_state.sheet_url = sheet_url
        st.rerun()
    
    st.markdown("---")
    
    if st.button("🔄 Verileri Yenile"):
        st.cache_data.clear()
        st.rerun()
    
    if st.button("🗑️ Oturumu Temizle"):
        st.session_state.current_address = None
        st.session_state.messages = []
        st.rerun()

# Ana uygulama
if st.session_state.sheet_url:
    # Verileri yükle
    data_result = load_data(st.session_state.sheet_url)
    
    if data_result[0] is not None:
        df, sheet = data_result
        
        # Mevcut adres gösterimi
        if st.session_state.current_address:
            st.markdown(f'<div class="current-address">Bu adres sayılıyor: <strong>{st.session_state.current_address}</strong></div>', 
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
                        st.session_state.current_address = address_input
                        st.session_state.messages = []
                        st.rerun()
                    else:
                        st.error("Bu adres sistemde bulunamadı!")
        
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
                    address_tbs = get_address_tbs(df, st.session_state.current_address)
                    tb_row = address_tbs[address_tbs['Taşıma Birimi (TB)'] == tb_input]
                    
                    if not tb_row.empty:
                        # TB bu adreste var mı?
                        current_durum = tb_row['Sayım Durumu'].iloc[0]
                        
                        if current_durum == 'Sayıldı':
                            # Daha önce sayılmış
                            st.session_state.messages.append({
                                'type': 'warning',
                                'message': f"Bu TB daha önce sayıldı: {tb_input}"
                            })
                        else:
                            # TB'yi sayıldı olarak işaretle
                            if update_sayim_durumu(sheet, tb_input, 'Sayıldı', st.session_state.username):
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
            if 'Sayım Yapan' in filtered_df.columns:
                display_columns.append('Sayım Yapan')
            if 'Sayım Tarihi' in filtered_df.columns:
                display_columns.append('Sayım Tarihi')
            
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
        st.error("Veriler yüklenemedi. Google Sheets URL'sini ve erişim izinlerini kontrol edin.")

else:
    st.info("👈 Lütfen soldaki menüden Google Sheets URL'sini girin.")
    
