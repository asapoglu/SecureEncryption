
## 1. Giriş

### 1.1 Amaç
Bu projenin amacı veri güvenliği için kullanılan temel şifreleme tekniklerini uygulamalı olarak deneyimlemek ve farklı şifreleme algoritmalarının etkinliğini değerlendirmektir. Proje veri şifreleme, şifre çözme, dijital imza oluşturma ve doğrulama işlemlerini içeren pratik uygulamalarla şifreleme tekniklerinin gerçek dünya kullanımına dair bilgi ve becerileri geliştirmeyi hedefler.
<img src="Screenshot/Main%20Scene.png" alt="Main Scene" width="400"/>
### 1.2 Kullanılan Teknikler
- **RSA (Rivest-Shamir-Adleman)**: Açık anahtarlı şifreleme alanında öncülerden biridir. RSA özellikle dijital imza oluşturma ve anahtar yönetimi için kullanılır. Bu projede simetrik anahtarları güvenli bir şekilde iletmek için RSA'nın açık ve özel anahtar çifti kullanılarak veri şifrelemesi ve şifre çözme işlemleri gerçekleştirilmektedir.
- **AES (Advanced Encryption Standard)**: Simetrik anahtarlı şifreleme alanında yaygın olarak kullanılan bir standarttır. Proje kapsamında AES'in farklı anahtar boyutları (128 ve 256 bit) ve şifreleme modları (CBC ve CTR) kullanılarak veri şifreleme ve çözme işlemleri yapılır.
- **SHA-256 (Secure Hash Algorithm 256-bit)**: Verilerin bütünlüğünü sağlamak için kullanılan güvenilir bir kriptografik hash algoritmasıdır. Projede uzun bir metnin mesaj özeti oluşturulup RSA ile dijital olarak imzalanarak veri bütünlüğü ve kimlik doğrulama sağlanmaktadır.

Bu proje RSA ile simetrik anahtar şifreleme ve şifre çözme, AES ile veri şifreleme ve şifre çözme, ve SHA-256 ile dijital imza oluşturma ve doğrulama işlemlerini bir araya getirerek veri güvenliğinin çeşitli yönlerini ele almaktadır. Farklı şifreleme algoritmalarının performansını ve etkinliğini analiz etmek amacıyla ölçümler ve karşılaştırmalar yapılmıştır.

---

## 2. RSA Şifreleme

### 2.1 Anahtar Oluşturma
RSA algoritması, güvenli veri iletimi ve dijital imzalar için kullanılan bir asimetrik şifreleme yöntemidir. RSA'da iki anahtar çifti bulunur: açık anahtar (public key) ve özel anahtar (private key). Bu anahtar çifti, şifreleme ve şifre çözme işlemlerinde karşılıklı olarak kullanılır.

Bu projede RSA anahtar çifti oluşturmak için `java.security` kütüphanesindeki `KeyPairGenerator` sınıfı kullanılmıştır.

```java
// RSA Anahtar Çifti Üretici oluştur
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
keyGen.initialize(2048); // RSA için 2048 bitlik anahtar boyutunu 
KeyPair pair = keyGen.generateKeyPair(); // Anahtar çiftini üret
PrivateKey privateKey = pair.getPrivate(); // Özel anahtarı al
PublicKey publicKey = pair.getPublic(); // Açık anahtarı al
```

<img src="Screenshot/RSA%20Key%20Pair%20Generator.png" alt="RSA Key Pair Generator" width="400"/>


Bu kod bloğu, RSA algoritmasını kullanarak bir açık-özel anahtar çifti oluşturur. RSA anahtar çiftini oluşturmak için şu adımlar takip edilir:
- **KeyPairGenerator Oluşturma**: RSA algoritması için KeyPairGenerator sınıfı kullanılır ve bir anahtar üretici oluşturulur.
- **Anahtar Boyutunu Belirleme**: Anahtar uzunluğu, RSA için güvenlik standardı olarak kabul edilen 2048 bit olarak ayarlanır.
- **Anahtar Çifti Üretimi**: Belirlenen bit uzunluğunda bir açık-özel anahtar çifti oluşturmak için generateKeyPair metodu kullanılır.
- **Özel ve Açık Anahtarları Alma**: Üretilen KeyPair nesnesinden özel ve açık anahtarlar sırasıyla getPrivate() ve getPublic() metodlarıyla alınır.

Bu şekilde oluşturulan RSA anahtar çifti, simetrik anahtarları şifrelemek ve şifre çözmek, dijital imzalar oluşturmak ve doğrulamak için kullanılabilir.


---

## 3. Simetrik Anahtar Üretimi ve RSA ile Şifrelenmesi

### 3.1 Simetrik Anahtarların Üretimi
- **128 Bit Anahtar (K1)**: AES algoritması için KeyGenerator sınıfı kullanılarak 128 bit uzunluğunda simetrik anahtar üretilmiştir.
- **256 Bit Anahtar (K2)**: Aynı yöntemle, 256 bit uzunluğunda bir başka simetrik anahtar üretilmiştir.

```java
// Simetrik Anahtarlar Üret
KeyGenerator keyGen128 = KeyGenerator.getInstance("AES");
keyGen128.init(128); // Anahtar boyutunu 128 bit olarak ayarla
SecretKey key128 = keyGen128.generateKey(); // 128 bit AES anahtarı

KeyGenerator keyGen256 = KeyGenerator.getInstance("AES");
keyGen256.init(256); // Anahtar boyutunu 256 bit olarak ayarla
SecretKey key256 = keyGen256.generateKey(); // 256 bit AES anahtarı
```

### 3.2 RSA ile Şifreleme ve Şifre Çözme
- **Şifreleme**: RSA açık anahtarı (KA+) ile her iki simetrik anahtar da ayrı ayrı şifrelenmiştir. Bu işlem simetrik anahtarların güvenli bir şekilde aktarılması veya depolanmasını sağlar.
- **Şifre Çözme**: Şifrelenmiş simetrik anahtarlar, RSA özel anahtarı (KA−) ile çözülmüştür. Böylece, yalnızca özel anahtara sahip olanlar şifrelenmiş veriyi çözebilir ve anahtarları tekrar kullanabilir.

```java
// RSA ile Şifreleme ve Şifre Çözme
Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
cipher.init(Cipher.ENCRYPT_MODE, publicKey);
byte[] encryptedKey128 = cipher.doFinal(key128.getEncoded());
byte[] encryptedKey256 = cipher.doFinal(key256.getEncoded());
cipher.init(Cipher.DECRYPT_MODE, privateKey);
byte[] decryptedKey128 = cipher.doFinal(encryptedKey128);
byte[] decryptedKey256 = cipher.doFinal(encryptedKey256);
```

### 3.3 Sonuçlar

<img src="Screenshot/Symmetric%20Key%20Encryption.png" alt="Symmetric Key Encryption" width="400"/>
Simetrik anahtarların şifrelenmiş ve şifresi çözülmüş halleri ekran çıktısında gösterilmiştir. Şifreleme ve şifre çözme işlemleri, RSA algoritmasının güçlü güvenlik özellikleriyle, simetrik anahtarların korunması için etkili bir yol sunar.

---

## 4. SHA-256 ve Dijital İmza

### 4.1 Hashing
Hashing, bir mesajın veya verinin sabit boyutlu bir özetini üretme sürecidir. Bu projede, SHA-256 algoritması kullanılarak uzun bir metnin özeti oluşturulmuştur. SHA-256, kriptografik olarak güvenilir bir hashing algoritması olup 256 bitlik bir özet üretir. Bu özet, verinin içeriğinin herhangi bir şekilde değiştirilip değiştirilmediğini tespit etmek için kullanılır.

```java
// SHA-256 kullanarak mesajın hash'ini oluşturma (mesaj özeti)
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] hash = digest.digest(message.getBytes());
```

### 4.2 Dijital İmza
Dijital imza, bir mesajın bütünlüğünü ve kaynağını doğrulamak için kullanılan bir mekanizmadır. Bu projede, RSA özel anahtarı ile dijital imza oluşturulmuştur. Dijital imza süreci şu adımlardan oluşur:

- **Mesaj Hash'i**: Mesaj, SHA-256 algoritması ile özetlenir.
- **İmza Oluşturma**: Özel anahtar, oluşturulan hash'in imzalanması için kullanılır.
- **İmza Doğrulama**: Mesajın hash'ini RSA açık anahtarı ile doğrulamak için mesajın hash'i ve dijital imza karşılaştırılır.

```java
// Özel anahtar kullanarak dijital imza oluşturma
Signature signature = Signature.getInstance("SHA256withRSA");
signature.initSign(privateKey);
signature.update(hash);
byte[] digitalSignature = signature.sign();
```

### 4.3 Sonuçlar

<img src="Screenshot/Hash%20and%20Digital%20Signature.png" alt="Hash and Digital Signature" width="400"/>

Bu proje, uzun bir metin için SHA-256 algoritması ile hash oluşturmayı ve bu hash'i RSA özel anahtarı ile dijital olarak imzalamayı içerir. Dijital imza daha sonra RSA açık anahtarı ile doğrulanır. Sonuçlar, mesajın bütünlüğünün ve kaynağının doğruluğunun onaylanmasını sağlar. İmzanın geçerliliği doğrulandığında, orijinal mesajın değiştirilmediği ve kaynağın doğrulandığı kanıtlanır.

```java
// Sonuçları ekrana yazdırma
System.out.println("Mesaj: " + message);
longMessage.setText(message);
hashTextArea.setText(bytesToHex(hash));
digitalSignatureTextArea.setText(bytesToHex(digitalSignature));

// Açık anahtar kullanarak dijital imzayı doğrulama
signature.initVerify(publicKey);
signature.update(hash);
boolean isVerified = signature.verify(digitalSignature);
verifiedButton.setSelected(isVerified);
```

---

## 5. AES Şifreleme

### 5.1 AES 128 CBC
AES (Advanced Encryption Standard), simetrik anahtarlı bir şifreleme algoritmasıdır. AES 128 CBC (Cipher Block Chaining), 128 bitlik bir anahtar kullanır ve şifreleme modunun bir parçası olarak her blok şifreleme işlemi sırasında bir önceki bloğun şifreli çıktısını kullanır. Bu proje kapsamında, 1MB'den büyük bir resim dosyası AES 128 CBC modunda şifrelenmiş ve şifresi çözülmüştür.

### 5.2 AES 256 CBC
AES 256 CBC, AES algoritmasının 256 bitlik bir anahtar kullanarak aynı CBC şifreleme modunu uygular. Daha uzun anahtar boyutu, şifrelemenin güvenlik düzeyini artırır. Projede, aynı resim dosyası AES 256 CBC ile şifrelenmiş ve şifresi çözülmüştür.

### 5.3 AES 256 CTR
AES 256 CTR (Counter) modu, blok şifrelemeyi blokları birbirinden bağımsız olarak şifreleyecek şekilde çalıştırır. 256 bitlik bir anahtar kullanır ve her bloğun şifresini çözmek için bir sayaç (counter) kullanır. Bu, paralel işlem için uygundur ve performans avantajı sağlar. Projede, aynı resim dosyası AES 256 CTR ile şifrelenmiş ve şifresi çözülmüştür.

---

### 5.4 Sonuçlar

<img src="Screenshot/AES%20File%20Encryption%20Scene.png" alt="AES File Encryption Scene" width="400"/>

<img src="Screenshot/Decrypt%20Time.png" alt="Decrypt Time" width="400"/>

<img src="Screenshot/Encrypt%20Time.png" alt="Encrypt Time" width="400"/>

Bu bölümde, AES şifreleme algoritmasının farklı modlarının şifreleme ve şifre çözme süreleri incelenmiştir. Testler 1MB'den büyük bir resim dosyası üzerinde yapılmış ve aşağıdaki sonuçlar elde edilmiştir:

  |   | Şifre Çözme Süresi |Şifre Çözme Süresi |
|------------------|---------------------|---------------------|
| AES 128 CBC      | 20 ms               | 30 ms              |
| AES 128 CBC (Yeni IV) | 6 ms           | 3 ms               |
| AES 256 CBC      | 7 ms                | 8 ms               |
| AES 256 CTR      | 11 ms               | 5 ms               |

### 5.5 Değerlendirme ve Yorumlar
- **AES 128 CBC**: Şifreleme süresi 20 ms ve şifre çözme süresi 30 ms'dir. CBC modunda IV'nin değiştirilmesi, şifreleme süresinde belirgin bir azalmaya neden olmuştur (20 ms'den 6 ms'ye düşüş). Bu değişiklik, farklı IV'lerin kullanılmasıyla her bloğun kendine özgü bir biçimde şifrelendiğini gösterir.
- **AES 256 CBC**: AES 256 CBC, 128 CBC'ye göre daha uzun bir anahtar boyutu kullansa da, şifreleme süresi şaşırtıcı bir şekilde daha kısadır (7 ms). Şifre çözme süresi ise benzer şekilde 8 ms'dir. Bu, güçlü bir anahtar yönetimine rağmen modern bilgisayar donanımlarının 256 bit işlemleri verimli bir şekilde yapabileceğini gösterir.
- **AES 256 CTR**: CTR modunda şifreleme ve şifre çözme süreleri sırasıyla 11 ms ve 5 ms'dir. CTR, her bir bloğu bağımsız olarak şifrelediği ve paralel işleme izin verdiği için performans açısından avantaj sağlayabilir.

Bu sonuçlar, AES şifreleme modları arasında güvenlik, performans ve işlem verimliliği arasındaki dengeyi gösterir. CBC modunda yeni bir IV'nin kullanılması, şifreleme performansını artırabilir, ancak güvenlik gereksinimleri de dikkate alınmalıdır.
