# GoodbyeDpi-DESTROYER3000 (YOKEDİCİ3000)

Bilgisayarınızın tamamını Goodbye DPI bileşenleri için tarar ve bunların hepsinden **zorla** kurtulmak için powershell ve güvenli modu kullanır

> [!CAUTION]
> ### Kendi sorumluluğunuzda kullanın. [LİSANS](LICENSE) dosyasına bakın ve aşağıdaki gri metinleri okuyun.

> GoodbyeDPI’yi silmekte zorlanan bir arkadaşım için bunu yazdım. Bu test edilmemiş uzun bir koddur ve GoodbyeDPI’yi ve kalıntılarını silmeye ve durdurmaya çalışırken bilgisayarınıza potansiyel olarak zarar verebilecek bir şey görürseniz kodu kendiniz kontrol edip düzenlemenizi tavsiye ederim.

> Bunu güvenlik hatalarını **KENDİNİZ** kontrol etmeden çalıştırmanızı önermem. Kodlamayı öğrenin.

> Bu ÇOK güçlü bir araçtır. Bu araca tamamen ve körü körüne güvenmenizi istemem.

Eğitim:

1-Bu github deposunu indirin/klonlayın

2-Yönetici ayrıcalıklarına sahip bir Powershell açın ve "Get-ExecutionPolicy" komutunu çalıştırın

2,5-Sonuç "Bypass" veya "Allsigned" değilse, "Set-ExecutionPolicy -ExecutionPolicy AllSigned" komutunu çalıştırın

3-Güvenli Modda yeniden başlatın

4-Dosyayı ya kendiniz dijital olarak imzalayın ya da yeni bir metin dosyası oluşturup kodu oraya kopyalayıp yapıştırın

5-O dosyayı [(Remove-GoodbyeDPI-Complete.ps1)](Remove-GoodbyeDPI-Complete.ps1) Yönetici yetkilerine sahip bir Powershell'de çalıştırın

6-GoodbyeDPI’den ve onu kaldırmaya çalışırken parçalanan zihinsel sağlığınıza ve bilgisayarınızın bağlantısına verdiği tüm sıkıntılardan kurtuldunuz, Bilgisayarı yeniden başlatın.

> [!IMPORTANT]
> Bu, orijinal İngilizce [Lisans](LICENSE) metninin gayriresmî Türkçe çevirisidir. Yasal geçerliliği olan metin İngilizce olandır.
> 
> MIT Lisansı
>
> Telif Hakkı (c) 2025 Lakunake
>
> İzin, işbu belgeyle, ücretsiz olarak, bu yazılımın ve ilişkili dokümantasyon dosyalarının (bundan sonra "Yazılım") bir kopyasını edinen herhangi bir kişiye, Yazılım üzerinde sınırlama olmaksızın işlem yapma hakkı verilmiştir; buna Yazılımı kullanma, kopyalama, değiştirme, birleştirme, yayımlama, dağıtma, alt lisans verme ve/veya Yazılımın kopyalarını satma hakları da dahildir ve Yazılımın sağlandığı kişilere bunları yapma izni verme hakkı verilir, aşağıdaki şartlara tabi olmak kaydıyla:
>
> Yukarıdaki telif hakkı bildirimi ve bu izin bildirimi, Yazılımın tüm kopyalarına veya önemli bölümlerine dahil edilecektir.
>
> YAZILIM "OLDUĞU GİBİ" SAĞLANMAKTADIR, AÇIK VEYA ZIMNİ HERHANGİ BİR GARANTİ OLMADAN, TİCARİ ELVERİŞLİLİK, BELİRLİ BİR AMACA UYGUNLUK VE İHLAL ETMEME GARANTİLERİ DE DAHİL OLMAK ÜZERE, ANCAK BUNLARLA SINIRLI OLMAMAK KAYDIYLA. HİÇBİR DURUMDA YAZARLAR VEYA TELİF HAKKI SAHİPLERİ, SÖZLEŞME, HAKSIZ FİİL VEYA DİĞER BİR HUKUKİ İŞLEM OLSUN OLMASIN, YAZILIMDAN, YAZILIMIN KULLANIMINDAN VEYA YAZILIMLA İLGİLİ DİĞER İŞLEMLERDEN DOĞAN HERHANGİ BİR TALEP, ZARAR VEYA DİĞER SORUMLULUKLAR İÇİN SORUMLU TUTULAMAZLAR.
