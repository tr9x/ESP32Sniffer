# ESP32 EAPOL Sniffer v3.1 📡

Mobilny, sprzętowy sniffer sieci WiFi (2.4 GHz) stworzony na bazie modułu **ESP32-2432S028R** (znanego jako *Cheap Yellow Display - CYD*). Program przechwytuje ramki EAPOL (WPA/WPA2 handshakes) i zapisuje je bezpośrednio na karcie SD w formacie `.cap` (PCAP), gotowym do analizy w programach takich jak Wireshark, Hashcat czy Aircrack-ng.

👤 **Autor:** Z3r<span style="color:red">[</span>0x30<span style="color:red">]</span>

---

## 🚀 Główne funkcje

* **Interfejs Dotykowy:** Pełna obsługa za pomocą wbudowanego ekranu dotykowego TFT.
* **Skaner Sieci:** Automatyczne skanowanie otoczenia w poszukiwaniu sieci WiFi (wyświetla SSID, kanał oraz siłę sygnału RSSI).
* **Filtrowanie BSSID:** Po wybraniu celu, sniffer odrzuca niepotrzebny ruch i skupia się wyłącznie na pakietach docelowego routera.
* **Detekcja EAPOL w czasie rzeczywistym:** Monitorowanie i zliczanie przechwyconych pakietów EAPOL na ekranie głównym.
* **Obejście błędu sprzętowego CYD:** Zastosowano zaawansowany routing szyny SPI. Ekran TFT oraz Touchscreen działają na magistrali **VSPI**, natomiast karta SD działa niezależnie na sprzętowej magistrali **HSPI**. Zapobiega to konfliktom i zapewnia bezstratny zapis pakietów.
* **Automatyczne nazewnictwo plików:** Pliki zapisywane są w formacie `[numer]_[SSID].cap` (np. `1_MojaSiec.cap`).

## 🛠 Wymagania Sprzętowe

* **Płytka:** ESP32-2432S028R (Cheap Yellow Display).
* **Karta Pamięci:** Karta MicroSD sformatowana w systemie **FAT32** (karty sformatowane w exFAT nie będą rozpoznawane).

## 💻 Wymagania Programowe (Arduino IDE)

Przed kompilacją upewnij się, że masz zainstalowane następujące biblioteki w Arduino IDE:
1. `WiFi.h` (wbudowana w rdzeń ESP32)
2. `SD.h`, `SPI.h` (wbudowane)
3. `TFT_eSPI` (od Bodmer) - *Wymaga poprawnej konfiguracji pliku `User_Setup.h` pod płytkę CYD.*
4. `XPT2046_Touchscreen` (od Paul Stoffregen)

## 📥 Instalacja i Wgrywanie

1. Sformatuj kartę MicroSD do systemu **FAT32** i włóż ją do slotu w ESP32.
2. Otwórz kod źródłowy (`.ino`) w środowisku Arduino IDE.
3. W menu `Narzędzia -> Płytka` wybierz **ESP32 Dev Module**.
4. Skonfiguruj poprawnie parametry kompilacji (zależnie od Twojej wersji CYD).
5. Podłącz ESP32 do komputera kablem USB i kliknij **Wgraj (Upload)**.
6. Opcjonalnie włącz *Serial Monitor* (115200 baud), aby podejrzeć logi z debugowania (przydatne przy sprawdzaniu inicjalizacji szyny SPI).

## 🎮 Instrukcja Obsługi

1. **Uruchomienie:** Po włączeniu zasilania urządzenie zainicjuje ekran, układ dotykowy oraz kartę SD. Jeśli karta SD nie zostanie wykryta, na ekranie pojawi się stosowny komunikat, a zapis zostanie wyłączony.
2. **Skanowanie:** System automatycznie przeskanuje dostępne sieci WiFi.
3. **Wybór Celu:** Kliknij nazwę sieci na liście, aby ustawić ją jako cel.
4. **Przechwytywanie:** Naciśnij przycisk **START**. ESP32 przejdzie w tryb `Promiscuous` i zacznie nasłuchiwać na kanale wybranej sieci.
5. **Monitorowanie:** Na ekranie na bieżąco aktualizują się statystyki pobranych pakietów ogólnych oraz celowanych pakietów EAPOL.
6. **Zatrzymanie:** Naciśnij **STOP**. Program bezpiecznie zamknie plik `.cap` na karcie SD, zapobiegając uszkodzeniu danych.
7. **Analiza:** Wyjmij kartę SD, podłącz do komputera i otwórz wygenerowany plik w programie **Wireshark**!

## ⚠️ Znane Problemy / Wskazówki

* **"SD CARD BRAK (Zapis wylaczony)"**: Najczęstszą przyczyną jest zły format karty. Windows domyślnie formatuje karty >32GB w systemie exFAT. Użyj programu typu *GUIFormat*, aby wymusić **FAT32**. Problem może też powodować brak docisku styków w tanich czytnikach CYD.
* **Zablokowany ekran dotykowy**: W przypadku użycia złych bibliotek ekran może nie reagować. Projekt używa zoptymalizowanego "przełączania" w locie pinów SPI w funkcji `handleTouch()`. Nie usuwaj tego mechanizmu.

---
*Stworzone w celach edukacyjnych i audytowych. Używaj tylko we własnych sieciach lub za wyraźną zgodą właściciela!*

by Z3r[0x30]
