#include <WiFi.h>
#include <SD.h>
#include <SPI.h>
#include <esp_wifi.h>
#include <TFT_eSPI.h>
#include <XPT2046_Touchscreen.h>

// ===== WERSJA Z NAPRAWIONYM SD CARD ORAZ DOTYKIEM =====

// ===== PINOUT ESP32-2432S028R =====
#define TOUCH_CS 33
#define TOUCH_IRQ 36
#define SD_CS 5
#define TFT_BL 21

// ===== DEBUG MODE =====
bool DEBUG_MODE = true;

// ===== OBIEKTY =====
TFT_eSPI tft = TFT_eSPI();
XPT2046_Touchscreen touch(TOUCH_CS, TOUCH_IRQ);

// DODANE: Dedykowana, druga sprzętowa magistrala SPI dla karty SD
SPIClass sdSPI(HSPI);

// ===== KOLORY =====
#define COLOR_BG       0x0000
#define COLOR_HEADER   0x001F
#define COLOR_TEXT     0xFFFF
#define COLOR_SELECTED 0x07E0
#define COLOR_BUTTON   0xF800
#define COLOR_EAPOL    0xFFE0
#define COLOR_WARN     0xFBE0

// ===== ZMIENNE GLOBALNE =====
enum AppState {
    STATE_SCAN,
    STATE_SELECT,
    STATE_CAPTURE,
    STATE_STOPPED
};
AppState currentState = STATE_SCAN;

struct WiFiNetwork {
    String ssid;
    int rssi;
    int channel;
    uint8_t bssid[6];
};
WiFiNetwork networks[20];
int networkCount = 0;
int selectedNetwork = -1;

int packetCounter = 0;
int eapolCounter = 0;
int bssidFilteredOut = 0;

// SD Card
File capFile;
char capFileName[64];
bool sdCardAvailable = false;

struct Button {
    int x, y, w, h;
    String label;
    uint16_t color;
};

Button btnStart = {10, 210, 100, 25, "START", COLOR_SELECTED};
Button btnStop = {120, 210, 100, 25, "STOP", COLOR_BUTTON};
Button btnRescan = {230, 210, 80, 25, "SCAN", 0x07FF};

// ===== STRUKTURY PCAP =====
typedef struct {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_hdr_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;

// ===== FUNKCJE POMOCNICZE =====
String sanitizeSSID(String ssid) {
    String safe = "";
    for (int i = 0; i < ssid.length() && i < 15; i++) { // Max 15 znaków (było 20)
        char c = ssid[i];
        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '_' || c == '-') {
            safe += c;
            } else if (c == ' ') {
                safe += '_';
            }
    }
    if (safe.length() == 0) safe = "net";
    return safe;
}

int findFreeFileNumber(String ssidSafe) {
    Serial.println("Szukam wolnego numeru dla: " + ssidSafe);
    for (int i = 1; i <= 999; i++) { // Obniżone do 999
        sprintf(capFileName, "/%d_%s.cap", i, ssidSafe.c_str());
        if (DEBUG_MODE && i <= 5) {
            Serial.print("  Sprawdzam: ");
            Serial.print(capFileName);
        }

        if (!SD.exists(capFileName)) {
            if (DEBUG_MODE && i <= 5) {
                Serial.println(" -> WOLNY!");
            }
            Serial.println("Znaleziono wolny numer: " + String(i));
            return i;
        }

        if (DEBUG_MODE && i <= 5) {
            Serial.println(" -> zajęty");
        }
    }

    Serial.println("Brak wolnych numerów!");
    return 0;
}

bool initCapFile() {
    Serial.println("\n=== INICJALIZACJA PLIKU PCAP ===");
    if (!sdCardAvailable) {
        Serial.println("BŁĄD: SD Card niedostępna!");
        return false;
    }

    if (selectedNetwork < 0) {
        Serial.println("BŁĄD: Nie wybrano sieci!");
        return false;
    }

    Serial.println("Test SD Card...");
    File testFile = SD.open("/test.txt", FILE_WRITE);
    if (!testFile) {
        Serial.println("BŁĄD: Nie mogę utworzyć pliku testowego!");
        Serial.println("SD Card może być tylko do odczytu lub uszkodzona.");
        sdCardAvailable = false;
        return false;
    }
    testFile.println("test");
    testFile.close();
    SD.remove("/test.txt");
    Serial.println("Test SD OK!");

    String ssidSafe = sanitizeSSID(networks[selectedNetwork].ssid);
    Serial.println("SSID original: " + networks[selectedNetwork].ssid);
    Serial.println("SSID sanitized: " + ssidSafe);

    int fileNum = findFreeFileNumber(ssidSafe);
    if (fileNum == 0) {
        Serial.println("BŁĄD: Brak wolnych numerów plików!");
        return false;
    }

    sprintf(capFileName, "/%d_%s.cap", fileNum, ssidSafe.c_str());
    Serial.println("Nazwa pliku: " + String(capFileName));
    Serial.println("Długość nazwy: " + String(strlen(capFileName)));

    if (strlen(capFileName) > 31) {
        Serial.println("OSTRZEŻENIE: Nazwa pliku za długa! Skracam...");
        String ssidShort = sanitizeSSID(networks[selectedNetwork].ssid);
        if (ssidShort.length() > 10) ssidShort = ssidShort.substring(0, 10);
        sprintf(capFileName, "/%d_%s.cap", fileNum, ssidShort.c_str());
        Serial.println("Nowa nazwa: " + String(capFileName));
    }

    Serial.println("Tworzenie pliku...");
    capFile = SD.open(capFileName, FILE_WRITE);
    if (!capFile) {
        Serial.println("BŁĄD: Nie mogę utworzyć pliku: " + String(capFileName));
        Serial.println("Próba z prostą nazwą...");
        sprintf(capFileName, "/%d.cap", fileNum);
        capFile = SD.open(capFileName, FILE_WRITE);

        if (!capFile) {
            Serial.println("BŁĄD: Nadal nie mogę utworzyć pliku!");
            return false;
        }
    }

    Serial.println("Plik utworzony!");
    Serial.println("Zapisuję nagłówek PCAP...");
    pcap_hdr_t hdr;
    hdr.magic_number = 0xa1b2c3d4;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone = 0;
    hdr.sigfigs = 0;
    hdr.snaplen = 65535;
    hdr.network = 105;

    size_t written = capFile.write((uint8_t*)&hdr, sizeof(pcap_hdr_t));
    Serial.println("Zapisano bajtów nagłówka: " + String(written));
    capFile.flush();
    Serial.println("Flush OK!");
    Serial.println("=== PLIK PCAP GOTOWY ===\n");
    return true;
}

// ===== FUNKCJE GUI =====
void drawHeader(String title) {
    tft.fillRect(0, 0, 320, 30, COLOR_HEADER);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextDatum(MC_DATUM);
    tft.drawString(title, 160, 15, 4);
}

void drawButton(Button btn) {
    tft.fillRoundRect(btn.x, btn.y, btn.w, btn.h, 5, btn.color);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextDatum(MC_DATUM);
    tft.drawString(btn.label, btn.x + btn.w/2, btn.y + btn.h/2, 2);
}

bool isButtonPressed(Button btn, int tx, int ty) {
    return (tx >= btn.x && tx <= btn.x + btn.w &&
    ty >= btn.y && ty <= btn.y + btn.h);
}

void drawNetworkList() {
    tft.fillRect(0, 30, 320, 175, COLOR_BG);

    int y = 35;
    int maxVisible = 7;
    for (int i = 0; i < min(networkCount, maxVisible); i++) {
        uint16_t bgColor = (i == selectedNetwork) ? COLOR_SELECTED : COLOR_BG;
        uint16_t textColor = (i == selectedNetwork) ? COLOR_BG : COLOR_TEXT;

        tft.fillRect(5, y, 310, 22, bgColor);
        tft.setTextColor(textColor);
        tft.setTextDatum(TL_DATUM);
        String line = networks[i].ssid;
        if (line.length() > 20) line = line.substring(0, 20) + "...";
        line += " Ch:" + String(networks[i].channel);
        line += " [" + String(networks[i].rssi) + "dBm]";

        tft.drawString(line, 10, y + 3, 2);
        y += 24;
    }
}

void drawCaptureScreen() {
    tft.fillRect(0, 30, 320, 175, COLOR_BG);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextDatum(TL_DATUM);
    int y = 40;
    if (selectedNetwork >= 0) {
        tft.drawString("SIEC:", 10, y, 2);
        tft.setTextColor(COLOR_SELECTED);
        String ssidShort = networks[selectedNetwork].ssid;
        if (ssidShort.length() > 15) ssidShort = ssidShort.substring(0, 15) + "..";
        tft.drawString(ssidShort, 60, y, 2);
        y += 20;

        tft.setTextColor(COLOR_TEXT);
        tft.drawString("Ch:" + String(networks[selectedNetwork].channel), 10, y, 2);
        y += 25;
    }

    tft.drawString("Pakiety: " + String(packetCounter), 10, y, 2);
    y += 20;
    tft.setTextColor(COLOR_EAPOL);
    tft.drawString("EAPOL: " + String(eapolCounter), 10, y, 4);
    y += 30;

    tft.setTextColor(COLOR_TEXT);
    String fileDisplay = String(capFileName);
    if (fileDisplay.startsWith("/")) fileDisplay = fileDisplay.substring(1);
    if (fileDisplay.length() > 25) fileDisplay = fileDisplay.substring(0, 25) + "..";
    tft.drawString(fileDisplay, 10, y, 2);
}

void updateCaptureStats() {
    tft.fillRect(0, 95, 320, 110, COLOR_BG);

    int y = 100;
    tft.setTextColor(COLOR_TEXT);
    tft.setTextDatum(TL_DATUM);
    tft.drawString("Pakiety: " + String(packetCounter), 10, y, 2);
    y += 20;

    tft.setTextColor(COLOR_EAPOL);
    tft.drawString("EAPOL: " + String(eapolCounter), 10, y, 4);
    y += 30;

    tft.setTextColor(COLOR_WARN);
    tft.drawString("Filtr: -" + String(bssidFilteredOut), 10, y, 2);
    y += 20;

    tft.setTextColor(COLOR_TEXT);
    String fileDisplay = String(capFileName);
    if (fileDisplay.startsWith("/")) fileDisplay = fileDisplay.substring(1);
    if (fileDisplay.length() > 25) fileDisplay = fileDisplay.substring(0, 25) + "..";
    tft.drawString(fileDisplay, 10, y, 2);
}

// ===== SKANOWANIE SIECI =====
void scanNetworks() {
    drawHeader("SKANOWANIE...");

    networkCount = 0;
    int n = WiFi.scanNetworks(false, false, false, 300);

    if (n > 0) {
        networkCount = min(n, 20);
        for (int i = 0; i < networkCount; i++) {
            networks[i].ssid = WiFi.SSID(i);
            networks[i].rssi = WiFi.RSSI(i);
            networks[i].channel = WiFi.channel(i);
            WiFi.BSSID(i, networks[i].bssid);
        }
    }

    WiFi.scanDelete();
    currentState = STATE_SELECT;

    drawHeader("WYBIERZ SIEC [" + String(networkCount) + "]");
    drawNetworkList();
    drawButton(btnStart);
    drawButton(btnRescan);
}

// ===== FUNKCJE POMOCNICZE DLA EAPOL =====
bool matchesBSSID(uint8_t* addr) {
    if (selectedNetwork < 0) return true;
    for (int i = 0; i < 6; i++) {
        if (addr[i] != networks[selectedNetwork].bssid[i]) {
            return false;
        }
    }
    return true;
}

bool extractBSSID(uint8_t* payload, uint16_t len, uint8_t* bssid_out) {
    if (len < 24) return false;
    uint8_t type = (payload[0] >> 2) & 0x03;
    if (type != 0x02) return false;

    uint8_t toDS = (payload[1] & 0x01);
    uint8_t fromDS = (payload[1] & 0x02) >> 1;
    int offset = -1;
    if (toDS == 0 && fromDS == 1) {
        offset = 10;
    } else if (toDS == 1 && fromDS == 0) {
        offset = 4;
    } else if (toDS == 0 && fromDS == 0) {
        offset = 16;
    } else {
        return false;
    }

    if (len < offset + 6) return false;
    memcpy(bssid_out, payload + offset, 6);
    return true;
}

bool isEAPOLFrame(uint8_t* payload, uint16_t len) {
    if (len < 32) return false;
    uint8_t type = (payload[0] >> 2) & 0x03;
    uint8_t subtype = (payload[0] >> 4) & 0x0F;
    if (type != 0x02) return false;

    int llc_offset = 24;
    if (subtype & 0x08) {
        llc_offset += 2;
    }

    if (len < llc_offset + 8) return false;
    if (payload[llc_offset]     == 0xAA &&
        payload[llc_offset + 1] == 0xAA &&
        payload[llc_offset + 2] == 0x03 &&
        payload[llc_offset + 3] == 0x00 &&
        payload[llc_offset + 4] == 0x00 &&
        payload[llc_offset + 5] == 0x00 &&
        payload[llc_offset + 6] == 0x88 &&
        payload[llc_offset + 7] == 0x8E) {
        return true;
        }
        return false;
}

// ===== CALLBACK SNIFFER =====
void IRAM_ATTR wifiSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (currentState != STATE_CAPTURE) return;
    if (type != WIFI_PKT_DATA) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 24 || len > 2346) return;

    packetCounter++;

    uint8_t bssid[6];
    if (!extractBSSID(payload, len, bssid)) {
        return;
    }

    if (selectedNetwork >= 0 && !matchesBSSID(bssid)) {
        bssidFilteredOut++;
        return;
    }

    if (isEAPOLFrame(payload, len)) {
        eapolCounter++;
        if (capFile && sdCardAvailable) {
            pcaprec_hdr_t pkthdr;
            pkthdr.ts_sec = millis() / 1000;
            pkthdr.ts_usec = (millis() % 1000) * 1000;
            pkthdr.incl_len = len;
            pkthdr.orig_len = len;

            capFile.write((uint8_t*)&pkthdr, sizeof(pcaprec_hdr_t));
            capFile.write(payload, len);
            capFile.flush();
        }

        if (DEBUG_MODE) {
            Serial.print(">>> EAPOL #");
            Serial.print(eapolCounter);
            Serial.print(" | Len: ");
            Serial.print(len);
            Serial.print(" | BSSID: ");
            for (int i = 0; i < 6; i++) {
                if (bssid[i] < 0x10) Serial.print("0");
                Serial.print(bssid[i], HEX);
                if (i < 5) Serial.print(":");
            }
            Serial.println(" | ZAPISANO!");
        }
    }
}

// ===== START/STOP CAPTURE =====
void startCapture() {
    if (selectedNetwork < 0) return;

    Serial.println("\n========================================");
    Serial.println("PRÓBA ROZPOCZĘCIA PRZECHWYTYWANIA");
    Serial.println("========================================");

    currentState = STATE_CAPTURE;
    packetCounter = 0;
    eapolCounter = 0;
    bssidFilteredOut = 0;
    if (!initCapFile()) {
        Serial.println("\n!!! BŁĄD INICJALIZACJI PLIKU !!!");
        currentState = STATE_SELECT;

        tft.fillScreen(COLOR_BG);
        tft.setTextColor(COLOR_BUTTON);
        tft.setTextDatum(MC_DATUM);
        tft.drawString("BLAD PLIKU!", 160, 100, 4);
        tft.setTextColor(COLOR_TEXT);
        tft.drawString("Sprawdz Serial Monitor", 160, 140, 2);
        delay(3000);

        scanNetworks();
        return;
    }

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&wifiSnifferCallback);
    esp_wifi_set_channel(networks[selectedNetwork].channel, WIFI_SECOND_CHAN_NONE);

    drawHeader("PRZECHWYTYWANIE...");
    drawCaptureScreen();
    drawButton(btnStop);
    Serial.println("\n=== START CAPTURE ===");
    Serial.println("SSID: " + networks[selectedNetwork].ssid);
    Serial.println("Channel: " + String(networks[selectedNetwork].channel));
    Serial.print("BSSID: ");
    for (int i = 0; i < 6; i++) {
        if (networks[selectedNetwork].bssid[i] < 0x10) Serial.print("0");
        Serial.print(networks[selectedNetwork].bssid[i], HEX);
        if (i < 5) Serial.print(":");
    }
    Serial.println();
    Serial.println("Plik: " + String(capFileName));
    Serial.println("\nCzekam na ramki EAPOL...\n");
}

void stopCapture() {
    esp_wifi_set_promiscuous(false);

    if (capFile) {
        capFile.close();
        Serial.println("Plik zamknięty: " + String(capFileName));
    }

    currentState = STATE_STOPPED;

    drawHeader("ZATRZYMANO");
    tft.fillRect(0, 30, 320, 175, COLOR_BG);

    tft.setTextColor(COLOR_TEXT);
    tft.setTextDatum(MC_DATUM);
    tft.drawString("Przechwytywanie zatrzymane", 160, 50, 2);
    tft.drawString("Pakiety: " + String(packetCounter), 160, 80, 2);
    tft.setTextColor(COLOR_EAPOL);
    tft.drawString("EAPOL: " + String(eapolCounter), 160, 110, 4);

    tft.setTextColor(COLOR_TEXT);
    String fileDisplay = String(capFileName);
    if (fileDisplay.startsWith("/")) fileDisplay = fileDisplay.substring(1);
    if (fileDisplay.length() > 30) fileDisplay = fileDisplay.substring(0, 30) + "..";
    tft.drawString(fileDisplay, 160, 150, 2);

    tft.setTextColor(COLOR_SELECTED);
    tft.drawString("Zapisano na SD!", 160, 170, 2);
    drawButton(btnRescan);

    Serial.println("\n=== STOP CAPTURE ===");
    Serial.println("Statystyki:");
    Serial.println("  Wszystkie pakiety: " + String(packetCounter));
    Serial.println("  EAPOL frames: " + String(eapolCounter));
    Serial.println("  Odrzucone (BSSID): " + String(bssidFilteredOut));
    Serial.println("  Plik: " + String(capFileName));
    Serial.println();
}

// ===== TOUCH HANDLER - POPRAWIONY =====
void handleTouch() {
    // Szybki test pinu sprzętowego (nie zakłóca SPI ekranu i SD)
    if (!touch.tirqTouched()) {
        return;
    }

    // Ekran wciśnięty! Przełączamy VSPI z ekranu na układ Touch
    // (CYD pinout dla Touch: CLK=25, MISO=39, MOSI=32, CS=33)
    SPI.begin(25, 39, 32, 33);

    bool isTouched = touch.touched();
    TS_Point p;
    if (isTouched) {
        p = touch.getPoint();
    }

    // Zwracamy VSPI z powrotem na ekran TFT
    // (CYD pinout dla TFT: CLK=14, MISO=12, MOSI=13, CS=15)
    SPI.begin(14, 12, 13, 15);

    if (!isTouched) {
        return;
    }

    int touchX = map(p.x, 200, 3700, 1, 320);
    int touchY = map(p.y, 240, 3800, 1, 240);

    if (currentState == STATE_SELECT) {
        if (touchY >= 35 && touchY <= 205 && touchX >= 5 && touchX <= 315) {
            int idx = (touchY - 35) / 24;
            if (idx < networkCount) {
                selectedNetwork = idx;
                drawNetworkList();
                Serial.println("Wybrano: " + networks[idx].ssid);
            }
        }

        if (isButtonPressed(btnStart, touchX, touchY)) {
            if (selectedNetwork >= 0) {
                startCapture();
            }
        }

        if (isButtonPressed(btnRescan, touchX, touchY)) {
            scanNetworks();
        }
    } else if (currentState == STATE_CAPTURE) {
        if (isButtonPressed(btnStop, touchX, touchY)) {
            stopCapture();
        }
    } else if (currentState == STATE_STOPPED) {
        if (isButtonPressed(btnRescan, touchX, touchY)) {
            scanNetworks();
        }
    }
    delay(200);
}

// ===== ANIMACJA STARTOWA =====
void showBootAnimation() {
    tft.fillScreen(COLOR_BG);
    tft.setTextDatum(MC_DATUM);
    tft.setTextFont(4);

    String text = "Z3r[0x30]";
    int charWidth = 18; // Przybliżona szerokość znaku dla fontu 4
    int startX = 160 - (text.length() * charWidth) / 2 + (charWidth / 2);
    int finalY = 100;

    // Efekt składania (spadające znaki)
    for (int i = 0; i < text.length(); i++) {
        String c = String(text[i]);
        int xPos = startX + (i * charWidth);

        // Animacja pojedynczego znaku
        for (int y = -20; y <= finalY; y += 20) {
            if (y > -20) {
                tft.setTextColor(COLOR_BG); // Zamazanie poprzedniej klatki
                tft.drawString(c, xPos, y - 20);
            }
            tft.setTextColor(COLOR_SELECTED); // Zielony podczas lotu
            tft.drawString(c, xPos, y);
            delay(15);
        }

        // Docelowy kolor (czerwone nawiasy, biała reszta)
        if (c == "[" || c == "]") {
            tft.setTextColor(0xF800); // Czerwony
        } else {
            tft.setTextColor(COLOR_TEXT); // Biały
        }
        tft.drawString(c, xPos, finalY);
        delay(80); // Przerwa przed kolejnym znakiem
    }

    // Krótkie mignięcie i dopisek
    delay(200);
    tft.setTextFont(2);
    tft.setTextColor(COLOR_SELECTED);
    tft.drawString("Wczytywanie modulow...", 160, 150);

    delay(1500); // Czas na podziwianie animacji
    tft.fillScreen(COLOR_BG); // Czyszczenie ekranu pod główny program
}
// ===== SETUP =====
void setup() {
    Serial.begin(115200);
    delay(1000);

    Serial.println("\n===========================================");
    Serial.println("  ESP32 EAPOL SNIFFER v3.1");
    Serial.println("  Debug version - DUAL SPI FIXED");
    Serial.println("===========================================\n");

    // ===== KROK 1: TFT =====
    Serial.println("1. Inicjalizacja TFT...");
    pinMode(TFT_BL, OUTPUT);
    digitalWrite(TFT_BL, HIGH);
    tft.init();
    tft.setRotation(1);
    tft.fillScreen(COLOR_BG);
    Serial.println("   ✓ TFT OK\n");

    showBootAnimation();

    // ===== KROK 2: TOUCH =====
    Serial.println("2. Inicjalizacja Touch...");
    // Ustawiamy SPI na piny dotyku i go inicjujemy
    SPI.begin(25, 39, 32, 33);

    if (!touch.begin()) {
        Serial.println("   ✗ BŁĄD Touch!\n");
        tft.setTextColor(COLOR_BUTTON);
        tft.setTextDatum(MC_DATUM);
        tft.drawString("TOUCH ERROR!", 160, 120, 4);
        while (true) delay(1000);
    }
    touch.setRotation(1);
    Serial.println("   ✓ Touch OK\n");

    // Od razu przywracamy SPI dla wyświetlacza TFT!
    SPI.begin(14, 12, 13, 15);

    // ===== KROK 3: SD CARD =====
    Serial.println("3. Inicjalizacja SD Card na dedykowanym sprzętowym SPI...");
    Serial.println("   Pin CS: " + String(SD_CS));

    // Uruchamiamy kartę SD na DRUGIEJ wolnej sprzętowej magistrali (HSPI)
    // Dzięki temu sniffer zapisujący dane nie spowolni wyświetlacza ani dotyku.
    sdSPI.begin(18, 19, 23, SD_CS);

    if (!SD.begin(SD_CS, sdSPI, 8000000)) { // Przekazujemy nasze nowe sprzętowe "sdSPI"
        Serial.println("   ✗ UWAGA: SD Card niedostępna!");
        Serial.println("   Możliwe przyczyny:");
        Serial.println("     - Karta nie włożona");
        Serial.println("     - Zły format (użyj FAT32)");
        Serial.println("     - Uszkodzona karta");
        Serial.println("   Kontynuuję bez zapisu...\n");
        sdCardAvailable = false;

        tft.setTextColor(COLOR_WARN);
        tft.setTextDatum(MC_DATUM);
        tft.drawString("SD CARD BRAK", 160, 100, 2);
        tft.setTextColor(COLOR_TEXT);
        tft.drawString("(Zapis wylaczony)", 160, 130, 2);
        delay(2000);
    } else {
        Serial.println("   ✓ SD Card OK");
        sdCardAvailable = true;
        uint8_t cardType = SD.cardType();
        Serial.print("   Typ karty: ");
        if (cardType == CARD_MMC) {
            Serial.println("MMC");
        } else if (cardType == CARD_SD) {
            Serial.println("SDSC");
        } else if (cardType == CARD_SDHC) {
            Serial.println("SDHC");
        } else {
            Serial.println("UNKNOWN");
        }

        uint64_t cardSize = SD.cardSize() / (1024 * 1024);
        Serial.println("   Rozmiar: " + String((uint32_t)cardSize) + " MB");

        uint64_t totalBytes = SD.totalBytes() / (1024 * 1024);
        uint64_t usedBytes = SD.usedBytes() / (1024 * 1024);
        Serial.println("   Wolne: " + String((uint32_t)(totalBytes - usedBytes)) + " MB");
        Serial.println();
    }

    Serial.println("✅ Hardware gotowy!\n");

    // WiFi init
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    // Skanowanie
    scanNetworks();
}

// ===== LOOP =====
unsigned long lastStatsUpdate = 0;
void loop() {
    handleTouch();

    if (currentState == STATE_CAPTURE && millis() - lastStatsUpdate > 1000) {
        updateCaptureStats();
        lastStatsUpdate = millis();
    }

    delay(50);
}
