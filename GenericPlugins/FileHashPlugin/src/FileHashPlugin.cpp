#include "FileHashPlugin.hpp"


#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cstring>
#include <algorithm> // Necesar pentru std::min

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView;

// --- REZOLVARE CONFLICTE WINDOWS ---
#ifdef MessageBox
#    undef MessageBox
#endif

#ifdef min
#    undef min
#endif

#ifdef max
#    undef max
#endif
// --------------------------------------------

// --- API KEY VIRUS TOTAL ---
// Cheia ta actuala (Asigura-te ca nu o distribui public daca e privata)
const std::string VT_API_KEY = "cb9c943d76722f2cd8f91f37c5bb57e2122028b296ad0e0bc849e14a7d2316ee";

constexpr int CMD_CHECK_VT  = 1;
constexpr int CMD_CLOSE     = 2;
constexpr int CMD_UPLOAD_VT = 3; // Comanda noua pentru upload

// --- IMPLEMENTARE SHA256 ---
class SimpleSHA256
{
    uint32_t state[8];
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;

    static uint32_t rotr(uint32_t x, uint32_t n)
    {
        return (x >> n) | (x << (32 - n));
    }

    void transform()
    {
        uint32_t m[64];
        uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2;

        for (i = 0, j = 0; i < 16; ++i, j += 4)
            m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
        for (; i < 64; ++i)
            m[i] = 0x0;

        for (i = 16; i < 64; ++i)
            m[i] = (rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10)) + m[i - 7] + (rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3)) +
                   m[i - 16];

        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];

        static const uint32_t K[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
                                        0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                                        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
                                        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                                        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
                                        0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                                        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

        for (i = 0; i < 64; ++i) {
            t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + m[i];
            t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            h  = g;
            g  = f;
            f  = e;
            e  = d + t1;
            d  = c;
            c  = b;
            b  = a;
            a  = t1 + t2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

  public:
    SimpleSHA256()
    {
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
        datalen  = 0;
        bitlen   = 0;
    }

    void update(const uint8_t* in_data, size_t len)
    {
        for (size_t i = 0; i < len; ++i) {
            data[datalen] = in_data[i];
            datalen++;
            if (datalen == 64) {
                transform();
                bitlen += 512;
                datalen = 0;
            }
        }
    }

    std::string final()
    {
        uint32_t i = datalen;
        if (datalen < 56) {
            data[i++] = 0x80;
            while (i < 56)
                data[i++] = 0x00;
        } else {
            data[i++] = 0x80;
            while (i < 64)
                data[i++] = 0x00;
            transform();
            memset(data, 0, 56);
        }
        bitlen += datalen * 8;
        data[63] = bitlen;
        data[62] = bitlen >> 8;
        data[61] = bitlen >> 16;
        data[60] = bitlen >> 24;
        data[59] = bitlen >> 32;
        data[58] = bitlen >> 40;
        data[57] = bitlen >> 48;
        data[56] = bitlen >> 56;
        transform();

        std::stringstream res;
        for (int k = 0; k < 8; k++)
            res << std::hex << std::setw(8) << std::setfill('0') << state[k];
        return res.str();
    }
};

// Callback pentru CURL
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    ((std::string*) userp)->append((char*) contents, size * nmemb);
    return size * nmemb;
}

class HashFileWindow : public Window, public Handlers::OnButtonPressedInterface
{
    Reference<ListView> listView;
    Reference<Label> lbHash;
    std::string fileHash;
    Reference<GView::Object> obj;

  public:
    HashFileWindow(Reference<GView::Object> _obj) : Window("VirusTotal Hash Checker", "d:c,w:80,h:24", WindowFlags::Sizeable | WindowFlags::Maximized)
    {
        obj = _obj;

        // Calculam SHA256 folosind clasa noastra interna
        this->fileHash = CalculateSHA256();

        Factory::Label::Create(this, "File Hash (SHA256):", "t:1,l:2,w:20");
        lbHash = Factory::Label::Create(this, this->fileHash, "t:2,l:2,w:66");

        listView = Factory::ListView::Create(this, "t:4,l:2,b:4,r:2", { "n:Engine,a:l,w:20", "n:Category,a:l,w:15", "n:Result,a:l,w:30" });

        // Buton Check
        auto btnCheck                         = Factory::Button::Create(this, "&Check VirusTotal", "b:1,l:2,w:25", CMD_CHECK_VT);
        btnCheck->Handlers()->OnButtonPressed = this;

        // Buton Upload (NOU)
        auto btnUpload                         = Factory::Button::Create(this, "&Upload File", "b:1,l:30,w:25", CMD_UPLOAD_VT);
        btnUpload->Handlers()->OnButtonPressed = this;

        // Buton Close
        auto btnClose                         = Factory::Button::Create(this, "&Close", "b:1,r:2,w:15", CMD_CLOSE);
        btnClose->Handlers()->OnButtonPressed = this;
    }

    std::string CalculateSHA256()
    {
        auto& dataCache = obj->GetData();
        uint64 size     = dataCache.GetSize();
        SimpleSHA256 sha;
        uint64 offset    = 0;
        uint32 chunkSize = 4096;

        while (offset < size) {
            uint32 currentRead = (uint32) (std::min) ((uint64) chunkSize, size - offset);
            auto bufferView    = dataCache.Get(offset, currentRead, false);
            if (bufferView.IsValid()) {
                sha.update(bufferView.GetData(), currentRead);
            } else {
                return "Error_Reading_File";
            }
            offset += currentRead;
        }
        return sha.final();
    }

    void CheckVirusTotal()
    {
        if (VT_API_KEY.find("INTRODU") != std::string::npos) {
            AppCUI::Dialogs::MessageBox::ShowError("Error", "Configurati API Key-ul!");
            return;
        }

        CURL* curl;
        CURLcode res;
        std::string readBuffer;

        curl = curl_easy_init();
        if (curl) {
            std::string url            = "https://www.virustotal.com/api/v3/files/" + fileHash;
            struct curl_slist* headers = NULL;
            headers                    = curl_slist_append(headers, ("x-apikey: " + VT_API_KEY).c_str());

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                AppCUI::Dialogs::MessageBox::ShowError("CURL Error", curl_easy_strerror(res));
            } else {
                ParseVTResponse(readBuffer);
            }
            curl_easy_cleanup(curl);
        }
    }

    void UploadToVirusTotal()
    {
        if (VT_API_KEY.find("INTRODU") != std::string::npos) {
            AppCUI::Dialogs::MessageBox::ShowError("Error", "Configurati API Key-ul!");
            return;
        }

        // Limita de siguranta: 32MB pentru upload simplu
        uint64 fSize = obj->GetData().GetSize();
        if (fSize > 32 * 1024 * 1024) {
            AppCUI::Dialogs::MessageBox::ShowError("Upload Error", "Fisierul este prea mare (>32MB) pentru acest plugin simplu!");
            return;
        }

        CURL* curl;
        CURLcode res;
        std::string readBuffer;

        curl = curl_easy_init();
        if (curl) {
            // URL pentru upload
            std::string url = "https://www.virustotal.com/api/v3/files";

            // Pregatim buffer-ul cu tot fisierul
            auto bufferView = obj->GetData().Get(0, (uint32) fSize, false);
            if (!bufferView.IsValid()) {
                AppCUI::Dialogs::MessageBox::ShowError("Read Error", "Nu am putut citi fisierul din memorie.");
                return;
            }

            // Headers
            struct curl_slist* headers = NULL;
            headers                    = curl_slist_append(headers, ("x-apikey: " + VT_API_KEY).c_str());

            // Form data (multipart)
            curl_mime* form      = NULL;
            curl_mimepart* field = NULL;

            form = curl_mime_init(curl);

            // Adaugam fisierul
            field = curl_mime_addpart(form);
            curl_mime_name(field, "file");
            curl_mime_data(field, (const char*) bufferView.GetData(), bufferView.GetLength());
            curl_mime_filename(field, "scan_sample.bin"); // Nume generic pentru upload

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_MIMEPOST, form); // Setam POST-ul multipart
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

            res = curl_easy_perform(curl);

            if (res != CURLE_OK) {
                AppCUI::Dialogs::MessageBox::ShowError("CURL Error", curl_easy_strerror(res));
            } else {
                // Verificam raspunsul la upload
                try {
                    auto json = nlohmann::json::parse(readBuffer);
                    if (json.contains("data") && json["data"].contains("id")) {
                        std::string analysisId = json["data"]["id"];
                        std::string msg =
                              "Fisier uploadat cu succes!\nAnalysis ID: " + analysisId + "\n\nAsteapta cateva secunde si apasa 'Check VirusTotal' din nou.";
                        AppCUI::Dialogs::MessageBox::ShowNotification("Success", msg.c_str());
                    } else if (json.contains("error")) {
                        std::string msg = json["error"]["message"];
                        AppCUI::Dialogs::MessageBox::ShowError("Upload Failed", msg.c_str());
                    } else {
                        AppCUI::Dialogs::MessageBox::ShowError("Info", "Raspuns necunoscut de la server.");
                    }
                } catch (...) {
                    AppCUI::Dialogs::MessageBox::ShowError("Error", "Eroare la parsarea raspunsului de upload.");
                }
            }

            curl_easy_cleanup(curl);
            curl_mime_free(form);
        }
    }

    void ParseVTResponse(const std::string& jsonData)
    {
        try {
            auto json = nlohmann::json::parse(jsonData);

            if (json.contains("error")) {
                std::string msg = json["error"]["message"];
                // Daca eroarea este "NotFoundError", sugeram upload
                if (json["error"]["code"] == "NotFoundError") {
                    AppCUI::Dialogs::MessageBox::ShowWarning(
                          "Not Found", "Fisierul nu este in baza de date.\nFoloseste butonul 'Upload File' pentru a-l scana.");
                } else {
                    AppCUI::Dialogs::MessageBox::ShowError("VT Error", msg.c_str());
                }
                return;
            }

            listView->DeleteAllItems();

            if (!json.contains("data") || !json["data"].contains("attributes")) {
                AppCUI::Dialogs::MessageBox::ShowWarning("Info", "Nu s-au gasit atribute pentru acest fisier.");
                return;
            }

            // Verificam statusul analizei (poate fi "queued" sau "in_progress" imediat dupa upload)
            /* Nota: In API v3 /files/{hash} returneaza raportul cache-uit.
               Daca tocmai l-ai uploadat, e posibil sa dureze pana apare raportul final. */

            if (json["data"]["attributes"].contains("last_analysis_results")) {
                auto results = json["data"]["attributes"]["last_analysis_results"];
                for (auto it = results.begin(); it != results.end(); ++it) {
                    auto engine          = it.value();
                    std::string name     = it.key();
                    std::string category = engine["category"];
                    std::string result   = engine["result"].is_null() ? "clean" : engine["result"].get<std::string>();

                    listView->AddItem({ name, category, result });
                }
            } else {
                AppCUI::Dialogs::MessageBox::ShowNotification("Info", "Analiza este inca in desfasurare sau nu exista rezultate detaliate.");
            }

        } catch (const std::exception& e) {
            AppCUI::Dialogs::MessageBox::ShowError("JSON Error", e.what());
        }
    }

    void OnButtonPressed(Reference<Button> btn) override
    {
        switch (btn->GetControlID()) {
        case CMD_CHECK_VT:
            CheckVirusTotal();
            break;
        case CMD_UPLOAD_VT:
            UploadToVirusTotal();
            break;
        case CMD_CLOSE:
            Exit();
            break;
        }
    }
};

extern "C" {
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> currentObject)
{
    if (command == "CheckHashVT") {
        if (!currentObject.IsValid())
            return false;
        HashFileWindow dlg(currentObject);
        dlg.Show();
        return true;
    }
    return false;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Command.CheckHashVT"] = Input::Key::Ctrl | Input::Key::Alt | Input::Key::Shift | Input::Key::V;
}
}