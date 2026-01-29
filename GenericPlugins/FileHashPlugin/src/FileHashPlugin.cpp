#include "FileHashPlugin.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <openssl/sha.h> // <--- AICI ESTE LIBRARIA PENTRU HASH
#include <iomanip>
#include <sstream>
#include <vector>
#include <cstring>
#include <algorithm>

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView;

#ifdef MessageBox
#    undef MessageBox
#endif
#ifdef min
#    undef min
#endif
#ifdef max
#    undef max
#endif

const std::string VT_API_KEY = "cb9c943d76722f2cd8f91f37c5bb57e2122028b296ad0e0bc849e14a7d2316ee";

constexpr int CMD_CHECK_VT  = 1;
constexpr int CMD_CLOSE     = 2;
constexpr int CMD_UPLOAD_VT = 3;

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
    HashFileWindow(Reference<GView::Object> _obj) : Window("VirusTotal Hash Checker", "d:c,w:85,h:24", WindowFlags::Sizeable | WindowFlags::Maximized)
    {
        obj = _obj;

        this->fileHash = CalculateSHA256();

        Factory::Label::Create(this, "File Hash (SHA256):", "t:1,l:2,w:20");
        lbHash = Factory::Label::Create(this, this->fileHash, "t:2,l:2,w:70");

        listView = Factory::ListView::Create(this, "t:4,l:2,b:4,r:2", { "n:Engine,a:l,w:20", "n:Category,a:l,w:15", "n:Result,a:l,w:30" });

        auto btnCheck                         = Factory::Button::Create(this, "&Check VirusTotal", "b:1,l:2,w:25", CMD_CHECK_VT);
        btnCheck->Handlers()->OnButtonPressed = this;

        auto btnUpload                         = Factory::Button::Create(this, "&Upload File", "b:1,l:30,w:25", CMD_UPLOAD_VT);
        btnUpload->Handlers()->OnButtonPressed = this;

        auto btnClose                         = Factory::Button::Create(this, "&Close", "b:1,r:2,w:15", CMD_CLOSE);
        btnClose->Handlers()->OnButtonPressed = this;
    }

    std::string CalculateSHA256()
    {
        auto& dataCache = obj->GetData();
        uint64 size     = dataCache.GetSize();

        unsigned char hash[SHA256_DIGEST_LENGTH]; 
        SHA256_CTX sha256;
        SHA256_Init(&sha256);

        uint64 offset    = 0;
        uint32 chunkSize = 4096;

        while (offset < size) {
            uint32 currentRead = (uint32) (std::min) ((uint64) chunkSize, size - offset);
            auto bufferView    = dataCache.Get(offset, currentRead, false);

            if (bufferView.IsValid()) {
                SHA256_Update(&sha256, bufferView.GetData(), currentRead);
            } else {
                return "Error_Reading_File";
            }
            offset += currentRead;
        }

        SHA256_Final(hash, &sha256);

        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int) hash[i];
        }
        return ss.str();
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
        uint64 fSize = obj->GetData().GetSize();
        if (fSize > 32 * 1024 * 1024) {
            AppCUI::Dialogs::MessageBox::ShowError("Upload Error", "Fisier > 32MB!");
            return;
        }

        CURL* curl;
        CURLcode res;
        std::string readBuffer;

        curl = curl_easy_init();
        if (curl) {
            std::string url = "https://www.virustotal.com/api/v3/files";
            auto bufferView = obj->GetData().Get(0, (uint32) fSize, false);
            if (!bufferView.IsValid())
                return;

            struct curl_slist* headers = NULL;
            headers                    = curl_slist_append(headers, ("x-apikey: " + VT_API_KEY).c_str());

            curl_mime* form      = NULL;
            curl_mimepart* field = NULL;
            form                 = curl_mime_init(curl);
            field                = curl_mime_addpart(form);
            curl_mime_name(field, "file");
            curl_mime_data(field, (const char*) bufferView.GetData(), bufferView.GetLength());
            curl_mime_filename(field, "scan_sample.bin");

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                AppCUI::Dialogs::MessageBox::ShowError("CURL Error", curl_easy_strerror(res));
            } else {
                try {
                    auto json = nlohmann::json::parse(readBuffer);
                    if (json.contains("data")) {
                        AppCUI::Dialogs::MessageBox::ShowNotification("Success", "Upload reusit! Verifica din nou in cateva secunde.");
                    } else {
                        std::string err = json.dump();
                        if (json.contains("error"))
                            err = json["error"]["message"];
                        AppCUI::Dialogs::MessageBox::ShowError("Upload Fail", err.c_str());
                    }
                } catch (...) {
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
                if (json["error"]["code"] == "NotFoundError") {
                    AppCUI::Dialogs::MessageBox::ShowWarning("Not Found", "Fisierul nu este in baza de date.\nFoloseste Upload.");
                } else {
                    std::string msg = json["error"]["message"];
                    AppCUI::Dialogs::MessageBox::ShowError("VT Error", msg.c_str());
                }
                return;
            }

            listView->DeleteAllItems();

            if (json.contains("data") && json["data"]["attributes"].contains("last_analysis_results")) {
                auto results = json["data"]["attributes"]["last_analysis_results"];

                for (auto it = results.begin(); it != results.end(); ++it) {
                    auto engine = it.value();

                    std::string name     = it.key();
                    std::string category = engine["category"].get<std::string>();
                    std::string result   = engine["result"].is_null() ? "clean" : engine["result"].get<std::string>();

                    listView->AddItem({ name, category, result });
                }
            }
        } catch (const std::exception& e) {
            AppCUI::Dialogs::MessageBox::ShowError("JSON Error", e.what());
        } catch (...) {
            AppCUI::Dialogs::MessageBox::ShowError("Error", "Unknown error parsing JSON");
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