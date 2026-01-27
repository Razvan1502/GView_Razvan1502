#include "DemoPluginGeneric.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <iostream>

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView;
using namespace GView::View;

constexpr int CMD_BUTTON_CLOSE = 1;
constexpr int CMD_BUTTON_MAKE_REQUEST = 2;

struct UserInfo {
    std::string name;
    std::string username;
    std::string companyName;
};


std::vector<UserInfo> parseUserData(const std::string& jsonData)
{
    std::vector<UserInfo> users;

    try {
        nlohmann::json jsonRepsone = nlohmann::json::parse(jsonData);

        for (const auto& user : jsonRepsone) {
            UserInfo userInfo;
            userInfo.name           = user["name"].get<std::string>();
            userInfo.username       = user["username"].get<std::string>();
            userInfo.companyName    = user["company"]["name"].get< std::string>();
            users.push_back(userInfo);
        }
    } catch (const nlohmann::json::parse_error& e) {
        std::cerr << "JSON parsing error: " << e.what() << std::endl;

    }

    return users;
}

//              

#undef MessageBox

// curl write callback to accumulate response into a std::string
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    ((std::string*) userp)->append((char*) contents, size * nmemb);
    return size * nmemb;
}

class DemoPluginGeneric : public Window, public Handlers::OnButtonPressedInterface
{
    Reference<Button> makeRequestButton, closeButton;

    Reference<ListView> listView;

    void MakeRequest()
    {
        CURL* curl;
        CURLcode res;
        std::string readBuffer;

        nlohmann::json jsonResponse;

        const std::string url = "https://jsonplaceholder.typicode.com/users";

        
        // initialize curl
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl = curl_easy_init();


        if(curl) {

            // set curl options
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str()); 
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);


            res = curl_easy_perform(curl);


            if(res != CURLE_OK) {
                std::cerr << "curl request failed : " << curl_easy_strerror(res) << std::endl;
            } else {
                try {
                    jsonResponse = nlohmann::json::parse(readBuffer);
                    listView->DeleteAllItems();
                    auto users = parseUserData(readBuffer);

                    for (const auto& user : users) {
                        listView->AddItem({ user.name, user.username, user.companyName });
                    }


                   // std::cout << "Response JSON: " << jsonResponse.dump(4) << std::endl;
                } catch (const nlohmann::json::parse_error& e) {
                    std::cerr << "JSON parsing error: " << e.what() << std::endl;
                    AppCUI::Dialogs::MessageBox::ShowError("JSON parsing error", e.what());
                }
            }
            curl_easy_cleanup(curl);
        }

        curl_global_cleanup();
    }

  public:
    DemoPluginGeneric() : Window("Demo generic API", "d:c,w:70,h:20", WindowFlags::Sizeable | WindowFlags::Maximized)
    {
        // "Name", "Username", "Company"
        listView = Factory::ListView::Create(this, "t:6,l:2,b:2,r:2", { "n:Name,a:l,w:15", "n:Username,a:l,w:15", "n:Company,a:l,w:30" });

        makeRequestButton = Factory::Button::Create(this, "&Make Request", "t:2,l:2,w:20", CMD_BUTTON_MAKE_REQUEST);
        makeRequestButton->Handlers()->OnButtonPressed = this;
        
        closeButton = Factory::Button::Create(this, "&Close", "t:4,l:2,w:20", CMD_BUTTON_CLOSE);
        closeButton->Handlers()->OnButtonPressed = this;
    }
    void OnButtonPressed(Reference<Button> btn) override
    {
        switch (btn->GetControlID()) {
            case CMD_BUTTON_MAKE_REQUEST:
                MakeRequest();
                break;
            case CMD_BUTTON_CLOSE:
                this->Exit();
                break;
            default:
                break;
        }

        this->Exit();
    }
};

extern "C"
{
    PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> currentObject)
    {
        // all good
        if (command == "MakeGenericAPI")
        {
            DemoPluginGeneric dlg;
            dlg.Show();
            return true;
        }
        return false;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Command.MakeGenericAPI"] = Input::Key::Ctrl | Input::Key::Alt | Input::Key::Shift | Input::Key::F10;
    }
}
