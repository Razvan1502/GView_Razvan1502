include(generic_plugin)
create_generic_plugin(DemoPluginGeneric)

find_package(CURL REQUIRED)
target_link_libraries(DemoPluginGeneric PRIVATE CURL::libcurl)    

find_package(nlohmann_json REQUIRED)
target_link_libraries(DemoPluginGeneric PRIVATE nlohmann_json::nlohmann_json)