include(generic_plugin)
create_generic_plugin(FileHashPlugin)

find_package(CURL REQUIRED)
target_link_libraries(FileHashPlugin PRIVATE CURL::libcurl)    

find_package(nlohmann_json REQUIRED)
target_link_libraries(FileHashPlugin PRIVATE nlohmann_json::nlohmann_json)