#pragma once

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <time.h>
#include <thread>
#include <future>
#include "tools.h"

const std::string root_path_public = "./public_host";
const std::string page_not_found = "/error/404.html";
const std::string page_auth_failed = "/error/auth_failure.html";
const std::string page_host_failed = "/error/host_failure.html";

//const std::string token_cookie = "token";
const std::string token_file = "token.json";
const long long token_cookie_timeout = 28800; // 8 hours
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
const int port = 553;
#else
const int port = 80;
#endif

void static_logger(const httplib::Request& req, const httplib::Response& res);
void file_request_handler(const httplib::Request& req, httplib::Response& res);
httplib::Server::HandlerResponse pre_router_handler(const httplib::Request& req, httplib::Response& res);
void exception_handler(const httplib::Request& req, httplib::Response& res, std::exception_ptr ep);
void error_handler(const httplib::Request& req, httplib::Response& res);
void post_routing_handler(const httplib::Request& req, httplib::Response& res);