#include <iostream>
#include <httplib.h>
#include <filesystem>
#include <nlohmann/json.hpp>
#include "tools.h"

const std::string root_path_public = "./public_host";
const std::string page_not_found = "/error/404.html";
const std::string page_auth_failed = "/error/auth_failure.html";
const std::string page_host_failed = "/error/host_failure.html";

//const std::string token_cookie = "token";
const std::string token_file = "token.json";
const long long token_cookie_timeout = 28800; // 8 hours
const int port = 54354;

int main(int argc, char* argv[])
{
	std::cout << "Loading stuff...\n";
	int port_used = port;

	if (argc > 1)
	{
		port_used = std::atoi(argv[1]);
		if (port_used < 0 || port_used > 65535) {
			std::cout << "Argument " << argv[1] << " is not a valid number. Port not defined manually.\n";
			port_used = port;
		}
	}

	httplib::Server svr;

	if (!svr.set_mount_point("/", root_path_public, httplib::Headers()))
	{
		std::cout << "Please create path /public_host to mount the server properly.\n";
		return 1;
	}

	svr.set_keep_alive_max_count(10);

	svr.set_post_routing_handler([](const httplib::Request& req, httplib::Response& res) {
		find_and_replace_all(res.body);
	});

	svr.set_error_handler([](const httplib::Request& req, httplib::Response& res) {
		std::cout << "[ERR] " << req.remote_addr << ":" << req.remote_port << " # " << res.status << std::endl;

		const std::string possurl = "/error/" + std::to_string(res.status) + ".html";
		const std::string possibl = root_path_public + possurl;

		if (httplib::detail::is_file(possibl)) {
			std::cout << "[ERR] " << req.remote_addr << ":" << req.remote_port << " <- " << possurl << std::endl;
			res.set_redirect(possurl);
		}
		else {
			auto fmt = "<p>Internal error! HTTP error code: <span style='color:red;'>%d</span></p>";
			char buf[BUFSIZ];
			snprintf(buf, sizeof(buf), fmt, res.status);
			res.set_content(buf, "text/html");
		}
	});

	svr.set_exception_handler([](const httplib::Request& req, httplib::Response& res, std::exception_ptr ep) {
		std::cout << "[EXC] " << req.remote_addr << ":" << req.remote_port << " # " << res.status << std::endl;

		const std::string possurl = "/error/" + std::to_string(res.status) + ".html";
		const std::string possibl = root_path_public + possurl;

		if (httplib::detail::is_file(possibl)) {
			res.set_redirect(possurl);
		}
		else {
			std::string fin = "<p>Internal error! HTTP error code: <span style='color:red;'>500</span></p><br><p>Detailed: ";

			try {
				std::rethrow_exception(ep);
			}
			catch (const std::exception& e) {
				const auto* wh = e.what();
				for (size_t p = 0; p < 96 && wh && wh[p] != '\0'; ++p) fin += (char)wh[p];
			}
			catch (...) { // See the following NOTE
				fin += "Unknown Exception";
			}

			fin += "</p>";
			res.set_content(fin.c_str(), "text/html");
		}
		res.status = 500;
	});

	svr.set_logger([](const httplib::Request& req, const httplib::Response& res) {
		std::cout << "[LOG] " << req.remote_addr << ":" << req.remote_port << " => " << req.path << std::endl;
		if (const auto _str = res.get_header_value("Location"); !_str.empty()) std::cout << "[LOG] " << req.remote_addr << ":" << req.remote_port << " <- " << _str << std::endl;
	});

	svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
		
		if (req.path.back() == '/') {
			res.set_redirect(req.path + "index.html");
			return httplib::Server::HandlerResponse::Handled;
		}
		else if (req.path.empty()) {
			res.set_redirect("/index.html");
			return httplib::Server::HandlerResponse::Handled;
		}
		else if (httplib::detail::is_dir(root_path_public + req.path)) {
			res.set_redirect(req.path + "/index.html");
			return httplib::Server::HandlerResponse::Handled;
		}

		return httplib::Server::HandlerResponse::Unhandled;
	});

	svr.set_file_request_handler([](const httplib::Request& req, httplib::Response& res) {
		const size_t rfin = req.path.rfind('/');
		const std::string sb = (rfin != std::string::npos) ? req.path.substr(0, rfin) : "/";
		const std::string fp = (rfin != std::string::npos) ? req.path.substr(rfin + 1) : "";


		if (fp.find(token_file) == 0) {
			res.set_redirect(page_not_found);
			return;
		}
		if (fp.find("login.html") == 0) {
			return;
		}

		const std::string expect_token = sb + "/" + token_file;
		const std::string expect_login = sb + "/login.html";

		CookieConf cookie(root_path_public + expect_token);

		const bool page_has_token = httplib::detail::is_file(root_path_public + expect_token);
		const bool page_has_login = httplib::detail::is_file(root_path_public + expect_login);

		if (page_has_token) {

			if (!cookie.exists()) // malformed token
			{
				cookie.remove_from(res);
				res.set_redirect(page_host_failed);
				return;
			}
			else if (!cookie.check_has(req)) { // not logged in. Has token.
				if (page_has_login) {
					cookie.remove_from(res);
					const std::string redir = expect_login + "?redir=" + httplib::detail::encode_url(req.path);
					res.set_redirect(redir);
					return;
				}
				else { // no login page, so that's bad.
					res.set_redirect(page_host_failed);
					return;
				}
			}

			cookie.merge_into(res);
		}
		else {
			cookie.remove_from(res);
		}
	});

	std::cout << "Hosting @ port = " << port_used << "\n";

	if (!svr.listen("0.0.0.0", port_used)) {
            std::cout << "Bad news, bind/listen failed.\n";
        }

	return 0;
}