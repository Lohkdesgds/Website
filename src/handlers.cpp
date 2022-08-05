#include "handlers.h"

void static_logger(const httplib::Request& req, const httplib::Response& res) {
	static std::mutex mu;
	std::lock_guard<std::mutex> l(mu);
	std::cout << "[LOG] " << req.remote_addr << ":" << req.remote_port << " => " << req.path << std::endl;
	if (const auto _str = res.get_header_value("Location"); !_str.empty()) std::cout << "[LOG] " << req.remote_addr << ":" << req.remote_port << " <- " << _str << std::endl;
}

void file_request_handler(const httplib::Request& req, httplib::Response& res) {
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
}

httplib::Server::HandlerResponse pre_router_handler(const httplib::Request& req, httplib::Response& res) {

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
}

void exception_handler(const httplib::Request& req, httplib::Response& res, std::exception_ptr ep) {
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
}

void error_handler(const httplib::Request& req, httplib::Response& res) {
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
}

void post_routing_handler(const httplib::Request& req, httplib::Response& res) {
	find_and_replace_all(res.body);
}