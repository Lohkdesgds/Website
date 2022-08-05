#include "handlers.h"

void _internal_logger(const std::string& textl) {
	static std::mutex mu;
	std::lock_guard<std::mutex> l(mu);
	MAKEDAY();
	const char* _tmp = asctime(&tm);
	std::string date = "unknown";
	if (_tmp) {
		date = _tmp;
		for (auto& i : date) if (i == '\n') i = '\0';
	}
	std::cout << "[" << date << "] " << textl << std::endl;
}

void static_logger(const httplib::Request& req, const httplib::Response& res) {
	_internal_logger("[LOG] " + req.remote_addr + ":" + std::to_string(req.remote_port) + " => rq: (" + req.path + ")");
}

void file_request_handler(const httplib::Request& req, httplib::Response& res) {
	
	static_logger(req, res);

	const std::string filepath = root_path_public + req.path;

	const auto send_file = [&filepath, &req, &res]() {
		const auto type = httplib::detail::find_content_type(filepath, {});
		std::string buf;

		if (!type) {
			res.status = 404;
			error_handler(req, res);
			return false;
		}
		//else { res.set_header("Content-Type", type); }

		httplib::detail::read_file(filepath, buf);
		const size_t datasiz = buf.size();

		if (datasiz == 0) {
			res.status = 404;
			error_handler(req, res);
			return false;
		}

		res.set_content_provider(datasiz, type,
			[
				ipref = req.remote_addr + ":" + std::to_string(req.remote_port), 
				abuf = std::move(buf),
				datasiz,
				relpath = req.path
			](size_t offset, size_t length, httplib::DataSink& sink) {
				if (offset + length > datasiz) {
					_internal_logger("[FATAL-ERROR] Failed sending '" + relpath + "'!");
					return false;
				}
				sink.write(abuf.data() + offset, length);
				if (log_full()) _internal_logger("[U/D] " + ipref + " <= dl: (" + relpath + " " + std::to_string(((length + offset) * 100) / datasiz) + "%)");
				return true;
			},
			[
				ipref = req.remote_addr + ":" + std::to_string(req.remote_port),
				relpath = req.path
			](bool succ) {
				if (log_full()) _internal_logger("[U/D] " + ipref + " <= dl: (" + relpath + " " + (succ ? "100% OK" : "FAILED") + ")");
			}
		);

		return true;
	};

	if (!httplib::detail::is_file(filepath)) {
		res.status = 404;
		error_handler(req, res);
		return;
	}

	const size_t rfin = req.path.rfind('/');
	const std::string sb = (rfin != std::string::npos) ? req.path.substr(0, rfin) : "/";
	const std::string fp = (rfin != std::string::npos) ? req.path.substr(rfin + 1) : "";


	if (fp.find(token_file) == 0) {
		res.set_redirect(page_not_found);
		return;
	}
	if (fp.find("login.html") == 0) {
		send_file();
		return;
	}

	const std::string expect_token = sb + "/" + token_file;
	const std::string expect_login = sb + "/" + login_file;

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

	send_file();
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
	_internal_logger("[EXC] " + req.remote_addr + ":" + std::to_string(req.remote_port) + " # " +  std::to_string(res.status));

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
	_internal_logger("[ERR] " + req.remote_addr + ":" + std::to_string(req.remote_port) + " # " +  std::to_string(res.status));

	const std::string possurl = "/error/" + std::to_string(res.status) + ".html";
	const std::string possibl = root_path_public + possurl;

	if (httplib::detail::is_file(possibl)) {
		_internal_logger("[ERR] " + req.remote_addr + ":" + std::to_string(req.remote_port) + " <- " + possurl);
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