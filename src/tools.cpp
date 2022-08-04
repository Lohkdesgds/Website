#include "tools.h"

std::string CookieConf::get_cookie(const httplib::Request& req) const
{
	if (!req.has_header("Cookie")) return std::string();
	std::string cookies = req.get_header_value("Cookie");
	if (cookies.empty()) return std::string();
	size_t pos = (" " + cookies).find(std::string(" ") + name + std::string("="));
	if (pos == std::string::npos) return std::string();
	size_t len = pos + name.length() + 1;
	std::string cookie = cookies.substr(len, cookies.find(";", len));
	return cookie; // decode ..., true;
}

CookieConf::CookieConf(const std::string& path)
{
	if (!httplib::detail::is_file(path)) return;

	std::string filedat;
	httplib::detail::read_file(path, filedat);

	nlohmann::json j = nlohmann::json::parse(filedat, nullptr, false);

	if (const auto& i = j.find("name"); i != j.end()) name = httplib::detail::encode_url(i->get<std::string>());
	if (const auto& i = j.find("value"); i != j.end()) value = httplib::detail::encode_url(i->get<std::string>());
	if (const auto& i = j.find("time_del_sec"); i != j.end()) time_del_sec = i->get<long long>();

	if (time_del_sec < 0) time_del_sec = -1;
}

CookieConf::CookieConf(const std::string& name, const std::string& value, const long long timeout)
	: name(name), value(value), time_del_sec(timeout)
{
}

void CookieConf::merge_into(httplib::Response& res) const
{
	if (name.empty() || value.empty()) return;
	std::string cookie = name + std::string("=") + value; // already encoded url
	if (time_del_sec != 0) cookie += "; Max-Age=" + std::to_string(time_del_sec > 0 ? time_del_sec : 0);
	res.set_header("Set-Cookie", cookie);
}

void CookieConf::remove_from(httplib::Response& res) const
{
	std::string cookie = name + std::string("=") + value + "; Max-Age=0";
	res.set_header("Set-Cookie", cookie);
}

bool CookieConf::check_has(const httplib::Request& req) const
{
	return exists() && get_cookie(req) == value;
}

bool CookieConf::exists() const
{
	return !name.empty() && !value.empty();
}

//void set_cookie(httplib::Response& resp, const std::string& name, const std::string& val, const long long maxagesec) {
//	std::string cookie = name + std::string("=") + httplib::detail::encode_url(val);
//	if (maxagesec != 0) cookie += "; Max-Age=" + std::to_string(maxagesec > 0 ? maxagesec : 0);
//	resp.set_header("Set-Cookie", cookie);
//}
//
//void del_cookie(httplib::Response& resp, const std::string& name) {
//	set_cookie(resp, name, "delete", -1);
//}
//
//std::string get_cookie(const httplib::Request& resp, const std::string& name) {
//	if (!resp.has_header("Cookie")) return std::string();
//	std::string cookies = resp.get_header_value("Cookie");
//	if (cookies.empty()) return std::string();
//	size_t pos = (" " + cookies).find(std::string(" ") + name + std::string("="));
//	if (pos == std::string::npos) return std::string();
//	size_t len = pos + name.length() + 1;
//	std::string cookie = cookies.substr(len, cookies.find(";", len));
//	return httplib::detail::decode_url(cookie, true);
//}

bool find_and_replace_all(std::string& body)
{
	while (1) {
		size_t fo = std::string::npos;
		const auto it = std::find_if(std::begin(opt_arr), std::end(opt_arr), [&](const std::string& opt) { return (fo = body.find(opt)) != std::string::npos; });
		if (!it || fo == std::string::npos) break;

		std::string replace;

		const size_t it_c = it - std::begin(opt_arr);

		switch (it_c) {
		case 0: //"%date%"
		{
			MAKEDAY(false);
			replace = asctime(&tm);
		}
			break;
		case 1: //"%tm_sec%"
		{
			MAKEDAY(false);
			replace = std::to_string(tm.tm_sec);
		}
			break;
		case 2: //"%tm_min%"
		{
			MAKEDAY(false);
			replace = std::to_string(tm.tm_min);
		}
			break;
		case 3: //"%tm_hour%"
		{
			MAKEDAY(false);
			replace = std::to_string(tm.tm_hour);
		}
			break;
		case 4: //"%tm_mday%"
		{
			MAKEDAY(false);
			replace = std::to_string(tm.tm_mday);
		}
			break;
		case 5: //"%tm_mon%"
		{
			MAKEDAY(false);
			replace = std::to_string(tm.tm_mon);
		}
			break;
		case 6: //"%tm_year%"
		{
			MAKEDAY(false);
			replace = std::to_string(tm.tm_year);
		}
			break;
		case 7: //"%tm_wday%"
		{
			MAKEDAY(false);
			replace = std::to_string(tm.tm_wday);
		}
			break;
		case 8: //"%tm_yday%"
		{
			MAKEDAY(false);
			replace = std::to_string(tm.tm_yday);
		}
			break;
		case 9: //"%tm_isdst%"
		{
			MAKEDAY(false);
			replace = std::to_string(tm.tm_isdst);
		}
			break;
		default:
			return false;
		}

		body = body.substr(0, fo) + replace + body.substr(fo + it->length());
	}
	{
		size_t p = 0;
		while ((p = body.find("\\%")) != std::string::npos) {
			body = body.substr(0, p) + body.substr(p + 1);
		}
	}

	return true;
}
