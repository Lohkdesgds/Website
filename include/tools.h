#pragma once

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <time.h>

const std::string opt_arr[] = {
	"%date%", "%tm_sec%", "%tm_min%", "%tm_hour%", "%tm_mday%", "%tm_mon%", "%tm_year%", "%tm_wday%", "%tm_yday%", "%tm_isdst%"
};

class CookieConf {
	std::string name;
	std::string value;
	long long time_del_sec = 0;

	std::string get_cookie(const httplib::Request&) const;
public:
	CookieConf(const std::string& path);
	CookieConf(const std::string& name, const std::string& value, const long long timeout = 0);

	void merge_into(httplib::Response&) const;
	void remove_from(httplib::Response&) const;
	bool check_has(const httplib::Request&) const;

	bool exists() const;
};

// sec < 0 == delete
//void set_cookie(httplib::Response& resp, const std::string& name, const std::string& val, const long long maxagesec = 0);
//void del_cookie(httplib::Response& resp, const std::string& name);
//std::string get_cookie(const httplib::Request& resp, const std::string& name);

bool find_and_replace_all(std::string& body);

#ifdef _WIN32
#define GMTIM(A,B) gmtime_s(B,A)
#else
#define GMTIM(A,B) gmtime_r(A,B)
#endif

#define MAKEDAY(onfail) \
tm tm;\
time_t t = time(0);\
if (!GMTIM(&t, &tm)) {\
	return onfail;\
}