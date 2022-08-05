#pragma once

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <time.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>

const std::string CURRDATE = __TIMESTAMP__;

const std::string opt_arr[] = {
	"%date%", "%tm_sec%", "%tm_min%", "%tm_hour%", "%tm_mday%", "%tm_mon%", "%tm_year%", "%tm_wday%", "%tm_yday%", "%tm_isdst%",
	"%compiled_date%"
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

bool find_and_replace_all(std::string& body);

#ifdef _WIN32
#define GMTIM(A,B) gmtime_s(B,A)
#define BADGM(X) (X != 0)
#else
#define GMTIM(A,B) gmtime_r(A,B)
#define BADGM(X) (!X)
#endif

#define MAKEDAY(onfail) \
tm tm;\
time_t t = time(0);\
if (BADGM(GMTIM(&t, &tm))) {\
	return onfail;\
}

int mkcert(X509** x509p, EVP_PKEY** pkeyp, int bits, int serial, int days);

bool __log_full(bool* = nullptr);
bool make_log_full(bool);
bool log_full();