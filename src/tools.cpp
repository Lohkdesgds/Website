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
	if (time_del_sec != 0) cookie += "; Max-Age=" + std::to_string(time_del_sec > 0 ? time_del_sec : 0) + "";
	res.set_header("Set-Cookie", cookie);
}

void CookieConf::remove_from(httplib::Response& res) const
{
	if (name.empty() || value.empty()) return;
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
			const char* _tmp = asctime(&tm);
			replace = _tmp ? _tmp : "FAILED_DATE";
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


// SOURCE: https://opensource.apple.com/source/OpenSSL/OpenSSL-22/openssl/demos/x509/mkcert.c


/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */

int add_ext(X509* cert, int nid, char* value)
{
	X509_EXTENSION* ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return 0;

	X509_add_ext(cert, ex, -1);
	X509_EXTENSION_free(ex);
	return 1;
}

static void callback(int p, int n, void* arg)
{
	//char c = 'B';
	//
	//if (p == 0) c = '.';
	//if (p == 1) c = '+';
	//if (p == 2) c = '*';
	//if (p == 3) c = '\n';
	//fputc(c, stderr);
}

int mkcert(X509** x509p, EVP_PKEY** pkeyp, int bits, int serial, int days)
{
	X509* x;
	EVP_PKEY* pk;
	RSA* rsa;
	X509_NAME* name = NULL;

	if ((pkeyp == NULL) || (*pkeyp == NULL))
	{
		if ((pk = EVP_PKEY_new()) == NULL)
		{
			abort();
			return(0);
		}
	}
	else
		pk = *pkeyp;

	if ((x509p == NULL) || (*x509p == NULL))
	{
		if ((x = X509_new()) == NULL)
			goto err;
	}
	else
		x = *x509p;

	rsa = RSA_generate_key(bits, RSA_F4, callback, NULL);
	if (!EVP_PKEY_assign_RSA(pk, rsa))
	{
		abort();
		goto err;
	}
	rsa = NULL;

	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
	X509_gmtime_adj(X509_get_notBefore(x), 0);
	X509_gmtime_adj(X509_get_notAfter(x), (long)60 * 60 * 24 * days);
	X509_set_pubkey(x, pk);

	name = X509_get_subject_name(x);

	/* This function creates and adds the entry, working out the
	 * correct string type and performing checks on its length.
	 * Normally we'd check the return value for errors...
	 */
	X509_NAME_add_entry_by_txt(name, "C",
		MBSTRING_ASC, (const unsigned char*)"UK", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN",
		MBSTRING_ASC, (const unsigned char*)"OpenSSL Group", -1, -1, 0);

	/* Its self signed so set the issuer name to be the same as the
	 * subject.
	 */
	X509_set_issuer_name(x, name);

	/* Add various extensions: standard extensions */
	add_ext(x, NID_basic_constraints, "critical,CA:TRUE");
	add_ext(x, NID_key_usage, "critical,keyCertSign,cRLSign");

	add_ext(x, NID_subject_key_identifier, "hash");

	/* Some Netscape specific extensions */
	add_ext(x, NID_netscape_cert_type, "sslCA");

	add_ext(x, NID_netscape_comment, "example comment extension");


#ifdef CUSTOM_EXT
	/* Maybe even add our own extension based on existing */
	{
		int nid;
		nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
		X509V3_EXT_add_alias(nid, NID_netscape_comment);
		add_ext(x, nid, "example comment alias");
	}
#endif

	if (!X509_sign(x, pk, EVP_md5()))
		goto err;

	*x509p = x;
	*pkeyp = pk;
	return(1);
err:
	return(0);
}