#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <iostream>
#include <httplib.h>
#include <filesystem>
#include <thread>
#include <future>
#include <nlohmann/json.hpp>
#include "tools.h"
#include "handlers.h"


std::future<bool> setup(httplib::Server* svr, const int port_used, const bool ipv6);

int main(int argc, char* argv[])
{
	std::cout << "Loading stuff... (built @ " << CURRDATE << ")\n";
	int port_used = port;
	bool ssl = false;
	bool enable_ipv4 = false, enable_ipv6 = false;
	bool log_verbose = false;

	if (argc > 1)
	{
		for (int aa = 1; aa < argc; ++aa)
		{
			if (strcmp(argv[aa], "-ssl") == 0) {
				ssl = true;
				std::cout << "(arg) SSL enabled.\n";
			}
			else if (strcmp(argv[aa], "-help") == 0) {
				enable_ipv4 = true;
				std::cout << "Arguments:\n-ssl (enable ssl, experimental)\n-help (this, exist on print)\n-ipv4 (enable ipv4 host)\n-ipv6 (enable ipv6 host)\n-fulllog (show all things going on)\n-port <num> (set port)\n";
				return 0;
			}
			else if (strcmp(argv[aa], "-ipv4") == 0) {
				enable_ipv4 = true;
				std::cout << "(arg) IPV4 enabled.\n";
			}
			else if (strcmp(argv[aa], "-fulllog") == 0) {
				log_verbose = true;
				std::cout << "(arg) Full log enabled.\n";
			}
			else if (strcmp(argv[aa], "-ipv6") == 0) {
				enable_ipv6 = true;
				std::cout << "(arg) IPV6 selected.\n";
			}
			else if (strcmp(argv[aa], "-port") == 0) {
				if (aa + 1 >= argc) {
					std::cout << "(arg) Cannot read port number correctly. Do -port <number>\n";
					return 1;
				}
				port_used = std::atoi(argv[aa + 1]);

				if (port_used < 0 || port_used > 65535) {
					std::cout << "(arg) Argument " << argv[aa + 1] << " is not a valid number for -port. Port reset.\n";
					port_used = port;
				}
				else {
					std::wcout << "(arg) Port " << port_used << " defined.\n";
				}

				++aa;
			}
		}
	}

	make_log_full(log_verbose);

	if (!enable_ipv4 && !enable_ipv6) {
		enable_ipv4 = true;
		std::cout << "By default, IPV4 is being used. Use -ipv4 and/or -ipv6 to be explicit on what to enable (or both).\n";
	}

	X509* xxx = nullptr;
	EVP_PKEY* ppp = nullptr;

	httplib::Server* sv4 = nullptr;
	httplib::Server* sv6 = nullptr;
	std::future<bool> v4f, v6f;

	if (ssl) {
		mkcert(&xxx, &ppp, 2048, 0, 365);
	}

	const auto reset = [&] {
		httplib::Server* ptr = nullptr;
		if (ssl) {
			ptr = (httplib::Server*)new httplib::SSLServer(xxx, ppp);
		}
		else {
			ptr = new httplib::Server();
		}
		return ptr;
	};

	const auto auto_setup = [&](const int select = 0) {
		if (enable_ipv4 && (select == 0 || select == 1)) {
			if (sv4) {
				std::cout << "Stopping IPV4...\n";
				sv4->stop();
				delete sv4;
			}
			std::cout << "Setting up IPV4...\n";
			sv4 = reset();
			if (!sv4 || !sv4->is_valid()) return false;
			v4f = setup(sv4, port_used, false);
			if (v4f.wait_for(std::chrono::seconds(0)) == std::future_status::ready) return false;
		}
		if (enable_ipv6 && (select == 0 || select == 2)) {
			if (sv6) {
				std::cout << "Stopping IPV6...\n";
				sv6->stop();
				delete sv6;
			}
			std::cout << "Setting up IPV6...\n";
			sv6 = reset();
			if (!sv6 || !sv6->is_valid()) return false;
			v6f = setup(sv6, port_used, true);
			if (v6f.wait_for(std::chrono::seconds(0)) == std::future_status::ready) return false;
		}
		return true;
	};

	auto_setup();
	std::cout << "Hosting.\n";

	while (1) { // waits forever.
		if (enable_ipv4 && (v4f.wait_for(std::chrono::seconds(10)) == std::future_status::ready)) {
			if (!v4f.get()) {
				while (!auto_setup(1)) {
					std::cout << "Trying again in 5 seconds.\n";
					std::this_thread::sleep_for(std::chrono::seconds(5));
				}
			}
		}
		if (enable_ipv6 && (v6f.wait_for(std::chrono::seconds(10)) == std::future_status::ready)) {
			if (!v6f.get()) {
				while (!auto_setup(2)) {
					std::cout << "Trying again in 5 seconds.\n";
					std::this_thread::sleep_for(std::chrono::seconds(5));
				}
			}
		}
	}

	return 0;
}

std::future<bool> setup(httplib::Server* svr, const int port_used, const bool ipv6)
{
	const auto make_sync_future = [](const bool good) { std::promise<bool> p; auto f = p.get_future(); p.set_value(good); return f; };

	if (!svr->is_valid()) {
		std::cout << "The server is invalid, sorry.\n";
		return make_sync_future(false);
	}

	//if (!svr->set_mount_point("/", root_path_public))
	//{
	//	std::cout << "Please create path /public_host to mount the server properly.\n";
	//	return make_sync_future(false);
	//}

	svr->set_keep_alive_max_count(10);
	//svr->set_post_routing_handler(post_routing_handler);
	svr->set_error_handler(error_handler);
	svr->set_exception_handler(exception_handler);
	svr->set_logger(static_logger);
	svr->set_pre_routing_handler(pre_router_handler);
	svr->Get(".*", file_request_handler);

	std::cout << "Hosting " << (ipv6 ? "IPV6" : "IPV4") << " @ port = " << port_used << "\n";

	return std::async(std::launch::async, [svr, ipv6, port_used] {
		return svr->listen(ipv6 ? "0:0:0:0:0:0:0:0" : "0.0.0.0", port_used);
	});
}
