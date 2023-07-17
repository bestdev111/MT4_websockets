#include "stdafx.h"
#include "params.h"
#include "safe_vector.hpp"
#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXHttpClient.h>

#include <winsock2.h>
#include <iphlpapi.h> 
#pragma comment(lib, "iphlpapi.lib")
#pragma comment (lib, "crypt32")

using namespace std;

#define MT_EXPFUNC extern "C" __declspec(dllexport)
#define dbg(msg) writeLog(".\\webscoket.log", msg);

static ix::WebSocket webSocket;
static SafeVector messages;
static string last_error;

int writeLog(const char *file, const char *content) {
	if (file && content) {
		FILE *fd;
		errno_t err = fopen_s(&fd, file, "a+b");
		if (err != 0)
			return 1;
		else {
			SYSTEMTIME st;
			GetLocalTime(&st);
			fprintf(fd, "%04d.%02d.%02d %02d:%02d:%02d.%03d::%s\r\n",
				st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, content);

			fclose(fd);
		}
	}
	return 0;
}

MT_EXPFUNC int __stdcall SetHeader(const char *key, const char * value) {
	ix::WebSocketHttpHeaders headers;
	headers[key] = value;
	webSocket.setExtraHeaders(headers);
}

MT_EXPFUNC int __stdcall Init(const char *url, int timeout, int heat_beat_period) {
	string server_url(url);

	try {
		ix::initNetSystem();

		webSocket.setUrl(server_url);

		webSocket.setPingInterval(heat_beat_period);

		// Per message deflate connection is enabled by default. You can tweak its parameters or disable it
		webSocket.disablePerMessageDeflate();

		// Setup a callback to be fired when a message or an event (open, close, error) is received
		webSocket.setOnMessageCallback([](const ix::WebSocketMessagePtr& msg)
		{
			if (msg->type == ix::WebSocketMessageType::Message)
			{
				messages.push_back(msg->str);
			}
		}
		);

		ix::WebSocketInitResult r = webSocket.connect(timeout);

		if (r.success) {
			webSocket.start();

			last_error.clear();
			return 1;
		}
		
		last_error.append(r.errorStr);
		return 0;
	}
	catch (std::exception & e) {
//		std::cerr << "websockets something wrong happened! " << std::endl;
//		std::cerr << e.what() << std::endl;
		dbg(e.what());
		last_error.append(e.what());
	}
	catch (...) {
	}


	return 0;
}

MT_EXPFUNC void __stdcall Deinit() {
	try {
		webSocket.stop();
		ix::uninitNetSystem();		
	}
	catch (std::exception & e) {
	//	std::cerr << e.what() << std::endl;
		dbg(e.what());
	}
	catch (...) {
	}

}

MT_EXPFUNC void  __stdcall WSGetLastError(char *data) {

	if (last_error.length() > 0) {
		strcpy(data, last_error.c_str());
		strcat(data, "\0");
	}
}

MT_EXPFUNC int  __stdcall httpSendPost(const char* url_, const char * input, int timeout, char *output) {
	ix::HttpResponsePtr out;
	std::string url(url_);

	ix::HttpClient httpClient;
	ix::HttpRequestArgsPtr args = httpClient.createRequest();

	args->connectTimeout = timeout;
	args->transferTimeout = timeout;

	ix::SocketTLSOptions opts;
	//opts.caFile = "cacert.pem";
	opts.caFile = "SYSTEM";
	httpClient.setTLSOptions(opts);
	out = httpClient.post(url, std::string(input), args);

	auto statusCode = out->statusCode;

	if (statusCode == 200) {		
		strcpy(output, out->body.c_str());
		strcat(output, "\0");
	}
	else {
		strcpy(output, out->errorMsg.c_str());
		strcat(output, "\0");
	}

	return statusCode;
}

MT_EXPFUNC int  __stdcall GetCommand(char *data) {

	if (messages.size() > 0) {
		strcpy(data, messages.back().c_str());
		strcat(data, "\0");

		messages.pop_back();

		return 1;
	}

	return 0;
}

MT_EXPFUNC int  __stdcall SendCommand(const char *command) {
	webSocket.send(command);
	return 1;
}

inline bool is_base64(unsigned char c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_decode(std::string const& encoded_string) {
	const std::string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

	int in_len = encoded_string.size();
	int i = 0;
	int j = 0;
	int in_ = 0;
	unsigned char char_array_4[4], char_array_3[3];
	std::string ret;

	while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
		char_array_4[i++] = encoded_string[in_]; in_++;
		if (i == 4) {
			for (i = 0; i < 4; i++)
				char_array_4[i] = base64_chars.find(char_array_4[i]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; (i < 3); i++)
				ret += char_array_3[i];
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; j++)
			char_array_4[j] = 0;

		for (j = 0; j < 4; j++)
			char_array_4[j] = base64_chars.find(char_array_4[j]);

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
	}

	return ret;
}

MT_EXPFUNC int  __stdcall base64Decode(const char* data, char *out) {
	strcpy(out, base64_decode(data).c_str());
	strcat(out, "\0");
}

char* getMAC_Address()
{
	char buf[13];
	IP_ADAPTER_INFO AdapterInfo[16];							// Allocate information for up to 16 NICs
	DWORD dwBufLen = sizeof(AdapterInfo);					// Save the memory size of buffer

	DWORD dwStatus = GetAdaptersInfo(							// Call GetAdapterInfo
		AdapterInfo,																// [out] buffer to receive data
		&dwBufLen);																	// [in] size of receive data buffer
//	assert(dwStatus == ERROR_SUCCESS);						// Verify return value is valid, no buffer overflow

	PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;	// Contains pointer to current adapter info
	sprintf_s(buf, "%02X%02X%02X%02X%02X%02X",
		pAdapterInfo->Address[0],
		pAdapterInfo->Address[1],
		pAdapterInfo->Address[2],
		pAdapterInfo->Address[3],
		pAdapterInfo->Address[4],
		pAdapterInfo->Address[5]);

	return buf;


};

MT_EXPFUNC int  __stdcall getMAC(char *out) {
	strcpy(out, getMAC_Address());
	strcat(out, "\0");

	return 0;
}


MT_EXPFUNC int  __stdcall loadCache(const char* path) {
	Params.Init(path);
	return 0;
}

MT_EXPFUNC int  __stdcall setCache(const char* key, const char *val) {
	Params.Set(key, val);
	return 0;
}

MT_EXPFUNC int  __stdcall getCache(const char* key, char *val) {
	strcpy(val, Params.Get(key).c_str());
	strcat(val, "\0");

	return 0;
}
