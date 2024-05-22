#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")

constexpr u_short DHCPSServerPort = 67;
constexpr u_short DHCPClientPort = 68;

/**
* uint8_t options[312]の理由
* > The 'options' field is now variable length. A DHCP client must be
* > prepared to receive DHCP messages with an 'options' field of at least
* > length 312 octets.  This requirement implies that a DHCP client must
* > be prepared to receive a message of up to 576 octets, the minimum IP
* > datagram size an IP host must be prepared to accept.
*/
constexpr uint32_t DHCPOptionsSize = 312;

/*
* https://datatracker.ietf.org/doc/html/rfc2131#page-9
* >  0                   1                   2                   3
* >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
* >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* >  |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
* >  +---------------+---------------+---------------+---------------+
* >  |                            xid (4)                            |
* >  +-------------------------------+-------------------------------+
* >  |           secs (2)            |           flags (2)           |
* >  +-------------------------------+-------------------------------+
* >  |                          ciaddr  (4)                          |
* >  +---------------------------------------------------------------+
* >  |                          yiaddr  (4)                          |
* >  +---------------------------------------------------------------+
* >  |                          siaddr  (4)                          |
* >  +---------------------------------------------------------------+
* >  |                          giaddr  (4)                          |
* >  +---------------------------------------------------------------+
* >  |                                                               |
* >  |                          chaddr  (16)                         |
* >  |                                                               |
* >  |                                                               |
* >  +---------------------------------------------------------------+
* >  |                                                               |
* >  |                          sname   (64)                         |
* >  +---------------------------------------------------------------+
* >  |                                                               |
* >  |                          file    (128)                        |
* >  +---------------------------------------------------------------+
* >  |                                                               |
* >  |                          options (variable)                   |
* >  +---------------------------------------------------------------+
* >
* >  Figure 1:  Format of a DHCP message
*/
struct DHCPMessage {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	uint8_t options[DHCPOptionsSize];
};

int main(void) {
	WSADATA wsaData = {};
	SOCKET sock = {};
	constexpr int RecvAddrSize = sizeof(sockaddr_in);
	constexpr int RecvBufLen = 512;
	char recvBuf[RecvBufLen];

	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed." << std::endl;
		return 1;
	}

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sock == INVALID_SOCKET) {
		std::cerr << "socket creation failed." << std::endl;
		WSACleanup();
		return 1;
	}

	BOOL broadcast = TRUE;
	if(setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof(broadcast)) < 0) {
		std::cerr << "setsockopt failed." << std::endl;
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	struct sockaddr_in clientAddr = {};
	clientAddr.sin_family = AF_INET;
	clientAddr.sin_port = htons(DHCPClientPort);
	clientAddr.sin_addr.s_addr = INADDR_ANY;

	if(bind(sock, (struct sockaddr*)&clientAddr, sizeof(clientAddr)) < 0) {
		std::cerr << "bind failed." << std::endl;
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	// DHCP Discoverメッセージの作成

	/*
	* >   FIELD      OCTETS       DESCRIPTION
	* >   -----      ------       -----------
	* >
	* >   op            1  Message op code / message type.
	* >					1 = BOOTREQUEST, 2 = BOOTREPLY
	* >   htype         1  Hardware address type, see ARP section in "Assigned
	* >					Numbers" RFC; e.g., '1' = 10mb ethernet.
	* >   hlen          1  Hardware address length (e.g.  '6' for 10mb
	* >					ethernet).
	* >   hops          1  Client sets to zero, optionally used by relay agents
	* >					when booting via a relay agent.
	* >   xid           4  Transaction ID, a random number chosen by the
	* >					client, used by the client and server to associate
	* >					messages and responses between a client and a
	* >					server.
	* >   secs          2  Filled in by client, seconds elapsed since client
	* >					began address acquisition or renewal process.
	* >   flags         2  Flags (see figure 2).
	* >   ciaddr        4  Client IP address; only filled in if client is in
	* >					BOUND, RENEW or REBINDING state and can respond
	* >					to ARP requests.
	* >   yiaddr        4  'your' (client) IP address.
	* >   siaddr        4  IP address of next server to use in bootstrap;
	* >					returned in DHCPOFFER, DHCPACK by server.
	* >   giaddr        4  Relay agent IP address, used in booting via a
	* >					relay agent.
	* >   chaddr       16  Client hardware address.
	* >   sname        64  Optional server host name, null terminated string.
	* >   file        128  Boot file name, null terminated string; "generic"
	* >					name or null in DHCPDISCOVER, fully qualified
	* >					directory-path name in DHCPOFFER.
	* >   options     var  Optional parameters field.  See the options
	* >					documents for a list of defined options.
	*/
	DHCPMessage dhcpDiscover = {
		.op = 1,
		.htype = 1,
		.hlen = 6,
		.hops = 0,
		.xid = htonl(0x12345678), // ここは適当
		.secs = 0,
		.flags = htons(0x8000), // ブロードキャストフラグを立てる
		.ciaddr = 0,
		.yiaddr = 0,
		.siaddr = 0,
		.giaddr = 0,
		.chaddr = 0,
		.sname = 0,
		.file = 0,
		.options = 0
	};

	// MACアドレスの設定
	const std::vector<uint8_t> mac = {0xC0, 0xFF, 0xEE, 0xC0, 0xFF, 0xEE};
	std::copy(mac.begin(), mac.end(), dhcpDiscover.chaddr);

	dhcpDiscover.options[0] = 53;	// Message Type
	dhcpDiscover.options[1] = 1;	// Length
	dhcpDiscover.options[2] = 1;	// DHCP Discover
	dhcpDiscover.options[3] = 255;	// End option

	sockaddr_in broadcastAddr = {};
	sockaddr_in recvAddr = {};
	broadcastAddr.sin_family = AF_INET;
	broadcastAddr.sin_port = htons(DHCPSServerPort);
	broadcastAddr.sin_addr.s_addr = INADDR_BROADCAST;

	// ここでDHCP Discoverメッセージをブロードキャスト
	if(sendto(sock, (char*)&dhcpDiscover, sizeof(dhcpDiscover), 0, (struct sockaddr*)&broadcastAddr, sizeof(broadcastAddr)) < 0) {
		std::cerr << "sendto failed." << std::endl;
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	std::cout << "DHCP Discover 送信" << std::endl;

	// ここでDHCP Offer メッセージを受信
	int recvAddrSize = RecvAddrSize;
	if(recvfrom(sock, recvBuf, RecvBufLen, 0, (struct sockaddr*)&recvAddr, &recvAddrSize) < 0) {
		std::cerr << "recvfrom failed." << std::endl;
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	std::cout << "DHCP Offer 受信" << std::endl;

	// 以下受信したメッセージの内容を出力する

	const DHCPMessage* dhcpOffer = (DHCPMessage*)recvBuf;

	std::cout << "DHCP Message:" << std::endl;
	std::cout << "  op: " << static_cast<int>(dhcpOffer->op) << std::endl;
	std::cout << "  htype: " << static_cast<int>(dhcpOffer->htype) << std::endl;
	std::cout << "  hlen: " << static_cast<int>(dhcpOffer->hlen) << std::endl;
	std::cout << "  hops: " << static_cast<int>(dhcpOffer->hops) << std::endl;
	std::cout << "  xid: " << ntohl(dhcpOffer->xid) << std::endl;
	std::cout << "  secs: " << ntohs(dhcpOffer->secs) << std::endl;
	std::cout << "  flags: " << ntohs(dhcpOffer->flags) << std::endl;

	char addrBuffer[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &dhcpOffer->ciaddr, addrBuffer, INET_ADDRSTRLEN);
	std::cout << "  ciaddr: " << addrBuffer << std::endl;
	inet_ntop(AF_INET, &dhcpOffer->yiaddr, addrBuffer, INET_ADDRSTRLEN);
	std::cout << "  yiaddr: " << addrBuffer << std::endl;
	inet_ntop(AF_INET, &dhcpOffer->siaddr, addrBuffer, INET_ADDRSTRLEN);
	std::cout << "  siaddr: " << addrBuffer << std::endl;
	inet_ntop(AF_INET, &dhcpOffer->giaddr, addrBuffer, INET_ADDRSTRLEN);
	std::cout << "  giaddr: " << addrBuffer << std::endl;

	std::cout << "  chaddr: ";
	for(uint32_t i = 0; i < 16; ++i) {
		std::cout << std::hex << static_cast<int>(dhcpOffer->chaddr[i]) << " ";
	}
	std::cout << std::dec << std::endl;
	std::cout << "  sname: " << dhcpOffer->sname << std::endl;
	std::cout << "  file: " << dhcpOffer->file << std::endl;
	std::cout << "  options: ";
	for(uint32_t i = 0; i < DHCPOptionsSize; ++i) {
		std::cout << std::hex << static_cast<int>(dhcpOffer->options[i]) << " ";
		if(dhcpOffer->options[i] == 255) {
			break;
		}
	}
	std::cout << std::dec << std::endl;

	closesocket(sock);
	WSACleanup();
	return 0;
}