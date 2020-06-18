#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <net/if.h>

// Constant
#define STDIN_FD 0

// Length Limitation
#define MAX_TYPE_LENGTH 10
#define MAX_NAME_LENGTH 100
#define MAX_STRING_LENGTH 100
#define MAX_PACKET_LENGTH 200
#define MAX_IPV4_BUFFER_LENGTH 20
#define MAX_IPV4_STRING_LENGTH 16

// Network Configuration
#define PORT 12345
#define PORT_PEER_VERIFICATION 60350
#define SERVER_ADDRESS "10.1.1.1"

// Type value
#define MSG_REGISTER 1
#define MSG_REGISTER_RESPONSE 2
#define MSG_DEREGISTER 3
#define MSG_DEREGISTER_RESPONSE 4
#define MSG_GET 5
#define MSG_GET_RESPONSE 6
#define MSG_VERIFY 7
#define MSG_VERIFY_RESPONSE 8
#define MSG_TYPE_NETERR 9

// Code value
#define MSG_SUCCESS 0
#define MSG_FAILED 1
#define MSG_KERNEL_NETERR 2

// Data value for verification
#define IPv4_VM1 "10.1.1.2"
#define IPv4_VM3 "10.1.2.2"

// Confidential data value for verification
#define STUDENT_ID_NUMBER "2017320110"

// Server socket variable
int sock;
struct sockaddr_in server_addr;

// Function prototype
void do_add(char*, unsigned char*, char*);
void do_del(char*, unsigned char*, char*);
void do_get(char*, char*);
void do_verify(char*);
void find_my_name(char*);
unsigned char checksum_generate(char*, int);
bool checksum_verify(char*, int);
void view_help(void);

// Get result list for verification
struct get_result {
	char name[MAX_NAME_LENGTH];
	char ipv4_addr_string[MAX_IPV4_BUFFER_LENGTH];
	struct get_result* prev;
	struct get_result* next;
};
struct get_result* head = NULL;

int main(void) {
	
	/* Declaration */

	// For work selection
	int retval;
	fd_set rfds_copy, rfds;

	// For general work
	char buffer[MAX_PACKET_LENGTH];
	char name[MAX_NAME_LENGTH];
	char type[MAX_TYPE_LENGTH];
	unsigned char dest[4];
	int i, len, dest_temp[4];

	// For verification
	int sock_verify;
	int buffer_verify_len;
	char my_name[MAX_NAME_LENGTH];
	char buffer_verify[MAX_PACKET_LENGTH];
	char buffer_verify_test[MAX_STRING_LENGTH] = "Hi, hello world: ";
	struct sockaddr_in verify_addr;
	struct sockaddr_in verify_from;
	int size = sizeof(verify_from);
	int name_len;
	int message_len = strlen("Hi, hello world: ") + strlen(STUDENT_ID_NUMBER);

	/* Initialization */

	// Socket creation
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("[ FATAL__ ] Socket creation error.\n");
		return 1;
	}

	// Socket configuration
	len = sizeof(server_addr);
	memset(&server_addr, 0, len);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);

	// Server IPv4 address verification
	if (inet_pton(AF_INET, SERVER_ADDRESS, &server_addr.sin_addr) <= 0) {
		printf("[ FATAL__ ] Invalid server IPv4 address.\n");
		return 1;
	}

	/* Preparation for direct verification request */

	// Socket creation
	if ((sock_verify = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("[ FATAL__ ] This device is not prepared for peer to peer verification.\n");
		return 1;
	}

	// Socket configuration
	len = sizeof(verify_addr);
	memset(&verify_addr, 0, len);
	verify_addr.sin_family = AF_INET;
	verify_addr.sin_port = htons(PORT_PEER_VERIFICATION);
	verify_addr.sin_addr.s_addr = INADDR_ANY;

	// Socket binding
	if (bind(sock_verify, (struct sockaddr*)&verify_addr, len) < 0) {
		printf("[ FATAL__ ] Socket binding failure.\n");
		return 1;
	}

	// Preparing work selection
	FD_ZERO(&rfds);
	FD_SET(STDIN_FD, &rfds);
	FD_SET(sock_verify, &rfds);
	strcat(buffer_verify_test, STUDENT_ID_NUMBER);

	/* Start application */

	printf("[ READY__ ] If you want to read manual, type help.\n\n");

	while(1) {

		rfds_copy = rfds;
		if ((retval = select(sock_verify + 1, &rfds_copy, 0, 0, 0)) < 0) {
			printf("[ FATAL__ ] Select function error occured.\n");
			return 1;
		}

		// Input occured
		if (retval > 0) {
			// Verification request
			if (FD_ISSET(sock_verify, &rfds_copy) > 0) {
				// Read verification request
				recvfrom(sock_verify, buffer_verify, sizeof(buffer_verify), 0, (struct sockaddr*)&verify_from, &size);
				
				// Preparation
				find_my_name(my_name);
				name_len = ntohs(*(unsigned short*)(buffer_verify + 2));
				buffer_verify_len = 4 + name_len + message_len;

				// Check type validity
				if (buffer_verify[0] != MSG_VERIFY) {
					buffer_verify[0] = MSG_TYPE_NETERR;
					buffer_verify[1] = MSG_FAILED;
					sendto(sock_verify, buffer_verify, buffer_verify_len, 0, (struct sockaddr*)&verify_from, sizeof(verify_from));
				}

				// Check message validity
				else if (strncmp(buffer_verify + 4 + name_len, buffer_verify_test, message_len) != 0) {
					buffer_verify[0] = MSG_VERIFY_RESPONSE;
					buffer_verify[1] = MSG_FAILED;
					sendto(sock_verify, buffer_verify, buffer_verify_len, 0, (struct sockaddr*)&verify_from, sizeof(verify_from));
				}

				// Check name validity
				else if (strncmp(buffer_verify + 4, my_name, name_len) != 0) {
					buffer_verify[0] = MSG_VERIFY_RESPONSE;
					buffer_verify[1] = MSG_FAILED;
					sendto(sock_verify, buffer_verify, buffer_verify_len, 0, (struct sockaddr*)&verify_from, sizeof(verify_from));
				}

				// Okay
				else {
					buffer_verify[0] = MSG_VERIFY_RESPONSE;
					buffer_verify[1] = MSG_SUCCESS;
					sendto(sock_verify, buffer_verify, buffer_verify_len, 0, (struct sockaddr*)&verify_from, sizeof(verify_from));
				}
			}

			// Keyboard input
			if (FD_ISSET(STDIN_FD, &rfds_copy) > 0) {
				scanf("%s", type);

				// add
				if (strncmp(type, "add", 3) == 0) {
					scanf("%s", name);
					scanf(" %d.%d.%d.%d", &dest_temp[0], &dest_temp[1], &dest_temp[2], &dest_temp[3]);
					for (i = 0; i < 4; i++) dest[i] = (unsigned char)dest_temp[i];
					do_add(name, dest, buffer);
				}

				// del
				else if (strncmp(type, "del", 3) == 0) {
					scanf("%s", name);
					scanf(" %d.%d.%d.%d", &dest_temp[0], &dest_temp[1], &dest_temp[2], &dest_temp[3]);
					for (i = 0; i < 4; i++) dest[i] = (unsigned char)dest_temp[i];
					do_del(name, dest, buffer);
				}

				// get
				else if (strncmp(type, "get", 3) == 0) {
					scanf("%s", name);
					do_get(name, buffer);
				}

				// verify
				else if (strncmp(type, "verify", 6) == 0) {
					scanf("%s", name);
					do_verify(name);
				}

				// exit
				else if (strncmp(type, "exit", 4) == 0) {
					printf("[ GOODBYE ] Session terminated.\n");
					fgets(name, MAX_NAME_LENGTH, stdin); // avoid space remaining in input buffer
					break;
				}

				// help
				else if (strncmp(type, "help", 4) == 0) view_help();

				// error
				else printf("[ NET_ERR ] Instruction cannot be understood.\n\n");

				// Avoid space character remaining in input buffer
				fgets(name, MAX_STRING_LENGTH, stdin);
			}
		}
	}

	/* Termination */

	close(sock);
	close(sock_verify);

	return 0;

}

void do_add(char* name, unsigned char* dest, char* output) {

	/* Declaration */

	int i;
	char result[MAX_PACKET_LENGTH];
	char ipv4_addr_string[MAX_IPV4_BUFFER_LENGTH], ipv4_addr_string_receive[MAX_IPV4_BUFFER_LENGTH];
	
	unsigned char* type = (unsigned char*)output;
	unsigned short* length = (unsigned short*)(output + 1);
	unsigned int* ipv4_addr = (unsigned int*)(output + 3);
	unsigned char* checksum = (unsigned char*)(output + 7);

	unsigned char* type_receive = (unsigned char*)result;
	unsigned char* code_receive = (unsigned char*)(result + 1);
	unsigned short* length_receive = (unsigned short*)(result + 2);
	unsigned char* name_receive = (unsigned char*)(result + 4);
	unsigned int* ipv4_addr_receive = (unsigned int*)(result + 4);
	unsigned char* checksum_receive = (unsigned char*)(result + 8);

	/* Working */

	*type = MSG_REGISTER;
	*length = htons(strlen(name));
	strcpy(output + 3, name);
	ipv4_addr = (unsigned int*)((unsigned char*)ipv4_addr + strlen(name));
	for (i = 0; i < 4; i++) *((unsigned char*)ipv4_addr + i) = dest[i];
	checksum += strlen(name);
	*checksum = checksum_generate(output, strlen(name));

	sendto(sock, output, 8 + strlen(name), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
	read(sock, result, MAX_PACKET_LENGTH);

	// Fix pointers
	ipv4_addr_receive = (unsigned int*)((unsigned char*)ipv4_addr_receive + ntohs(*length_receive));
	checksum_receive += *length_receive;

	/* Error detection */

	// Different type received
	if (*type_receive != MSG_REGISTER_RESPONSE) {
		printf("[ NET_ERR ] Network error in type field.\n\n");
		return;
	}

	// Duplication
	if (*code_receive == MSG_FAILED) {
		printf("[ DUPLICA ] Value about requested machine already exists.\n\n");
		return;
	}

	// Kernel failed
	if (*code_receive != MSG_SUCCESS) {
		printf("[ NET_ERR ] Network error in code field.\n\n");
		return;
	}

	// Different length received
	if (*length_receive != *length) {
		printf("[ NET_ERR ] Network error in length field.\n\n");
		return;
	}

	// Different name received
	if (strncmp(name, name_receive, strlen(name)) != 0) {
		printf("[ NET_ERR ] Network error in name field.\n\n");
		return;
	}

	inet_ntop(AF_INET, ipv4_addr, ipv4_addr_string, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ipv4_addr_receive, ipv4_addr_string_receive, INET_ADDRSTRLEN);

	// Different IPv4 address received
	if (strcmp(ipv4_addr_string, ipv4_addr_string_receive) != 0) {
		printf("[ NET_ERR ] Network error in IPv4 address field.\n\n");
		return;
	}

	// Checksum error
	if (!checksum_verify(result, strlen(name))) {
		printf("[ NET_ERR ] Network error in checksum field.\n\n");
		return;
	}

	// Success
	printf("[ SUCCESS ] Registration Successful.\n\n");

	return;

}

void do_del(char* name, unsigned char* dest, char* output) {

	/* Declaration */

	int i;
	char result[MAX_PACKET_LENGTH];
	char ipv4_addr_string[MAX_IPV4_BUFFER_LENGTH];
	char ipv4_addr_string_receive[MAX_IPV4_BUFFER_LENGTH];
	
	unsigned char* type = (unsigned char*)output;
	unsigned short* length = (unsigned short*)(output + 1);
	unsigned int* ipv4_addr = (unsigned int*)(output + 3);
	unsigned char* checksum = (unsigned char*)(output + 7);

	unsigned char* type_receive = (unsigned char*)result;
	unsigned char* code_receive = (unsigned char*)(result + 1);
	unsigned short* length_receive = (unsigned short*)(result + 2);
	unsigned char* name_receive = (unsigned char*)(result + 4);
	unsigned int* ipv4_addr_receive = (unsigned int*)(result + 4);
	unsigned char* checksum_receive = (unsigned char*)(result + 8);

	/* Working */

	*type = MSG_DEREGISTER;
	*length = htons(strlen(name));
	strcpy(output + 3, name);
	ipv4_addr = (unsigned int*)((unsigned char*)ipv4_addr + strlen(name));
	for (i = 0; i < 4; i++) *((unsigned char*)ipv4_addr + i) = dest[i];
	checksum += strlen(name);
	*checksum = checksum_generate(output, strlen(name));

	sendto(sock, output, 8 + strlen(name), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
	read(sock, result, MAX_PACKET_LENGTH);

	// Fix Pointers
	ipv4_addr_receive = (unsigned int*)((unsigned char*)ipv4_addr_receive + ntohs(*length_receive));
	checksum_receive += *length_receive;

	/* Error detection */

	// Different type received
	if (*type_receive != MSG_DEREGISTER_RESPONSE) {
		printf("[ NET_ERR ] Network error in type field.\n\n");
		return;
	}

	// Inexistence
	if (*code_receive == MSG_FAILED) {
		printf("[ NOEXIST ] Value about requested machine and IPv4 address does not exist.\n\n");
		return;
	}

	// Kernel failed
	if (*code_receive != MSG_SUCCESS) {
		printf("[ NET_ERR ] Network error in code field.\n\n");
		return;
	}

	// Different length received
	if (*length_receive != *length) {
		printf("[ NET_ERR ] Network error in length field.\n\n");
		return;
	}

	// Different name received
	if (strncmp(name, name_receive, strlen(name)) != 0) {
		printf("[ NET_ERR ] Network error in name field.\n\n");
		return;
	}

	inet_ntop(AF_INET, ipv4_addr, ipv4_addr_string, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, ipv4_addr_receive, ipv4_addr_string_receive, INET_ADDRSTRLEN);

	// Different IPv4 address received
	if (strcmp(ipv4_addr_string, ipv4_addr_string_receive) != 0) {
		printf("[ NET_ERR ] Network error in IPv4 address field.\n\n");
		return;
	}

	// Checksum error
	if (!checksum_verify(result, strlen(name))) {
		printf("[ NET_ERR ] Network error in checksum field.\n\n");
		return;
	}

	// Success
	printf("[ SUCCESS ] Removal Successful.\n\n");

	return;

}

void do_get(char* name, char* output) {

	/* Declaration */

	char result[MAX_PACKET_LENGTH];
	
	unsigned char* type = (unsigned char*)output;
	unsigned short* length = (unsigned short*)(output + 1);
	unsigned char* checksum = (unsigned char*)(output + 3);

	unsigned char* type_receive = (unsigned char*)result;
	unsigned char* code_receive = (unsigned char*)(result + 1);
	unsigned short* length_receive = (unsigned short*)(result + 2);
	unsigned char* name_receive = (unsigned char*)(result + 4);
	unsigned int* ipv4_addr_receive = (unsigned int*)(result + 4);
	unsigned char* checksum_receive = (unsigned char*)(result + 8);

	unsigned char ipv4_a, ipv4_b, ipv4_c, ipv4_d;

	struct get_result* ptr = head;
	struct get_result* new_node = NULL;

	/* Working */

	*type = MSG_GET;
	*length = htons(strlen(name));
	strcpy(output + 3, name);
	checksum += strlen(name);
	*checksum = checksum_generate(output, strlen(name));

	sendto(sock, output, 4 + strlen(name), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
	read(sock, result, MAX_PACKET_LENGTH);

	// Fix pointers
	ipv4_addr_receive = (unsigned int*)((unsigned char*)ipv4_addr_receive + ntohs(*length_receive));
	checksum_receive += *length_receive;

	/* Error detection */

	// Different type received
	if (*type_receive != MSG_GET_RESPONSE) {
		printf("[ NET_ERR ] Network error in type field.\n\n");
		return;
	}

	// Inexistence
	if (*code_receive == MSG_FAILED) {
		printf("[ NOEXIST ] Value about requested machine does not exist.\n\n");
		return;
	}

	// Kernel failed
	if (*code_receive != MSG_SUCCESS) {
		printf("[ NET_ERR ] Network error in code field.\n\n");
		return;
	}

	// Different length received
	if (*length_receive != *length) {
		printf("[ NET_ERR ] Network error in length field.\n\n");
		return;
	}

	// Different name received
	if (strncmp(name, name_receive, strlen(name)) != 0) {
		printf("[ NET_ERR ] Network error in name field.\n\n");
		return;
	}

	// Checksum error
	if (!checksum_verify(result, strlen(name))) {
		printf("[ NET_ERR ] Network error in checksum field.\n\n");
		return;
	}

	// Success
	ipv4_a = (unsigned char)(*ipv4_addr_receive >> 24);
	ipv4_b = (unsigned char)(*ipv4_addr_receive >> 16);
	ipv4_c = (unsigned char)(*ipv4_addr_receive >> 8);
	ipv4_d = (unsigned char)*ipv4_addr_receive;

	printf("[ SUCCESS ] Received IPv4 address is [ %d.%d.%d.%d ].\n", (int)ipv4_d, (int)ipv4_c, (int)ipv4_b, (int)ipv4_a);

	// Save result
	if (head == NULL) {
		new_node = (struct get_result*)malloc(sizeof(struct get_result));
		strcpy(new_node->name, name);
		inet_ntop(AF_INET, ipv4_addr_receive, new_node->ipv4_addr_string, MAX_IPV4_BUFFER_LENGTH);
		new_node->prev = NULL;
		new_node->next = NULL;
		head = new_node;
		printf("[ SAVEADR ] New IPv4 address information is now saved.\n\n");
	}
	else {
		while(ptr != NULL) {
			if (strcmp(ptr->name, name) == 0) {
				// Previous node update
				inet_ntop(AF_INET, ipv4_addr_receive, result, MAX_IPV4_STRING_LENGTH);
				if (strcmp(ptr->ipv4_addr_string, result) == 0) {
					printf("[ SAME_AS ] Received IPv4 address is same as which is already known.\n\n");
				}
				else {
					strcpy(ptr->ipv4_addr_string, name);
					printf("[ UPDATED ] New IPv4 address information is now saved.\n\n");
				}
				break;
			}
			if (ptr->next == NULL) {
				// New node insert
				new_node = (struct get_result*)malloc(sizeof(struct get_result));
				strcpy(new_node->name, name);
				inet_ntop(AF_INET, ipv4_addr_receive, new_node->ipv4_addr_string, MAX_IPV4_BUFFER_LENGTH);
				new_node->prev = ptr;
				new_node->next = NULL;
				ptr->next = new_node;
				printf("[ SAVEADR ] New IPv4 address information is now saved.\n\n");
				break;
			}
			else ptr = ptr->next;
		}
	}

	return;

}

void do_verify(char* name) {

	/* Declaration */

	int sock_verify;
	struct sockaddr_in dest;
	char output[MAX_PACKET_LENGTH], result[MAX_PACKET_LENGTH];
	char ipv4_addr_string[MAX_IPV4_STRING_LENGTH];
	int name_len = strlen(name);
	int message_len = strlen("Hi, hello world: ") + strlen(STUDENT_ID_NUMBER);
	int dest_len;
	struct get_result* ptr = head;
	char buffer_name[MAX_NAME_LENGTH];
	char buffer_verify_test[MAX_STRING_LENGTH] = "Hi, hello world: ";

	/* Connecting to destination */

	// Socket creation
	if ((sock_verify = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("[ FATAL__ ] Socket creation error.\n");
		return;
	}

	// Socket configuration
	dest_len = sizeof(dest);
	memset(&dest, 0, dest_len);
	dest.sin_family = AF_INET;
	dest.sin_port = htons(PORT_PEER_VERIFICATION);

	// Get IPv4 address string
	if (head == NULL) {
		printf("[ UNKNOWN ] Get request should be made before requesting verification.\n\n");
		return;
	}
	else {
		while(ptr != NULL) {
			if (strcmp(ptr->name, name) == 0) break;
			if (ptr->next == NULL) {
				printf("[ UNKNOWN ] Get request should be made before requesting verification.\n\n");
				return;
			}
		}
	}

	// Server IPv4 address verification
	if (inet_pton(AF_INET, ptr->ipv4_addr_string, &dest.sin_addr) <= 0) {
		printf("[ INVALID ] Invalid IPv4 address confirmed.\n\n");
		return;
	}

	// Fill values
	output[0] = MSG_VERIFY; // Type
	output[1] = MSG_SUCCESS; // Code
	*(unsigned short*)(output + 2) = htons(name_len); // Length

	strcpy(buffer_name, name);
	strcat(name, "Hi, hello world: ");
	strcat(name, STUDENT_ID_NUMBER);
	strcat(name, "");
	strcpy(output + 4, name);

	// Ping
	sendto(sock_verify, output, 4 + name_len + message_len, 0, (struct sockaddr*)&dest, dest_len);
	read(sock_verify, result, MAX_PACKET_LENGTH);

	// Check type and code validity
	if (result[0] != MSG_VERIFY_RESPONSE || result[1] != MSG_SUCCESS) {
		printf("[ INVALID ] The address saved previously is confirmed invalid.\n\n");
		return;
	}

	// Check message validity
	strcat(buffer_verify_test, STUDENT_ID_NUMBER);
	if (strncmp(result + 4 + ntohs(*(unsigned short*)(result + 2)), buffer_verify_test, message_len) != 0) {
		printf("[ INVALID ] The address saved previously is confirmed invalid.\n\n");
		return;
	}

	// Check name validity
	if (strncmp(result + 4, buffer_name, name_len) != 0) {
		printf("[ INVALID ] The address saved previously is confirmed invalid.\n\n");
		return;
	}

	// Success
	printf("[ VALID__ ] The address saved previously is verified.\n\n");

	return;

}

void find_my_name(char* array) {

	int my_socket;
	struct ifreq ifr;
	struct sockaddr_in* ptr;

	my_socket = socket(AF_INET, SOCK_DGRAM, 0);

	strncpy(ifr.ifr_name, "enp0s3", IFNAMSIZ - 1);
	ioctl(my_socket, SIOCGIFADDR, &ifr);

	ptr = (struct sockaddr_in*)&ifr.ifr_addr;
	inet_ntop(AF_INET, &ptr->sin_addr, array, sizeof(struct sockaddr));

	// Hardcoding
	if (strcmp(array, IPv4_VM1) == 0) strcpy(array, "VM1");
	else if (strcmp(array, IPv4_VM3) == 0) strcpy(array, "VM3");
	else strcpy(array, "");

	close(my_socket);

	return;

}

unsigned char checksum_generate(char* array, int name_length) {

	int i, length;
	unsigned char sum = 0;

	if (array[0] == MSG_GET) length = name_length + 4;
	else length = name_length + 8;

	for (i = 0; i < length - 1; i++) {
		sum += (unsigned char)array[i];
	}

	return sum;

}

bool checksum_verify(char* array, int name_length) {

	int i, length;
	unsigned char sum = 0;

	length = name_length + 9;

	for (i = 0; i < length - 1; i++) {
		sum += (unsigned char)array[i];
	}

	return (unsigned char)array[length - 1] == sum;

}

void view_help(void) {

	printf("\n---------------------------------------------------------------\n");
	printf("|      You can use add, del, get, help, verify, exit.         |\n");
	printf("|      Please refer to project manual for further help.       |\n");
	printf("---------------------------------------------------------------\n\n");

	return;

}
