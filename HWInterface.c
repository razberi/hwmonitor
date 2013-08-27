
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <signal.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <json/json.h>

#include "HWInterface.h"
#include "HIDCP2112.h"

//typedef boolean bool;

#define LISTEN_PORT			8600
#define MAXEVENTS			64
#define MAX_SOCKETS 		64
#define SEND_BUFFER 		1 << 16
#define RECV_BUFFER 		1 << 16

#define MAX_4CH_POE			46.5 // in Watts
#define MAX_16CH_POE		149.0
#define POE_FAULT_LEVEL		0.85 // 85% load sets fault LED red

#define VLAN_EEPROM_OFFSET	0x40 // the EEPROM offset where VLAN data is written

// the CP2112 device handle
HID_SMBUS_DEVICE handle = NULL;

Model model;
char serialNumber[16];
char mcuVersion[9];
StatusLED sled;
FaultLED fled;
Port mirrorInDest = 0;
Port mirrorOutDest = 0;


// holds the port data that has been queried via the CP2112
struct port_data {
	int list_idx;
	Port portNum;
	char portName[20];
	bool state;
	int speed;
	double receiveRate;
	double transmitRate;
	bool poeState;
	double powerDraw;
	uint64_t receivedBytes;
	uint64_t transmittedBytes;
	bool isMirrorInSrc;
	bool isMirrorOutSrc;
	time_t updateTime;
};

struct port_data *ports[22];

// holds socket state data like file descriptor and Tx/Rx buffers
struct socket_state {
	int fd;
	int list_idx;
	bool closed;
	BYTE send_buf[SEND_BUFFER];
	ushort send_buf_length;
	BYTE recv_buf[RECV_BUFFER];
	ushort recv_buf_length;
};

struct socket_state *active_sockets[MAX_SOCKETS];
int active_sockets_len = 0;

// holds a message that has been received from the buffer but has not been processed
struct socket_message {
	char *msg;
	struct socket_state *pState; // save the socket ref so we can send replies
	struct socket_message *next;
} socket_message;

bool running = TRUE;
pthread_mutex_t       socket_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutexattr_t   mta;


// port data structs
void InitPortData();
void PrintPortData();
struct port_data *GetPortData(Port port);
void PollData(); // refresh port data structs
void SendUpdate(struct socket_state *pState);

// read/write registers
int ReadRequest(BYTE slaveAddress, BYTE address, BYTE bytesToRead, BYTE *buffer);
int WriteRequest(BYTE slaveAddress, BYTE *buffer, BYTE bytesToWrite);
int ReadPortRegister(Port port, BYTE reg, BYTE *buffer);
int WritePortRegister(Port port, BYTE reg, BYTE *buffer);
int ReadSwitchRegister(BYTE smiAddress, BYTE reg, BYTE switchDevice, BYTE *buffer);
int WriteSwitchRegister(BYTE smiAddress, BYTE reg, BYTE switchDevice, BYTE *buffer);

// basic data
void GetModelAndSerial();
void GetLEDs();
void SetLEDs(FaultLED faultLed, StatusLED statusLed);
void ReadEEPROM(BYTE offset, BYTE count, BYTE *buffer);
void WriteEEPROM(BYTE *buffer, BYTE offset, BYTE count);
void PrintEEPROM();

// switch data
BYTE GetSwitchPortNumber(Port port);
BYTE GetSwitchPortDevice(Port port);
void GetSwitchData();
void GetSwitchPortCounters(Port port);

// PoE data
BYTE GetPoEPortDevice(Port port);
BYTE GetPoEPortRegister(Port port);
void GetPoEData();
double GetPoEPortPowerDraw(int portNume);
void CheckPoEFault();
void EnablePoE();
void EnablePoEPort(Port port);
void EnablePoEDevice(BYTE devAddress);
void EnablePoEChannel(BYTE devAddress, int channel);
void DisablePoE();
void DisablePoEPort(Port port);
void DisablePoEDevice(BYTE devAddress);
void DisablePoEChannel(BYTE devAddress, int channel);

// port mirroring
void ClearMonitorConfiguration();
void SetMonitorConfiguration(Port dest, Port *sources, int srcLen, bool isIngress);
Port GetMonitorDestination(bool isIngress);
bool IsMonitorSource(Port port, bool isIngress);

// VLANs
void SetVlanMask(Port port, BYTE *mask);
void SetVlanScenario0();
void SetVlanScenario1();
int GetVlanScenario();

void timer_handler(int signum);

// socket functions
int RunSocketLoop();
void CloseSocket(int fd);
void AppendSendBuffer(struct socket_state *pState, BYTE *buf, int bufLen);
void AppendRecvBuffer(struct socket_state *pState, BYTE *buf, int bufLen);
void FlushSendBuffer(struct socket_state *pState);
void FlushSendBuffers();

// read socket msg thread
pthread_t recvThread;
void *ProcessMessageThread(void *state);
void ParseMessage(struct socket_message *pMsg);
struct json_object *GenerateJson();

// poll data thread
pthread_t pollThread;
void *PollDataThread(void *state);

void read_file();
char *buffer = 0;
long buflen = 0;
int verbose = 0;

int run();

int main(int argc, char *argv[]) {
	int rc, status_code;

	if (argc > 1 && !strcmp(argv[1], "-v"))
		verbose = 1;

	while (1) {
		rc = fork();
		if (rc < 0) {
			perror("fork");
			exit(rc);
		}

		if (rc == 0)
			exit(run());
		else {
			printf("Waiting on child process PID %d\n", rc);
			wait(&status_code);
			printf("Child process ended, restarting in 5 seconds...\n");
			usleep(5 * 1000 * 1000);
		}
	}
}

int run() {
	int rc;

	// initialize mutexes
	pthread_mutexattr_init(&mta);
	pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE); /* or PTHREAD_MUTEX_RECURSIVE_NP */
	pthread_mutex_init(&socket_lock, &mta);

	// connect to CP2112
	if ((rc = HidCP2112_Connect(CP2112_VID, CP2112_PID, handle)) != 0) {
		fprintf(stderr, "Cannot connect to the CP2112 device. Error code: %d\n", rc);
		return rc;
	}

	SetLEDs(Off, Green); // initially set state to green
	GetModelAndSerial();
	InitPortData();

	//PrintEEPROM();
	//PollData();
	//usleep(2 * 1000 * 1000);
	//PollData();
	//PrintPortData();
	//GenerateJson();

	struct sigaction sa;
	struct itimerval timer;
	/* Install timer_handler as the signal handler for SIGALRM.  */
	memset(&sa, 0, sizeof (sa));
	sa.sa_handler = &timer_handler;
	sigaction(SIGALRM, &sa, NULL);

	// Configure the timer to expire after 2000 msec...
	timer.it_value.tv_sec = 10;
	timer.it_value.tv_usec = 0;
	// ... and every 2000 msec after that
	timer.it_interval.tv_sec = 10;
	timer.it_interval.tv_usec = 0;
	setitimer(ITIMER_REAL, &timer, NULL);

	running = TRUE;
	rc = pthread_create(&recvThread, NULL, ProcessMessageThread, NULL);
	if (rc) {
		printf("ProcessMessageThread: return code from pthread_create(): %d\n", rc);
		return rc;
	}
	rc = pthread_create(&pollThread, NULL, PollDataThread, NULL);
	if (rc) {
		printf("PollDataThread: return code from pthread_create(): %d\n", rc);
		return rc;
	}

	RunSocketLoop();

	running = FALSE;
	return 0;
}

int GetTotalPortCount() {
	return model == Razberi4Port ? 6 : 22;
}

int GetPhysicalPortCount() {
	return model == Razberi4Port ? 5 : 18;
}

int GetNonUplinkPortCount() {
	return model == Razberi4Port ? 4 : 16;
}

void InitPortData() {
	for (int i = 0; i < GetTotalPortCount(); ++i) {
		struct port_data *port;
		port = (struct port_data *)malloc(sizeof(*port));
		port->list_idx = i;
		port->portNum = (Port)(i+1);
		snprintf(port->portName, 20, "Port%d", i+1);
		port->state = FALSE;
		port->speed = 0;
		port->receiveRate = 0.0;
		port->transmitRate = 0.0;
		port->poeState = FALSE;
		port->powerDraw = 0.0;
		port->receivedBytes = 0;
		port->transmittedBytes = 0;
		port->isMirrorInSrc = FALSE;
		port->isMirrorOutSrc = FALSE;
		port->updateTime = time(NULL);
		ports[i] = port;
	}

	if (model == Razberi4Port) {
		ports[4]->portNum = UPLINK_1;
		ports[5]->portNum = COM_X;
		strcpy(ports[4]->portName, "Uplink1");
		strcpy(ports[5]->portName, "Cpu");
	} else {
		ports[16]->portNum = UPLINK_1;
		ports[17]->portNum = UPLINK_2;
		ports[18]->portNum = SWITCH_1;
		ports[19]->portNum = SWITCH_2;
		ports[20]->portNum = COM_X;
		ports[21]->portNum = DSP;
		strcpy(ports[16]->portName, "Uplink1");
		strcpy(ports[17]->portName, "Uplink2");
		strcpy(ports[18]->portName, "Switch1");
		strcpy(ports[19]->portName, "Switch2");
		strcpy(ports[20]->portName, "Cpu");
		strcpy(ports[21]->portName, "DSP");
	}
}

struct port_data *GetPortData(Port port) {
	for (int i = 0; i < GetTotalPortCount(); ++i) {
		if (ports[i]->portNum == port)
			return ports[i];
	}
	return NULL;
}

void PrintPortData() {
	for (int i = 0; i < GetPhysicalPortCount(); ++i) {
		struct port_data *pPort = ports[i];
		printf("[%d] %d :: %s\n", pPort->list_idx, pPort->portNum, pPort->portName);
		printf("State: %d\n", pPort->state);
		printf("Speed: %d\n", pPort->speed);
		printf("PoEState: %d\tPowerDraw: %.2f\n", pPort->poeState, pPort->powerDraw);
		printf("RxBytes: %ju\tTxBytes: %ju\n", pPort->receivedBytes, pPort->transmittedBytes);
		printf("RxRate: %.2f\tTxRate: %.2f\n", pPort->receiveRate, pPort->transmitRate);
		// "2013-05-13T14:29:53-0500"
		char tmbuf[25];
		strftime(tmbuf, 25, "%FT%T%z", localtime(&pPort->updateTime));
		printf("LastUpdate: %s\n\n", tmbuf);
	}
}

struct json_object *GenerateJson() {
	json_object *jobj = json_object_new_object();
	json_object_object_add(jobj, "Model",        json_object_new_string(Get_Model_Name(model)));
	json_object_object_add(jobj, "Serial",       json_object_new_string(serialNumber));
	json_object_object_add(jobj, "MCUVersion",   json_object_new_string(mcuVersion));
	json_object_object_add(jobj, "VLANScenario", json_object_new_int(GetVlanScenario()));
	json_object_object_add(jobj, "StatusLED",    json_object_new_boolean(sled == Green));
	json_object_object_add(jobj, "FaultLED",     json_object_new_boolean(fled == On));

	json_object *jMirroring = json_object_new_object();
	json_object *jIncoming = json_object_new_object();
	json_object *jOutgoing = json_object_new_object();
	json_object_object_add(jIncoming, "Dest", json_object_new_string(mirrorInDest == 0 ? "Disabled" : GetPortData(mirrorInDest)->portName));
	json_object_object_add(jIncoming, "Cpu", json_object_new_boolean(GetPortData(COM_X)->isMirrorInSrc));
	json_object_object_add(jOutgoing, "Dest", json_object_new_string(mirrorOutDest == 0 ? "Disabled" : GetPortData(mirrorOutDest)->portName));
	json_object_object_add(jOutgoing, "Cpu", json_object_new_boolean(GetPortData(COM_X)->isMirrorOutSrc));
	for (int i = 0; i < GetPhysicalPortCount(); ++i) {
		struct port_data *pPort = ports[i];
		json_object_object_add(jIncoming, pPort->portName, json_object_new_boolean(pPort->isMirrorInSrc));
		json_object_object_add(jOutgoing, pPort->portName, json_object_new_boolean(pPort->isMirrorOutSrc));
	}
	json_object_object_add(jMirroring, "Incoming", jIncoming);
	json_object_object_add(jMirroring, "Outgoing", jOutgoing);
	json_object_object_add(jobj, "Mirroring", jMirroring);


	json_object *jPorts   = json_object_new_array();
	json_object *jUplinks = json_object_new_array();

	for (int i = 0; i < GetPhysicalPortCount(); ++i) {
		struct port_data *pPort = ports[i];
		char tmbuf[25];strftime(tmbuf, sizeof tmbuf, "%FT%T%z", localtime(&pPort->updateTime));

		json_object *jPort = json_object_new_object();
		json_object_object_add(jPort, "Port",             json_object_new_int(pPort->portNum));
		json_object_object_add(jPort, "State",            json_object_new_boolean(pPort->state));
		json_object_object_add(jPort, "Speed",            json_object_new_int(pPort->speed));
		json_object_object_add(jPort, "ReceiveRate",      json_object_new_double(pPort->receiveRate));
		json_object_object_add(jPort, "TransmitRate",     json_object_new_double(pPort->transmitRate));
		json_object_object_add(jPort, "ReceivedBytes",    json_object_new_int64(pPort->receivedBytes));
		json_object_object_add(jPort, "TransmittedBytes", json_object_new_int64(pPort->transmittedBytes));
		json_object_object_add(jPort, "PoEState",         json_object_new_boolean(pPort->poeState));
		json_object_object_add(jPort, "PowerDraw",        json_object_new_double(pPort->powerDraw));
		json_object_object_add(jPort, "Updated",          json_object_new_string(tmbuf));
		if (i < GetNonUplinkPortCount())
			json_object_array_add(jPorts, jPort);
		else
			json_object_array_add(jUplinks, jPort);
	}

	json_object_object_add(jobj, "Ports",   jPorts);
	json_object_object_add(jobj, "Uplinks", jUplinks);

	//const char *pJsonString = json_object_to_json_string(jobj);
	//printf("JSON: \n%s\n", pJsonString);
	//return pJsonString;
	return jobj;
}

void PollData() {
	// switch data has finer grained locking within
	// so it is left outside of the lock below
	GetSwitchData();

	HidCP2112_Acquire_Lock();
	GetPoEData();
	GetLEDs();
	CheckPoEFault();
	mirrorInDest  = GetMonitorDestination(TRUE);
	mirrorOutDest = GetMonitorDestination(FALSE);
	HidCP2112_Release_Lock();

	for (int i = 0; i < GetPhysicalPortCount(); ++i) {
		struct port_data *pPort = ports[i];
		printf("Port: %8s State: %d PoEState: %d Speed: %4d InBytes: %15ju OutBytes: %15ju RxRate: %10.2f TxRate: %10.2f\n",
			pPort->portName, pPort->state, pPort->poeState, pPort->speed, pPort->receivedBytes,
			pPort->transmittedBytes, pPort->receiveRate, pPort->transmitRate);
	}
}

void SendUpdate(struct socket_state *pState) {
	json_object *jobj = GenerateJson();
	const char *jsonString = json_object_to_json_string(jobj);
	AppendSendBuffer(pState, (char *)jsonString, strlen(jsonString));
	FlushSendBuffer(pState);
	json_object_put(jobj);
}

void *PollDataThread(void *state) {
	printf(BOLDGREEN "Started poll data thread." RESET "\n");
	while (running) {
		//printf("Polling data.\n");
		PollData();
		usleep(2 * 1000 * 1000);
	}
	printf(BOLDGREEN "Poll data thread ended." RESET "\n");
}

void *ProcessMessageThread(void *state) {
	printf(BOLDGREEN "Started process message thread." RESET "\n");

	struct socket_message *head = NULL;
	struct socket_message *last = NULL;
	while (running) {
		pthread_mutex_lock(&socket_lock);

		for (int i = 0; i < active_sockets_len; ++i) {
			struct socket_state *pState = active_sockets[i];

			if (pState->recv_buf_length == 0)
				continue;

			int count = 0;
			do {
				count = strlen(pState->recv_buf);
				printf("Detected strlen: %d recvBufLen: %d\n", count, pState->recv_buf_length);
				if (count) {
					if (pState->recv_buf_length > 0 &&
						(pState->recv_buf[0] == 0x0A || pState->recv_buf[0] == 0x0D)) {
						memcpy(&pState->recv_buf, &pState->recv_buf[1], RECV_BUFFER - 1);
						pState->recv_buf_length -= 1;
						printf("Trimmed CR/LF byte off beginning of buffer.\n");
						printf("New recvBufLen: %d\n", pState->recv_buf_length);
						continue;
					}
					if (count >= pState->recv_buf_length) {
						printf("No NUL terminator received yet, waiting on next read...\n");
						break;
					}

					count += 1; // make room for null terminator since strlen returns the count without the \0
					struct socket_message *msg = (struct socket_message*)malloc(sizeof(socket_message));
					msg->msg = calloc(count, sizeof(char));
					msg->pState = pState;
					msg->next = NULL;

					memcpy(msg->msg, &pState->recv_buf, count);
					pState->recv_buf_length -= count;
					memcpy(&pState->recv_buf, &pState->recv_buf[count], pState->recv_buf_length);
					//msg->msg[count] = '\0'; // set last char to NUL

					// add msg struct to end of linked list
					if (head == NULL) {
						head = msg;
						last = msg;
					} else {
						last->next = msg;
						last = msg;
					}

					printf("New recvBufLen: %d\n", pState->recv_buf_length);
				} else {
					// count == 0 and recv buf > 0
					// means first char is a \0
					// trim off first char
					if (pState->recv_buf_length > 0 && pState->recv_buf[0] == 0) {
						memcpy(&pState->recv_buf, &pState->recv_buf[1], RECV_BUFFER - 1);
						pState->recv_buf_length -= 1;
						printf("Trimmed NUL byte off beginning of buffer.\n");
						printf("New recvBufLen: %d\n", pState->recv_buf_length);
						count = 1; // so we dont exit the loop unless recv_buf_length is 0
					}
				}
			} while(count && pState->recv_buf_length);
		}
		pthread_mutex_unlock(&socket_lock);

		// now process the messages outside of the lock
		while (head) {
			ParseMessage(head);

			// free the one we just processed and move the
			// pointer to the next one if there is one
			struct socket_message *next = head->next;
			free(head->msg);
			free(head);
			head = next;
		}

		head = last = NULL;
		usleep(2 * 1000 * 1000); // 2s sleep
	}

	printf(BOLDGREEN "Process message thread ended." RESET "\n");
}

bool GetJsonBoolean(struct json_object *jobj) {
	enum json_type type = json_object_get_type(jobj);
	if (type == json_type_boolean)
		return json_object_get_boolean(jobj);
	if (type == json_type_string)
		return strlen(json_object_get_string(jobj)) == 4;
	return 0;
}

void ParseMessage(struct socket_message *pMsg) {
	int strLen = strlen(pMsg->msg);
	printf("Processing msg (%d chars): " BOLDBLUE "%s" RESET "\n", strLen, pMsg->msg);

	struct json_tokener *tok = json_tokener_new();
  	struct json_object *jobj = json_tokener_parse_ex(tok, pMsg->msg, -1);
	if (tok->err != json_tokener_success) {
		printf(BOLDRED "Error parsing message... skipping." RESET "\n");
		json_tokener_free(tok);
		return;
	}

	json_tokener_free(tok);

	struct json_object *jMsgType = NULL;
	struct json_object *jPoEPort = NULL;
	struct json_object *jPoEEnabled = NULL;
	struct json_object *jIncoming = NULL;
	struct json_object *jOutgoing = NULL;
	struct json_object *jInDest = NULL;
	struct json_object *jOutDest = NULL;
	struct json_object *jVlanScenario = NULL;

	jMsgType = json_object_object_get(jobj, "MsgType");
	if (!jMsgType) {
		fprintf(stderr, BOLDRED "Cannot parse: No MsgType property: %s" RESET "\n", pMsg->msg);
		goto parse_out;
	}

	const char *pMsgTypeValue = json_object_get_string(jMsgType);
	if (strcmp(pMsgTypeValue, "Update") == 0) {
		printf(BOLDBLUE "Request update message received." RESET "\n");
		SendUpdate(pMsg->pState);
	} else if (strcmp(pMsgTypeValue, "PoE") == 0) {
		// first get the Port and Enabled properties
		jPoEPort = json_object_object_get(jobj, "Port");
		if (!jPoEPort) {
			fprintf(stderr, BOLDRED "Cannot parse: No Port property for %s command: %s" RESET "\n", pMsgTypeValue, pMsg->msg);
			goto parse_out;
		}
		jPoEEnabled = json_object_object_get(jobj, "Enabled");
		if (!jPoEEnabled) {
			fprintf(stderr, BOLDRED "Cannot parse: No Enabled property %s PoE command: %s" RESET "\n", pMsgTypeValue, pMsg->msg);
			goto parse_out;
		}

		bool bEnabled = GetJsonBoolean(jPoEEnabled);
		const char *pPortName = json_object_get_string(jPoEPort);

		// special case for "all"
		if (strcmp(pPortName, "all") == 0) {
			printf(BOLDBLUE "%s all PoE ports..." RESET "\n", bEnabled ? "Enabling" : "Disabling");
			if (bEnabled) EnablePoE();
			else          DisablePoE();
		} else {
			// find port with this name and apply PoE command
			for (int i = 0; i < GetNonUplinkPortCount(); ++i) {
				struct port_data *pPort = ports[i];
				if (strcmp(pPort->portName, pPortName) == 0) {
					printf(BOLDBLUE "%s PoE for port: (%d) %s" RESET "\n", bEnabled ? "Enabling" : "Disabling", pPort->portNum, pPort->portName);
					if (bEnabled) EnablePoEPort(pPort->portNum);
					else          DisablePoEPort(pPort->portNum);
					goto parse_out;
				}
			}

			fprintf(stderr, "Parse PoE: Cannot find port named: %s\n", pPortName);
		}
	} else if (strcmp(pMsgTypeValue, "Mirroring") == 0) {
		// get the incoming and outgoing objects
		jIncoming = json_object_object_get(jobj, "Incoming");
		if (!jIncoming) {
			fprintf(stderr, BOLDRED "Cannot parse: No Incoming property for incoming %s command: %s" RESET "\n", pMsgTypeValue, pMsg->msg);
			goto parse_out;
		}
		jOutgoing = json_object_object_get(jobj, "Outgoing");
		if (!jOutgoing) {
			fprintf(stderr, BOLDRED "Cannot parse: No Outgoing property for outgoing %s command: %s" RESET "\n", pMsgTypeValue, pMsg->msg);
			goto parse_out;
		}
		jInDest = json_object_object_get(jIncoming, "Dest");
		if (!jInDest) {
			fprintf(stderr, BOLDRED "Cannot parse: No Dest property for incoming %s command: %s" RESET "\n", pMsgTypeValue, pMsg->msg);
			goto parse_out;
		}
		jOutDest = json_object_object_get(jOutgoing, "Dest");
		if (!jOutDest) {
			fprintf(stderr, BOLDRED "Cannot parse: No Dest property for outgoing %s command: %s" RESET "\n", pMsgTypeValue, pMsg->msg);
			goto parse_out;
		}

		ClearMonitorConfiguration();

		const char *strInDest = json_object_get_string(jInDest);
		const char *strOutDest = json_object_get_string(jOutDest);

		Port destInPortNum = 0;
		Port inSources[GetTotalPortCount()];
		int inLen = 0;
		Port destOutPortNum = 0;
		Port outSources[GetTotalPortCount()];
		int outLen = 0;
		struct json_object *jPort = NULL;

		for (int i = 0; i < GetTotalPortCount(); ++i) {
			struct port_data *pPort = ports[i];
			if (strcmp(strInDest, pPort->portName) == 0)
				destInPortNum = pPort->portNum;
			if (strcmp(strOutDest, pPort->portName) == 0)
				destOutPortNum = pPort->portNum;

			jPort = json_object_object_get(jIncoming, pPort->portName);
			if (jPort) {
				bool enabled = GetJsonBoolean(jPort);
				if (enabled) inSources[inLen++] = pPort->portNum;
				json_object_put(jPort);
			}

			jPort = json_object_object_get(jOutgoing, pPort->portName);
			if (jPort) {
				bool enabled = GetJsonBoolean(jPort);
				if (enabled) outSources[outLen++] = pPort->portNum;
				json_object_put(jPort);
			}
		}

		if (destInPortNum == 0 && strcmp(strInDest, "Disabled") != 0) {
			fprintf(stderr, BOLDRED "Parser error: could not find incoming destination port name: %s" RESET "\n", strInDest);
			goto parse_out;
		}
		if (destOutPortNum == 0 && strcmp(strOutDest, "Disabled") != 0) {
			fprintf(stderr, BOLDRED "Parser error: could not find outgoing destination port name: %s" RESET "\n", strOutDest);
			goto parse_out;
		}

		SetMonitorConfiguration(destInPortNum, inSources, inLen, TRUE);
		SetMonitorConfiguration(destOutPortNum, outSources, outLen, FALSE);
	} else if (strcmp(pMsgTypeValue, "VLAN") == 0) {
		jVlanScenario = json_object_object_get(jobj, "VLANScenario");
		if (!jVlanScenario) {
			fprintf(stderr, BOLDRED "Cannot parse: No VLANScenario property for %s command: %s" RESET "\n", pMsgTypeValue, pMsg->msg);
			goto parse_out;
		}

		int vlanScenario = json_object_get_int(jVlanScenario);
		printf(BOLDBLUE "Setting VLAN Scenario: %d" RESET "\n", vlanScenario);
		switch (vlanScenario) {
			case 0: SetVlanScenario0(); break;
			case 1: SetVlanScenario1(); break;
			default: fprintf(stderr, BOLDRED "Unknown VLAN Scenario: %d" RESET "\n", vlanScenario); break;
		}
	} else {
		fprintf(stderr, BOLDRED "Unknown message type: %s" RESET "\n", pMsgTypeValue);
	}

parse_out:
	if (jVlanScenario) json_object_put(jVlanScenario);
	if (jIncoming)     json_object_put(jIncoming);
	if (jOutgoing)     json_object_put(jOutgoing);
	if (jInDest)       json_object_put(jInDest);
	if (jOutDest)      json_object_put(jOutDest);
	if (jPoEEnabled)   json_object_put(jPoEEnabled);
	if (jMsgType)      json_object_put(jMsgType);
	if (jobj)          json_object_put(jobj);
}



/// Read/write Registers

int ReadRequest(BYTE slaveAddress, BYTE address, BYTE bytesToRead, BYTE *buffer) {
	int i;
	BYTE targetAddr[16];
	targetAddr[0] = address;
	BYTE s0, s1;
	ushort s2, s3;
	BYTE status, length = -1;
	BYTE data[64];

	HidCP2112_Acquire_Lock();
	HidCP2112_DataWriteReadRequest(handle, slaveAddress, bytesToRead, 1, targetAddr);

	do {
		HidCP2112_TransferStatusRequest(handle);
	 	HidCP2112_TransferStatusResponse(handle, &s0, &s1, &s2, &s3);
	} while (s0 != HID_SMBUS_S0_COMPLETE);

	HidCP2112_DataReadForceSend(handle, bytesToRead);
	HidCP2112_DataReadResponse(handle, &status, &length, data);
	HidCP2112_Release_Lock();

	for (i = 0; i < length; ++i)
		buffer[i] = data[i];

	return length;
}

int WriteRequest(BYTE slaveAddress, BYTE *buffer, BYTE bytesToWrite) {
	return HidCP2112_DataWrite(handle, slaveAddress, bytesToWrite, buffer);
}

int ReadPortRegister(Port port, BYTE reg, BYTE *buffer) {
	if (reg >= 32) return -1; // there are only 32 registers

	BYTE smiAddress = GetSwitchPortNumber(port) + 0x10;
	BYTE switchAddr = model == Razberi16Port ? GetSwitchPortDevice(port) : 0x00;
	return ReadSwitchRegister(smiAddress, reg, switchAddr, buffer);
}

int WritePortRegister(Port port, BYTE reg, BYTE *buffer) {
	if (reg >= 32) return -1; // there are only 32 registers

	BYTE smiAddress = GetSwitchPortNumber(port) + 0x10;
	BYTE switchAddr = model == Razberi16Port ? GetSwitchPortDevice(port) : 0x00;
	return WriteSwitchRegister(smiAddress, reg, switchAddr, buffer);
}

int ReadSwitchRegister(BYTE smiAddress, BYTE reg, BYTE switchDevice, BYTE *buffer) {
	if (smiAddress >= 32 || reg >= 32)
		return -1; // There are only 32 registers and 32 SMI addresses.
	if (switchDevice > 0x02 || (model == Razberi16Port && switchDevice == 0x00) || (model == Razberi4Port && switchDevice != 0x00))
		return -1; // The switch device must be 0x01 or 0x02 for 16ch or 0x00 for 4ch.

	int read = -1;
	BYTE output[2];

	// enable MDIO
	BYTE writeBytes[3] = { 0x02, 0x01, 0 };
	WriteRequest(Switch, writeBytes, 2);

	if (model == Razberi4Port) {
		// address port register
		writeBytes[0] = 0x5F;
		writeBytes[1] = smiAddress;
		WriteRequest(Switch, writeBytes, 2);

		// read register
		read = ReadRequest(Switch, (0x60 + reg), 2, output);
		if (!read) return -1;
		// reverse order
		buffer[0] = output[1];
		buffer[1] = output[0];
	} else if (model == Razberi16Port) {
		// address switch
		writeBytes[0] = 0x5F;
		writeBytes[1] = switchDevice;
		WriteRequest(Switch, writeBytes, 2);

		ushort smiCommand = (ushort)(1 << 15 | 1 << 12 | 2 << 10 | smiAddress << 5 | reg);
		writeBytes[0] = 0x60;
		writeBytes[1] = (smiCommand & 0xFF); // lsb
		writeBytes[2] = (smiCommand >> 8);   // msb
		WriteRequest(Switch, writeBytes, 3);

		read = ReadRequest(Switch, 0x60, 2, output); // confirm read register
		if (!read || output[0] != writeBytes[1] || output[1] != (writeBytes[2] & 0x7F))
			return -1;

		read = ReadRequest(Switch, 0x61, 2, output); // read register value
		if (!read) return -1;
		// reverse order
		buffer[0] = output[1];
		buffer[1] = output[0];
	}

	return read;
}

int WriteSwitchRegister(BYTE smiAddress, BYTE reg, BYTE switchDevice, BYTE *buffer) {
	if (smiAddress >= 32 || reg >= 32)
		return -1; // There are only 32 registers and 32 SMI addresses.
	if (switchDevice > 0x02 || (model == Razberi16Port && switchDevice == 0x00) || (model == Razberi4Port && switchDevice != 0x00))
		return -1; // The switch device must be 0x01 or 0x02 for 16ch or 0x00 for 4ch.

	// enable MDIO
	BYTE writeBytes[3] = { 0x02, 0x01, 0 };
	WriteRequest(Switch, writeBytes, 2);

	if (model == Razberi4Port) {
		// address port register
		writeBytes[0] = 0x5F;
		writeBytes[1] = smiAddress;
		WriteRequest(Switch, writeBytes, 2);

		// write mask
		writeBytes[0] = (0x60 + reg);
		writeBytes[1] = buffer[1]; // reverse order
		writeBytes[2] = buffer[0];
		return WriteRequest(Switch, writeBytes, 3);
	} else if (model == Razberi16Port) {
		// address switch
		writeBytes[0] = 0x5F;
		writeBytes[1] = switchDevice;
		WriteRequest(Switch, writeBytes, 2);

		ushort smiCommand = (ushort)(1 << 15 | 1 << 12 | 1 << 10 | smiAddress << 5 | reg);
		writeBytes[0] = 0x61;
		writeBytes[1] = buffer[1];
		writeBytes[2] = buffer[0];
		WriteRequest(Switch, writeBytes, 3); // write value first

		writeBytes[0] = 0x60;
		writeBytes[1] = smiCommand & 0xFF; // lsb
		writeBytes[2] = smiCommand >> 8;   // msb
		return WriteRequest(Switch, writeBytes, 3); // write SMI command
	}
	return -1;
}


/// Basic Data

void GetModelAndSerial() {
	BYTE data[16];
	int i, r;

	printf("Getting model and serial.\n");
	if ((r = ReadRequest(EEPROM, 0x00, 16, data)) > 0) {
		for (i = 0; i < r; ++i) {
			if (data[i] == 0xFF) {
				serialNumber[i] = '\0';
				break;
			}
			serialNumber[i] = data[i]; // already encoded as ASCII, no modification necessary
		}
		serialNumber[i+1] = '\0';
	}

	if ((r = ReadRequest(EEPROM, 0x1C, 4, data)) > 0) {
		snprintf(mcuVersion, 9, "%02d%02d%02d%02d", data[0], data[1], data[2], data[3]);
		//printf("%02d%02d%02d%02d", data[0], data[1], data[2], data[3]);
		mcuVersion[8] = '\0';
	}

	model = Other;
	if (serialNumber[2] == '0' && ((serialNumber[3] == '0' && serialNumber[4] == '4') || serialNumber[3] == '4'))
		model = Razberi4Port;
	else if ((serialNumber[2] == '0' && serialNumber[3] == '1' && serialNumber[4] == '6') || (serialNumber[2] == '1' && serialNumber[3] == '6'))
		model = Razberi16Port;

	printf("Serial: %s, MCU Version: %s\n", serialNumber, mcuVersion);
}

void GetLEDs() {
	BYTE latchValue;
	HidCP2112_GetGpioValues(handle, &latchValue);

	fled = (FaultLED)(latchValue & 0x01);
	sled = (StatusLED)((latchValue >> 1) & 0x01);

	printf("Latch value: %02X Fault: %s Status: %s\n", latchValue, Get_FaultLED_Name(fled), Get_StatusLED_Name(sled));
}

void SetLEDs(FaultLED faultLed, StatusLED statusLed) {
	BYTE latchValue = (statusLed << 1) | faultLed;
	printf("Setting LEDs... Latch value: %02X Fault: %s Status: %s\n", latchValue, Get_FaultLED_Name(faultLed), Get_StatusLED_Name(statusLed));
	if    (statusLed == Green) HidCP2112_SetGpioConfig(handle, 3, OPEN_DRAIN, GPIO_FUNCTION, 0);
	else if (statusLed == Red) HidCP2112_SetGpioConfig(handle, 1, OPEN_DRAIN, GPIO_FUNCTION, 0);
	HidCP2112_SetGpioValues(handle, latchValue, 0x03);
	GetLEDs(); // update known state
}

void ReadEEPROM(BYTE offset, BYTE count, BYTE *buffer) {
	BYTE maxRead = 8;
	BYTE finalOffset = 0;
	while (count > 0) {
		BYTE countToRead = count > maxRead ? maxRead : count;
		BYTE thisRead[countToRead];
		ReadRequest(EEPROM, offset, countToRead, thisRead);
		memcpy(&buffer[finalOffset], thisRead, countToRead); // copy this read to the output buffer
		offset += countToRead;
		count -= countToRead;
		finalOffset += countToRead;
	}
}

void WriteEEPROM(BYTE *buffer, BYTE offset, BYTE count) {
	BYTE maxWrite = 8;
	BYTE finalOffset = 0;
	while (count > 0) {
		BYTE countToWrite = count > maxWrite ? maxWrite : count;
		BYTE thisWrite[countToWrite+1]; // 0th byte is EEPROM offset
		thisWrite[0] = offset; // address on EEPROM to write data to
		memcpy(&thisWrite[1], &buffer[finalOffset], countToWrite); // copy bytes to write to the write buffer
		WriteRequest(EEPROM, thisWrite, countToWrite+1);
		offset += countToWrite;
		count -= countToWrite;
		finalOffset += countToWrite;
	}
}

void PrintEEPROM() {
	BYTE buffer[256];
	ReadEEPROM(0x00, (BYTE)255, buffer);
	for (int i = 0; i < 16; ++i) {
		printf("%X  | ", i);
		for (int j = 0; j < 16; ++j) {
			printf("%02X ", buffer[i*16+j]);
		}
		printf(" |\n");
	}
}


/// Switch Data

BYTE GetSwitchPortNumber(Port port) {
	if (model == Razberi4Port) {
		switch (port) {
			case PORT_1:   return 0x00;
			case PORT_2:   return 0x01;
			case PORT_3:   return 0x02;
			case PORT_4:   return 0x03;
			case UPLINK_1: return 0x05;
			case COM_X:    return 0x04;
		}
	} else if (model == Razberi16Port) {
		switch (port) {
			case PORT_1:
			case PORT_9:  return 0x06;
			case PORT_2:
			case PORT_10: return 0x07;
			case PORT_3:
			case PORT_11: return 0x04;
			case PORT_4:
			case PORT_12: return 0x05;
			case PORT_5:
			case PORT_13: return 0x02;
			case PORT_6:
			case PORT_14: return 0x03;
			case PORT_7:
			case PORT_15: return 0x00;
			case PORT_8:
			case PORT_16: return 0x01;
			case UPLINK_1:
			case UPLINK_2: return 0x08;
			case SWITCH_1:
			case COM_X:    return 0x09;
			case SWITCH_2:
			case DSP:      return 0x0A;
		}
	}
	return 0x00;
}

BYTE GetSwitchPortDevice(Port port) {
	if (model == Razberi4Port)
		return 0x00;

	switch (port) {
		case PORT_1:
		case PORT_2:
		case PORT_3:
		case PORT_4:
		case PORT_5:
		case PORT_6:
		case PORT_7:
		case PORT_8:
		case UPLINK_1:
		case SWITCH_1:
		case DSP: return 0x02;
		case PORT_9:
		case PORT_10:
		case PORT_11:
		case PORT_12:
		case PORT_13:
		case PORT_14:
		case PORT_15:
		case PORT_16:
		case UPLINK_2:
		case SWITCH_2:
		case COM_X: return 0x01;
	}
	return 0x00;
}

void GetSwitchData() {
	BYTE buffer[2];
	// enable MDIO
	BYTE writeBytes[3] = { 0x02, 0x01, 0 };
	WriteRequest(Switch, writeBytes, 2);

	for (int i = 0; i < GetPhysicalPortCount(); ++i) {
		struct port_data *pPort = ports[i];
		HidCP2112_Acquire_Lock();

		ReadPortRegister(pPort->portNum, 0x00, buffer);
		pPort->state = (buffer[0] & 0x08) == 0x08 ? TRUE : FALSE;
		switch (buffer[0] & 0x03) { // 0000 0011
			case 0: pPort->speed = 10; break;
			case 1: pPort->speed = 100; break;
			case 2: pPort->speed = 1000; break;
		}

		// sets values to zero because when PoE is switched off
		// sometimes stale values remain here
		if (!pPort->state) {
			pPort->receiveRate = 0;
			pPort->transmitRate = 0;
			//continue;
		}

		// check if port is ingress or egress source
		pPort->isMirrorInSrc  = IsMonitorSource(pPort->portNum, TRUE);
		pPort->isMirrorOutSrc = IsMonitorSource(pPort->portNum, FALSE);

		GetSwitchPortCounters(pPort->portNum);
		HidCP2112_Release_Lock();
	}
}

void GetSwitchPortCounters(Port port) {
	BYTE buffer[2];
	uint64_t inCounter = 0;
	uint64_t outCounter = 0;
	BYTE swDevice = GetSwitchPortDevice(port);
	struct port_data *pPort = GetPortData(port);

	// capture port counters
	buffer[0] = 0xDC;
	buffer[1] = GetSwitchPortNumber(port);
	WriteSwitchRegister(0x1B, 0x1D, swDevice, buffer);
	ReadSwitchRegister(0x1B, 0x1D, swDevice, buffer);


	// read ingoodoctetslo counter
	buffer[0] = 0xCC;
	buffer[1] = 0x00;
	WriteSwitchRegister(0x1B, 0x1D, swDevice, buffer);
	// read counter bytes 3&2
	ReadSwitchRegister(0x1B, 0x1E, swDevice, buffer);
	inCounter |= ((uint64_t)buffer[0] << 24) | (buffer[1] << 16);
	// read counter bytes 1&0
	ReadSwitchRegister(0x1B, 0x1F, swDevice, buffer);
	inCounter |= (buffer[0] << 8) | (buffer[1] << 0);
	// read ingoodoctetshi counter
	buffer[0] = 0xCC;
	buffer[1] = 0x01;
	WriteSwitchRegister(0x1B, 0x1D, swDevice, buffer);
	// read counter bytes 3&2
	ReadSwitchRegister(0x1B, 0x1E, swDevice, buffer);
	inCounter |= ((uint64_t)buffer[0] << 56) | ((uint64_t)buffer[1] << 48);
	// read counter bytes 1&0
	ReadSwitchRegister(0x1B, 0x1F, swDevice, buffer);
	inCounter |= ((uint64_t)buffer[0] << 40) | ((uint64_t)buffer[1] << 32);

	// read outoctetslo counter
	buffer[0] = 0xCC;
	buffer[1] = 0x0E;
	WriteSwitchRegister(0x1B, 0x1D, swDevice, buffer);
	// read counter bytes 3&2
	ReadSwitchRegister(0x1B, 0x1E, swDevice, buffer);
	outCounter |= ((uint64_t)buffer[0] << 24) | (buffer[1] << 16);
	// read counter bytes 1&0
	ReadSwitchRegister(0x1B, 0x1F, swDevice, buffer);
	outCounter |= (buffer[0] << 8) | (buffer[1] << 0);
	// read outoctetshi counter
	buffer[0] = 0xCC;
	buffer[1] = 0x0F;
	WriteSwitchRegister(0x1B, 0x1D, swDevice, buffer);
	// read counter bytes 3&2
	ReadSwitchRegister(0x1B, 0x1E, swDevice, buffer);
	outCounter |= ((uint64_t)buffer[0] << 56) | ((uint64_t)buffer[1] << 48);
	// read counter bytes 1&0
	ReadSwitchRegister(0x1B, 0x1F, swDevice, buffer);
	outCounter |= ((uint64_t)buffer[0] << 40) | ((uint64_t)buffer[1] << 32);

	uint64_t rxByteDiff = inCounter - pPort->receivedBytes;
	uint64_t txByteDiff = outCounter - pPort->transmittedBytes;
	double timeDiff = difftime(time(NULL), pPort->updateTime);
	if (timeDiff < 1) timeDiff = 1;

	pPort->receivedBytes = inCounter;
	pPort->transmittedBytes = outCounter;
	pPort->receiveRate = (rxByteDiff / 1024) / timeDiff;
	pPort->transmitRate = (txByteDiff / 1024) / timeDiff;
	pPort->updateTime = time(NULL);
}


/// PoE Data

BYTE GetPoEPortDevice(Port port) {
	switch (port) {
		case PORT_1:
		case PORT_2:
		case PORT_3:
		case PORT_4: return model == Razberi4Port ? PoEControl : PoEControl1;
		case PORT_5:
		case PORT_6:
		case PORT_7:
		case PORT_8: return PoEControl2;
		case PORT_9:
		case PORT_10:
		case PORT_11:
		case PORT_12: return PoEControl3;
		case PORT_13:
		case PORT_14:
		case PORT_15:
		case PORT_16: return PoEControl4;
	}
	return PoEControl;
}

BYTE GetPoEPortRegister(Port port) {
	switch (port) {
		case PORT_1:
		case PORT_5:
		case PORT_9:
		case PORT_13: return 0x30;
		case PORT_2:
		case PORT_6:
		case PORT_10:
		case PORT_14: return 0x34;
		case PORT_3:
		case PORT_7:
		case PORT_11:
		case PORT_15: return 0x38;
		case PORT_4:
		case PORT_8:
		case PORT_12:
		case PORT_16: return 0x3C;
	}
	return 0x00;
}

double GetPoEPortPowerDraw(int portNum) {
	const double currentUnit = 122.07; // 61.035uA for 0.5ohm or 122.07uA for 0.25ohm, Razberi PCB uses 0.25ohm
	const double voltageUnit = 5.835;  // 5.835mV
	BYTE device = GetPoEPortDevice(portNum);
	BYTE reg = GetPoEPortRegister(portNum);

	BYTE buffer[1];

	ReadRequest(device, reg, 1, buffer);
	BYTE lsb = buffer[0];
	ReadRequest(device, reg+1, 1, buffer);
	BYTE msb = buffer[0];
	ushort current = (msb << 8) | lsb;

	ReadRequest(device, reg+2, 1, buffer);
	lsb = buffer[0];
	ReadRequest(device, reg+3, 1, buffer);
	msb = buffer[0];
	ushort voltage = (msb << 8) | lsb;

	double poePower = ((voltage * voltageUnit) / 1000) * ((current * currentUnit) / 1000 / 1000);
	//printf("Port: %d PoePower: %f\n", portNum, poePower);
	return poePower;
}

void GetPoEData() {
	BYTE buffer[1];
	if (model == Razberi4Port) {
		ReadRequest(PoEControl, 0x12, 1, buffer);
		ports[0]->poeState = (buffer[0] & 0x03) == 0x03 ? TRUE : FALSE;
		ports[1]->poeState = (buffer[0] & 0x0C) == 0x0C ? TRUE : FALSE;
		ports[2]->poeState = (buffer[0] & 0x30) == 0x30 ? TRUE : FALSE;
		ports[3]->poeState = (buffer[0] & 0xC0) == 0xC0 ? TRUE : FALSE;
		for (int i = 0; i < 4; ++i)
			ports[i]->powerDraw = (ports[i]->state && ports[i]->poeState) ? GetPoEPortPowerDraw(ports[i]->portNum) : 0.0;
	} else {
		ReadRequest(PoEControl1, 0x12, 1, buffer);
		ports[0]->poeState = (buffer[0] & 0x03) == 0x03 ? TRUE : FALSE;
		ports[1]->poeState = (buffer[0] & 0x0C) == 0x0C ? TRUE : FALSE;
		ports[2]->poeState = (buffer[0] & 0x30) == 0x30 ? TRUE : FALSE;
		ports[3]->poeState = (buffer[0] & 0xC0) == 0xC0 ? TRUE : FALSE;
		ReadRequest(PoEControl2, 0x12, 1, buffer);
		ports[4]->poeState = (buffer[0] & 0x03) == 0x03 ? TRUE : FALSE;
		ports[5]->poeState = (buffer[0] & 0x0C) == 0x0C ? TRUE : FALSE;
		ports[6]->poeState = (buffer[0] & 0x30) == 0x30 ? TRUE : FALSE;
		ports[7]->poeState = (buffer[0] & 0xC0) == 0xC0 ? TRUE : FALSE;
		ReadRequest(PoEControl3, 0x12, 1, buffer);
		ports[8]->poeState  = (buffer[0] & 0x03) == 0x03 ? TRUE : FALSE;
		ports[9]->poeState  = (buffer[0] & 0x0C) == 0x0C ? TRUE : FALSE;
		ports[10]->poeState = (buffer[0] & 0x30) == 0x30 ? TRUE : FALSE;
		ports[11]->poeState = (buffer[0] & 0xC0) == 0xC0 ? TRUE : FALSE;
		ReadRequest(PoEControl4, 0x12, 1, buffer);
		ports[12]->poeState = (buffer[0] & 0x03) == 0x03 ? TRUE : FALSE;
		ports[13]->poeState = (buffer[0] & 0x0C) == 0x0C ? TRUE : FALSE;
		ports[14]->poeState = (buffer[0] & 0x30) == 0x30 ? TRUE : FALSE;
		ports[15]->poeState = (buffer[0] & 0xC0) == 0xC0 ? TRUE : FALSE;
		for (int i = 0; i < 16; ++i)
			ports[i]->powerDraw = (ports[i]->state && ports[i]->poeState) ? GetPoEPortPowerDraw(i) : 0.0;
	}
}

void CheckPoEFault() {
	double totalPoE = 0.0;
	double maxPoE = model == Razberi4Port ? MAX_4CH_POE : MAX_16CH_POE;

	// sum all power usage across ports
	for (int i = 0; i < GetNonUplinkPortCount(); ++i)
		totalPoE += ports[i]->powerDraw;

	double fractionUsed = totalPoE / maxPoE;
	printf("TotalPoE: %7.3f MaxPoE: %7.3f Fraction: %5.2f%%\n", totalPoE, maxPoE, fractionUsed * 100);
	if (fractionUsed > POE_FAULT_LEVEL && fled == Off)
		SetLEDs(On, sled);
	else if (fractionUsed <= POE_FAULT_LEVEL && fled == On)
		SetLEDs(Off, sled);
}

/**
 * Enables PoE on all ports.
 */
void EnablePoE() {
	if (model == Razberi4Port)
		EnablePoEDevice(PoEControl);
	else if (model == Razberi16Port) {
		EnablePoEDevice(PoEControl1);
		EnablePoEDevice(PoEControl2);
		EnablePoEDevice(PoEControl3);
		EnablePoEDevice(PoEControl4);
	}
}

/**
 * Enables PoE on the specified port.
 */
void EnablePoEPort(Port port) {
	// only 1-16 are PoE ports
	if (port < 1 || port > 16)
		return;

	int channel = (int)port;
	printf("Channel: %d\n", channel);
	if (model == Razberi4Port)
		EnablePoEChannel(PoEControl, 5-channel);
	else if (model == Razberi16Port) {
		if      (channel <= 4)  EnablePoEChannel(PoEControl1, 5-(channel-0));
		else if (channel <= 8)  EnablePoEChannel(PoEControl2, 5-(channel-4));
		else if (channel <= 12) EnablePoEChannel(PoEControl3, 5-(channel-8));
		else                    EnablePoEChannel(PoEControl4, 5-(channel-12));
	}
}

/**
 * Enables PoE on all ports for the specified PoE controller.
 */
void EnablePoEDevice(BYTE devAddress) {
	HidCP2112_Acquire_Lock();
	BYTE write[2];
	write[0] = 0x12;
	write[1] = 0xFF;
	WriteRequest(devAddress, write, 2);
	write[0] = 0x13;
	write[1] = 0xF0;
	WriteRequest(devAddress, write, 2);
	write[0] = 0x14;
	write[1] = 0xFF;
	WriteRequest(devAddress, write, 2);
	HidCP2112_Release_Lock();
}

/**
 * Enables PoE on the specified PoE controller and channel.
 */
void EnablePoEChannel(BYTE devAddress, int channel) {
	HidCP2112_Acquire_Lock();
	BYTE read[1];
	ReadRequest(devAddress, 0x12, 1, read);
	int shift = 4-channel;
	BYTE write[2];
	write[0] = 0x12;
	write[1] = (read[0] | (0x03 << (shift * 2)));
	WriteRequest(devAddress, write, 2);
	write[0] = 0x13;
	write[1] = (read[0] | (0x01 << (4 + shift)));
	WriteRequest(devAddress, write, 2);
	write[0] = 0x14;
	write[1] = (read[0] | (0x11 << shift));
	WriteRequest(devAddress, write, 2);
	HidCP2112_Release_Lock();
}

/**
 * Disables PoE on all ports.
 */
void DisablePoE() {
	if (model == Razberi4Port)
		DisablePoEDevice(PoEControl);
	else if (model == Razberi16Port) {
		DisablePoEDevice(PoEControl1);
		DisablePoEDevice(PoEControl2);
		DisablePoEDevice(PoEControl3);
		DisablePoEDevice(PoEControl4);
	}
}

/**
 * Disables PoE on the specified port.
 */
void DisablePoEPort(Port port) {
	// only 1-16 are PoE ports
	if (port < 1 || port > 16)
		return;

	int channel = (int)port;
	if (model == Razberi4Port)
		DisablePoEChannel(PoEControl, 5-channel);
	else if (model == Razberi16Port) {
		if      (channel <= 4)  DisablePoEChannel(PoEControl1, 5-(channel-0));
		else if (channel <= 8)  DisablePoEChannel(PoEControl2, 5-(channel-4));
		else if (channel <= 12) DisablePoEChannel(PoEControl3, 5-(channel-8));
		else                    DisablePoEChannel(PoEControl4, 5-(channel-12));
	}
}

/**
 * Disables PoE on all ports for the specified PoE controller.
 */
void DisablePoEDevice(BYTE devAddress) {
	HidCP2112_Acquire_Lock();
	BYTE write[2];
	write[0] = 0x12;
	write[1] = 0x00;
	WriteRequest(devAddress, write, 2);
	HidCP2112_Release_Lock();
}

/**
 * Disables PoE on the specified PoE controller and channel.
 */
void DisablePoEChannel(BYTE devAddress, int channel) {
	HidCP2112_Acquire_Lock();
	BYTE read[1];
	ReadRequest(devAddress, 0x12, 1, read);
	int shift = 4-channel;
	BYTE write[2];
	write[0] = 0x12;
	write[1] = read[0] & ((0x03 << (shift * 2)) ^ 0xFF);
	WriteRequest(devAddress, write, 2);
	HidCP2112_Release_Lock();
}


/// Mirroring Configuration

void ClearMonitorConfiguration() {
	printf("Clearing monitor configuration...\n");

	HidCP2112_Acquire_Lock();
	BYTE bytes[2];
	if (model == Razberi4Port) {
		ReadSwitchRegister(0x1B, 0x1A, 0x00, bytes);
		bytes[0] = 0xFF;
		WriteSwitchRegister(0x1B, 0x1A, 0x00, bytes);
	} else if (model == Razberi16Port) {
		// switch 1
		ReadSwitchRegister(0x1B, 0x1A, 0x01, bytes);
		bytes[0] = 0xFF;
		WriteSwitchRegister(0x1B, 0x1A, 0x01, bytes);
		// switch 2
		ReadSwitchRegister(0x1B, 0x1A, 0x02, bytes);
		bytes[0] = 0xFF;
		WriteSwitchRegister(0x1B, 0x1A, 0x02, bytes);
	}

	for (int i = 0; i < GetTotalPortCount(); ++i) {
		Port p = ports[i]->portNum;
		ReadPortRegister(p, 0x08, bytes);
		bytes[1] &= 0xCF; // 1100-1111 - clears bits 4 and 5
		WritePortRegister(p, 0x08, bytes);
	}

	HidCP2112_Release_Lock();
	printf("Cleared monitor configuration.\n");
}

void SetMonitorConfiguration(Port dest, Port *sources, int srcLen, bool isIngress) {
	if (dest == 0 || srcLen == 0)
		return; // source ports cannot be empty and dest cannot be unknown
	for (int i = 0; i < srcLen; ++i) {
		if (sources[i] == dest) {
			printf("Source ports cannot contain the monitor destination.");
			return;
		}
	}

	printf(BOLDBLUE "Setting %s mirroring configuration:" RESET " Dest: %s Sources: ", isIngress ? "ingress" : "egress", GetPortData(dest)->portName);
	for (int i = 0; i < srcLen; i++)
		printf("%s ", GetPortData(sources[i])->portName);
	printf("\n");

	HidCP2112_Acquire_Lock();
	BYTE destPortNum = GetSwitchPortNumber(dest);
	BYTE swNum = GetSwitchPortDevice(dest);

	// set destination port
	BYTE bytes[2];
	ReadSwitchRegister(0x1B, 0x1A, swNum, bytes);
	printf("Current monitor dest: %2X-%2X\n", bytes[0], bytes[1]);
	if (isIngress) bytes[0] = (destPortNum << 4) | (bytes[0] & 0x0F); // set [7:4] to dest port number
	else           bytes[0] = (bytes[0] & 0xF0) | destPortNum;        // set [3:0] to dest port number
	WriteSwitchRegister(0x1B, 0x1A, swNum, bytes); // 0x1B is Globals 1, 0x1A is Monitor Control
	ReadSwitchRegister(0x1B, 0x1A, swNum, bytes);
	printf("New monitor dest: %2X-%2X\n", bytes[0], bytes[1]);

	// if dest is on SW1 we want the port that goes to SW1 to be marked as the ingress monitor destination (16 ch only)
	if (swNum != 0x00) {
		Port secSwDest = swNum == 0x01 ? SWITCH_1 : SWITCH_2;
		BYTE swNum2 = GetSwitchPortDevice(secSwDest);
		BYTE portNum2 = GetSwitchPortNumber(secSwDest);
		ReadSwitchRegister(0x1B, 0x1A, swNum2, bytes);
		if (isIngress) bytes[0] = (portNum2 << 4) | (bytes[0] & 0x0F); // set [7:4] to dest port number
		else           bytes[0] = (bytes[0] & 0xF0) | portNum2;        // set [3:0] to dest port number
		WriteSwitchRegister(0x1B, 0x1A, swNum2, bytes);

		// make sure Switch1 and Switch2 ports are DSA tag ports so these cross-chip packets can be marked as To_Sniffer
		ReadPortRegister(SWITCH_1, 0x04, bytes);
		bytes[0] |= 1; // set bit 8 (on msb)
		WritePortRegister(SWITCH_1, 0x04, bytes);
		ReadPortRegister(SWITCH_2, 0x04, bytes);
		bytes[0] |= 1; // set bit 8 (on msb)
		WritePortRegister(SWITCH_2, 0x04, bytes);
	}

	// set ports as monitor sources
	for (int i = 0; i < srcLen; ++i) {
		Port p = sources[i];
		ReadPortRegister(p, 0x08, bytes); // 0x08 is the Port Control 2 register
		int bitNum = isIngress ? 4 : 5;
		bytes[1] |= 1 << bitNum; // set bit 4 or 5
		WritePortRegister(p, 0x08, bytes);
	}
	HidCP2112_Release_Lock();
}

Port GetMonitorDestination(bool isIngress) {
	BYTE bytes[2];
	if (model == Razberi4Port) {
		ReadSwitchRegister(0x1B, 0x1A, 0x00, bytes);
		BYTE swPortNum = isIngress ? (bytes[0] >> 4) : (bytes[0] & 0x0F);
		for (int i = 0; i < GetTotalPortCount(); ++i) {
			struct port_data *pPort = ports[i];
			if (GetSwitchPortNumber(pPort->portNum) == swPortNum)
				return pPort->portNum;
		}
	} else if (model == Razberi16Port) {
		// TODO
	}

	return 0;
}

bool IsMonitorSource(Port port, bool isIngress) {
	BYTE bytes[2];
	ReadPortRegister(port, 0x08, bytes); // 0x08 is the Port Control 2 register
	int bitNum = isIngress ? 4 : 5;
	BYTE mask = 1 << bitNum;
	return bytes[1] & mask; // != 0 means its a source
}


/// VLAN

void SetVlanMask(Port port, BYTE *mask) {
	BYTE bytes[3];
	if (model == Razberi4Port) {
		// address port register
		bytes[0] = 0x5F;
		bytes[1] = GetSwitchPortNumber(port) + 0x10;
		WriteRequest(Switch, bytes, 2);

		// write mask
		bytes[0] = 0x66;
		bytes[1] = mask[1];
		bytes[2] = mask[0];
		WriteRequest(Switch, bytes, 3);
	} else {
		// address switch
		bytes[0] = 0x5F;
		bytes[1] = GetSwitchPortDevice(port);
		WriteRequest(Switch, bytes, 2);

		BYTE bytPort = GetSwitchPortNumber(port) + 0x10;
		ushort smiCommand = (ushort)(1 << 15 | 1 << 12 | 1 << 10 | bytPort << 5 | 0x06); // 0x06 is the VLAN register
		bytes[0] = 0x61;
		bytes[1] = mask[1];
		bytes[2] = mask[0];
		WriteRequest(Switch, bytes, 3); // write mask first

		bytes[0] = 0x60;
		bytes[1] = smiCommand & 0xFF; // lsb
		bytes[2] = smiCommand >> 8; // msb
		WriteRequest(Switch, bytes, 3); // write SMI command
	}
}

void SetVlanScenario0() {
	HidCP2112_Acquire_Lock();
	BYTE mask[2];
	if (model == Razberi4Port) {
		mask[0]=0x00; mask[1]=0x3E; SetVlanMask(PORT_1, mask);
		mask[0]=0x00; mask[1]=0x3D; SetVlanMask(PORT_2, mask);
		mask[0]=0x00; mask[1]=0x3B; SetVlanMask(PORT_3, mask);
		mask[0]=0x00; mask[1]=0x37; SetVlanMask(PORT_4, mask);
		mask[0]=0x00; mask[1]=0x2F; SetVlanMask(COM_X, mask);
		mask[0]=0x00; mask[1]=0x1F; SetVlanMask(UPLINK_1, mask);

		BYTE eepromData[] = { 0x3E, 0x3D, 0x3B, 0x37, 0x2F, 0x1F };
		WriteEEPROM(eepromData, VLAN_EEPROM_OFFSET, 6);
	} else {
		mask[0]=0x07; mask[1]=0xBF; SetVlanMask(PORT_1, mask);
		mask[0]=0x07; mask[1]=0x7F; SetVlanMask(PORT_2, mask);
		mask[0]=0x07; mask[1]=0xEF; SetVlanMask(PORT_3, mask);
		mask[0]=0x07; mask[1]=0xDF; SetVlanMask(PORT_4, mask);
		mask[0]=0x07; mask[1]=0xFB; SetVlanMask(PORT_5, mask);
		mask[0]=0x07; mask[1]=0xF7; SetVlanMask(PORT_6, mask);
		mask[0]=0x07; mask[1]=0xFE; SetVlanMask(PORT_7, mask);
		mask[0]=0x07; mask[1]=0xFD; SetVlanMask(PORT_8, mask);
		mask[0]=0x07; mask[1]=0xBF; SetVlanMask(PORT_9, mask);
		mask[0]=0x07; mask[1]=0x7F; SetVlanMask(PORT_10, mask);
		mask[0]=0x07; mask[1]=0xEF; SetVlanMask(PORT_11, mask);
		mask[0]=0x07; mask[1]=0xDF; SetVlanMask(PORT_12, mask);
		mask[0]=0x07; mask[1]=0xFB; SetVlanMask(PORT_13, mask);
		mask[0]=0x07; mask[1]=0xF7; SetVlanMask(PORT_14, mask);
		mask[0]=0x07; mask[1]=0xFE; SetVlanMask(PORT_15, mask);
		mask[0]=0x07; mask[1]=0xFD; SetVlanMask(PORT_16, mask);
		mask[0]=0x06; mask[1]=0xFF; SetVlanMask(UPLINK_1, mask);
		mask[0]=0x06; mask[1]=0xFF; SetVlanMask(UPLINK_2, mask);
		mask[0]=0x05; mask[1]=0xFF; SetVlanMask(SWITCH_1, mask);
		mask[0]=0x03; mask[1]=0xFF; SetVlanMask(SWITCH_2, mask);
		mask[0]=0x05; mask[1]=0xFF; SetVlanMask(COM_X, mask);
		mask[0]=0x03; mask[1]=0xFF; SetVlanMask(DSP, mask);

		BYTE eepromData[88]; // 22 ports, 4 bytes / port
		for (int i = 0; i < 11; ++i) {
			ushort smi = 1 << 15 | 1 << 12 | 1 << 10 | (i + 0x10) << 5 | 0x06; // 0x06 is VLAN register
			ushort mask = 0x7FF ^ (1 << i); // every bit is 1 except for the one for that port
			eepromData[i*4+0] = eepromData[i*4+44] = (smi >> 8) & 0xFF;
			eepromData[i*4+1] = eepromData[i*4+45] = smi & 0xFF;
			eepromData[i*4+2] = eepromData[i*4+46] = (mask >> 8) & 0xFF;
			eepromData[i*4+3] = eepromData[i*4+47] = mask & 0xFF;
		}

		WriteEEPROM(eepromData, VLAN_EEPROM_OFFSET, 88);
	}
	HidCP2112_Release_Lock();
}

void SetVlanScenario1() {
	HidCP2112_Acquire_Lock();
	BYTE mask[2];
	if (model == Razberi4Port) {
		mask[0]=0x00; mask[1]=0x1E; SetVlanMask(PORT_1, mask);
		mask[0]=0x00; mask[1]=0x1D; SetVlanMask(PORT_2, mask);
		mask[0]=0x00; mask[1]=0x1B; SetVlanMask(PORT_3, mask);
		mask[0]=0x00; mask[1]=0x17; SetVlanMask(PORT_4, mask);
		mask[0]=0x00; mask[1]=0x2F; SetVlanMask(COM_X, mask);
		mask[0]=0x00; mask[1]=0x10; SetVlanMask(UPLINK_1, mask);

		BYTE eepromData[] = { 0x1E, 0x1D, 0x1B, 0x17, 0x2F, 0x10 };
		WriteEEPROM(eepromData, VLAN_EEPROM_OFFSET, 6);
	} else {
		mask[0]=0x07; mask[1]=0xBF; SetVlanMask(PORT_1, mask);
		mask[0]=0x07; mask[1]=0x7F; SetVlanMask(PORT_2, mask);
		mask[0]=0x07; mask[1]=0xEF; SetVlanMask(PORT_3, mask);
		mask[0]=0x07; mask[1]=0xDF; SetVlanMask(PORT_4, mask);
		mask[0]=0x07; mask[1]=0xFB; SetVlanMask(PORT_5, mask);
		mask[0]=0x07; mask[1]=0xF7; SetVlanMask(PORT_6, mask);
		mask[0]=0x07; mask[1]=0xFE; SetVlanMask(PORT_7, mask);
		mask[0]=0x07; mask[1]=0xFD; SetVlanMask(PORT_8, mask);
		mask[0]=0x07; mask[1]=0xBF; SetVlanMask(PORT_9, mask);
		mask[0]=0x07; mask[1]=0x7F; SetVlanMask(PORT_10, mask);
		mask[0]=0x07; mask[1]=0xEF; SetVlanMask(PORT_11, mask);
		mask[0]=0x07; mask[1]=0xDF; SetVlanMask(PORT_12, mask);
		mask[0]=0x07; mask[1]=0xFB; SetVlanMask(PORT_13, mask);
		mask[0]=0x07; mask[1]=0xF7; SetVlanMask(PORT_14, mask);
		mask[0]=0x07; mask[1]=0xFE; SetVlanMask(PORT_15, mask);
		mask[0]=0x07; mask[1]=0xFD; SetVlanMask(PORT_16, mask);
		mask[0]=0x06; mask[1]=0xFF; SetVlanMask(UPLINK_1, mask);
		mask[0]=0x02; mask[1]=0x00; SetVlanMask(UPLINK_2, mask); // uplink 2 can only communicate with COM X
		mask[0]=0x05; mask[1]=0xFF; SetVlanMask(SWITCH_1, mask);
		mask[0]=0x03; mask[1]=0xFF; SetVlanMask(SWITCH_2, mask);
		mask[0]=0x05; mask[1]=0xFF; SetVlanMask(COM_X, mask);
		mask[0]=0x03; mask[1]=0xFF; SetVlanMask(DSP, mask);

		BYTE eepromData[88]; // 22 ports, 4 bytes / port
		for (int i = 0; i < 11; ++i) {
			ushort smi = 1 << 15 | 1 << 12 | 1 << 10 | (i + 0x10) << 5 | 0x06; // 0x06 is VLAN register
			ushort mask = 0x7FF ^ (1 << i); // every bit is 1 except for the one for that port
			eepromData[i*4+0] = eepromData[i*4+44] = (smi >> 8) & 0xFF; // repeat the data for sw2
			eepromData[i*4+1] = eepromData[i*4+45] = smi & 0xFF;
			eepromData[i*4+2] = eepromData[i*4+46] = (mask >> 8) & 0xFF;
			eepromData[i*4+3] = eepromData[i*4+47] = mask & 0xFF;
		}

		// vlan mask for Uplink 2 can only talk to COM X
		eepromData[34] = 0x02;
		eepromData[35] = 0x00;

		WriteEEPROM(eepromData, VLAN_EEPROM_OFFSET, 88);
	}
	HidCP2112_Release_Lock();
}

int GetVlanScenario() {
	BYTE eepromData[] = { 0x01 }; // initialize to unused value

	if (model == Razberi4Port) {
		ReadEEPROM(VLAN_EEPROM_OFFSET, 1, eepromData);
		// vlan scenario 0 has a 0x3E in this position,
		// scenario 1 has a 0x1E in this position
		if (eepromData[0] == 0x3E)
			return 0;
		if (eepromData[0] == 0x1E)
			return 1;
	} else {
		ReadEEPROM(VLAN_EEPROM_OFFSET + 35, 1, eepromData);
		// vlan scenario 0 has a 0xFF in this position, also an uninitialized
		// eeprom will also have a 0xFF, which is good because the default
		// should be vlan 0 when none has be chosen
		if (eepromData[0] == 0xFF)
			return 0;
		// vlan scenario 1 has a 0x00 in this position
		if (eepromData[0] == 0x00)
			return 1;
	}

	return 0;
}

/// Socket functions

void AppendSendBuffer(struct socket_state *pState, BYTE *buf, int bufLen) {
	int i;
	if (pState->closed) {
		fprintf(stderr, "Socket client connection already closed.\n");
		return;
	}
	if (bufLen + 1 + (int)pState->send_buf_length > SEND_BUFFER) {
		fprintf(stderr, "Not enough space in send buffer for socket. (fd=%d, buffer level=%d, size to add=%d)\n", pState->fd, pState->send_buf_length, bufLen);
		return;
	}

	pthread_mutex_lock(&socket_lock);

	printf("Adding message to send buffer: %s\n", buf);
	memcpy(&pState->send_buf[pState->send_buf_length], buf, bufLen);
	pState->send_buf_length += bufLen;
	pState->send_buf[pState->send_buf_length] = 0;
	pState->send_buf_length += 1;

	printf("Added %d bytes of data to send buffer for idx=%d, fd=%d, pState=%p, sendBufLen=%d, recvBufLen=%d\n",
		bufLen, pState->list_idx, pState->fd, pState, pState->send_buf_length, pState->recv_buf_length);
	//for (i = 0; i < bufLen; ++i)
	//	printf("buf[%d] = %c (%d)\n", i, buf[i], buf[i]);

	pthread_mutex_unlock(&socket_lock);
}

void AppendRecvBuffer(struct socket_state *pState, BYTE *buf, int bufLen) {
	int i;
	if (bufLen + (int)pState->recv_buf_length > RECV_BUFFER) {
		fprintf(stderr, "Not enough space in receive buffer for socket. (fd=%d, buffer level=%d, size to add=%d)\n", pState->fd, pState->recv_buf_length, bufLen);
		return;
	}

	pthread_mutex_lock(&socket_lock);

	memcpy(&pState->recv_buf[pState->recv_buf_length], buf, bufLen);
	pState->recv_buf_length += bufLen;

	printf("Added %d bytes of data to recv buffer for idx=%d, fd=%d, pState=%p, sendBufLen=%d, recvBufLen=%d\n",
		bufLen, pState->list_idx, pState->fd, pState, pState->send_buf_length, pState->recv_buf_length);
	//for (i = 0; i < bufLen; ++i)
	//	printf("buf[%d] = %c (%d)\n", i, buf[i], buf[i]);

	pthread_mutex_unlock(&socket_lock);
}

void FlushSendBuffer(struct socket_state *pState) {
	printf("Flushing send buffer for fd=%d, sendBufLen=%d, recvBufLen=%d\n", pState->fd, pState->send_buf_length, pState->recv_buf_length);
	if (!pState->closed && pState->send_buf_length > 0) {
		int s = write(pState->fd, pState->send_buf, pState->send_buf_length);
		if (s == -1) {
			fprintf(stderr, "Error while flushing send buffer: fd=%d\n", pState->fd);
			perror("flush_send_buffer write");
			CloseSocket(pState->fd);
		} else {
			pState->send_buf_length = 0; // clear buffer
			printf("Sent %d bytes to fd=%d, sendBufLen=%d, recvBufLen=%d\n", s, pState->fd, pState->send_buf_length, pState->recv_buf_length);
		}
	}
}

void FlushSendBuffers() {
	struct socket_state *pState;

	pthread_mutex_lock(&socket_lock);

	for (int i = 0; i < active_sockets_len; i++) {
		pState = active_sockets[i];
		FlushSendBuffer(pState);
	}

	pthread_mutex_unlock(&socket_lock);
}

void CloseSocket(int fd) {
	int i, idx = -1;
	pthread_mutex_lock(&socket_lock);

	for (i = 0; i < active_sockets_len; i++) {
		if (active_sockets[i]->fd == fd) {
			idx = i;
			active_sockets[i]->send_buf_length = 0;
			active_sockets[i]->recv_buf_length = 0;
			active_sockets[i]->closed = 1;
			break;
		}
	}

	close(fd);
	if (idx >= 0) {
		printf("Freeing struct memory: (%d) %p %ld %ld\n", idx, active_sockets[idx], sizeof(active_sockets[idx]), sizeof(*active_sockets[idx]));
		free(active_sockets[idx]);
	}

	for (i = idx; i < active_sockets_len - 1; i++) {
		active_sockets[i] = active_sockets[i+1];
		active_sockets[i]->list_idx = i;
	}
	active_sockets_len--;
	active_sockets[active_sockets_len] = NULL;

	printf("Closed socket (fd=%d). Total connections: %d\n", fd, active_sockets_len);

	pthread_mutex_unlock(&socket_lock);
}


int make_socket_non_blocking (int sfd) {
	int flags, s;

	flags = fcntl (sfd, F_GETFL, 0);
	if (flags == -1) {
		perror ("fcntl");
		return -1;
	}

	flags |= O_NONBLOCK;
	s = fcntl (sfd, F_SETFL, flags);
	if (s == -1) {
		perror ("fcntl");
		return -1;
	}

	return 0;
}

int create_and_bind (int port) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;
	char portStr[6];

	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
	//hints.ai_family = AF_INET;     /* Return IPv4 */
	hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
	hints.ai_flags = AI_PASSIVE;     /* All interfaces */

	sprintf(portStr, "%d", port);
	s = getaddrinfo (NULL, portStr, &hints, &result);
	if (s != 0) {
		fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1)
			continue;

		s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0)
			/* We managed to bind successfully! */
			break;

		close (sfd);
	}

	if (rp == NULL) {
		fprintf (stderr, "Could not bind\n");
		return -1;
	}

	freeaddrinfo (result);

	return sfd;
}

int RunSocketLoop() {
	int sfd, s;
	int efd;
	struct epoll_event event;
	struct epoll_event *events;
	struct socket_state *state;


	sfd = create_and_bind (LISTEN_PORT);
	if (sfd == -1) {
		printf("Could not create and bind socket.\n");
		abort();
	}

	s = make_socket_non_blocking (sfd);
	if (s == -1) {
		fprintf(stderr, "Could not make socket non-blocking.\n");
		abort();
	}

	s = listen (sfd, SOMAXCONN);
	if (s == -1) {
		fprintf(stderr, "Could not listen on socket.\n");
		perror("listen");
		abort();
	}

	efd = epoll_create1 (0);
	if (efd == -1) {
		fprintf(stderr, "Could not epoll_create.\n");
		perror("epoll_create");
		abort();
	}

	struct socket_state sockState;
	sockState.fd = sfd;
	event.data.ptr = &sockState;
	//event.data.fd = sfd;
	event.events = EPOLLIN | EPOLLET;
	s = epoll_ctl (efd, EPOLL_CTL_ADD, sfd, &event);
	if (s == -1) {
		fprintf(stderr, "Could not epoll_ctl.\n");
		perror("epoll_ctl");
		abort();
	}

	/* Buffer where events are returned */
	events = calloc (MAXEVENTS, sizeof event);

	printf(BOLDGREEN "Entering socket event loop." RESET "\n");

	/* The event loop */
	while (1) {
		int n, i;

		n = epoll_wait (efd, events, MAXEVENTS, -1);
		// EINTR happens when the timer receives a signal and as a result
		// will interrupt the blocking epoll_wait, so we should just
		// ignore it because the call didn't fail due to an actual error
		if (n == -1) {
			if (errno != EINTR)
				perror("epoll_wait");
			continue;
		}

		printf("New socket events: %d\n", n);

		for (i = 0; i < n; i++) {
			state = (struct socket_state*)events[i].data.ptr;
			printf("Event flags: fd=%d, flags=%X\n", state->fd, events[i].events);
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN) && !(events[i].events & EPOLLOUT))) {
				/* An error has occured on this fd, or the socket is not
				   ready for reading (why were we notified then?) */
				fprintf (stderr, "epoll error: %d\n", events[i].events);
				//close (state->fd);
				CloseSocket(state->fd);
				continue;
			}

			if (sfd == state->fd) {
				/* We have a notification on the listening socket, which
				   means one or more incoming connections. */
				while (1) {
					struct sockaddr in_addr;
					socklen_t in_len;
					int infd;
					char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

					in_len = sizeof in_addr;
					infd = accept (sfd, &in_addr, &in_len);
					if (infd == -1) {
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
							/* We have processed all incoming connections. */
							break;
						} else {
							perror ("accept");
							break;
						}
					}

					s = getnameinfo (&in_addr, in_len,
					               hbuf, sizeof hbuf,
					               sbuf, sizeof sbuf,
					               NI_NUMERICHOST | NI_NUMERICSERV);

					if (s == 0) {
						printf(BOLDGREEN "Accepted connection on descriptor %d (host=%s, port=%s)" RESET "\n", infd, hbuf, sbuf);
					}

					/* Make the incoming socket non-blocking and add it to the list of fds to monitor. */
					s = make_socket_non_blocking (infd);
					if (s == -1) {
						fprintf(stderr, BOLDRED "Could not make the socket non-blocking: fd=%d" RESET "\n", infd);
						abort();
					}

					if (active_sockets_len == MAX_SOCKETS) {
						fprintf(stderr, BOLDRED "Cannot accept any more connections, max sockets reached." RESET);
						close(infd);
						continue;
					}

					struct socket_state *newState;
					newState = (struct socket_state *)calloc(1, sizeof(*newState));
					newState->fd = infd;
					//memcpy(newState->send_buf, buffer, buflen);
					//newState->send_buf_length = buflen;
					event.data.ptr = newState;
					event.events = EPOLLIN | EPOLLET | EPOLLOUT;
					s = epoll_ctl(efd, EPOLL_CTL_ADD, infd, &event);
					if (s == -1) {
						perror ("epoll_ctl");
						abort();
					}

					pthread_mutex_lock(&socket_lock);
					newState->list_idx = active_sockets_len;
					active_sockets[active_sockets_len] = newState;
					active_sockets_len++;
					printf(BOLDGREEN "Total connections: %d" RESET "\n", active_sockets_len);
					pthread_mutex_unlock(&socket_lock);

					//SendUpdate(newState);
				}
				continue;
			}

			if (events[i].events & EPOLLIN) {
				/* We have data on the fd waiting to be read. Read and
				   display it. We must read whatever data is available
				   completely, as we are running in edge-triggered mode
				   and won't get a notification again for the same
				   data. */
				int done = 0;

				while (1) {
					ssize_t count;
					char buf[512];

					count = read (state->fd, buf, sizeof buf);
					if (count == -1) {
						/* If errno == EAGAIN, that means we have read all
						   data. So go back to the main loop. */
						if (errno != EAGAIN) {
							perror ("read");
							done = 1;
						}
						break;
					} else if (count == 0) {
						/* End of file. The remote has closed the connection. */
						done = 1;
						break;
					}

					AppendRecvBuffer(state, buf, count);

					/* Write the buffer to standard output */
					//s = write (1, buf, count);
					//if (s == -1) {
					//	perror ("write");
					//	abort ();
					//}
				}

				if (done) {
					printf (BOLDGREEN "Closing connection on descriptor %d" RESET "\n", state->fd);

					/* Closing the descriptor will make epoll remove it
					 from the set of descriptors which are monitored. */
					//close (state->fd);
					CloseSocket(state->fd);
					continue;
				}
			}

			//if (events[i].events & EPOLLOUT) {
			//	printf("Socket ready for sending on fd=%d\n", state->fd);
			//	FlushSendBuffer(state);
			//}
		}
	}

	free (events);
	close (sfd);

	return EXIT_SUCCESS;
}




void timer_handler(int signum) {
	int i, s;
	struct socket_state *pState;

	return;
	if (active_sockets_len == 0)
		return;

	pthread_mutex_lock(&socket_lock);

	printf("Timer fired. Active sockets: %d\n", active_sockets_len);

	//printf("Active socket addrs: ");
	//for (i = 0; i < active_sockets_len; i++) {
	//	printf("(%d) %p %p :: ", i, active_sockets[i], &active_sockets[i]);
	//}
	printf("\n");
	for (i = 0; i < active_sockets_len; i++) {
		pState = active_sockets[i];
		if (buflen + pState->send_buf_length > SEND_BUFFER) {
			fprintf(stderr, "Not enough space in send buffer for socket. (fd=%d, buffer level=%d, size to add=%lu)\n", pState->fd, pState->send_buf_length, buflen);
			continue;
		}
		//printf("Adding data to buffer for i=%d, idx=%d, pState=%p, as=%p, fd=%d, bufAddr=%p, bufLen=%d\n",
		//	i, pState->list_idx, pState, active_sockets[i], pState->fd, &pState->send_buf[pState->send_buf_length], pState->send_buf_length);
		memcpy(&pState->send_buf[pState->send_buf_length], buffer, buflen);
		pState->send_buf_length += buflen;
		printf("Added %lu bytes of data to send buffer for idx=%d, fd=%d, pState=%p, sendBufLen=%d, recvBufLen=%d\n",
			buflen, pState->list_idx, pState->fd, pState, pState->send_buf_length, pState->recv_buf_length);
	}

	for (i = 0; i < active_sockets_len; i++) {
		pState = active_sockets[i];
		if (pState->send_buf_length > 0) {
			s = write(pState->fd, pState->send_buf, pState->send_buf_length);
			if (s == -1)
				perror("write");
			pState->send_buf_length = 0;
			printf("Sent %d bytes to fd=%d, sendBufLen=%d, recvBufLen=%d\n", s, pState->fd, pState->send_buf_length, pState->recv_buf_length);
		}
	}

	pthread_mutex_unlock(&socket_lock);
}

void read_file() {
	FILE *f = fopen("jsonData.json", "r");
	if (f) {
		fseek(f, 0, SEEK_END);
		buflen = ftell(f);
		buflen++;
		fseek(f, 0, SEEK_SET);
		buffer = malloc(buflen);
		if (buffer)
			fread(buffer, 1, buflen, f);
		fclose(f);
		buffer[buflen-1] = '\0';
	}
}
