

#include <pthread.h>
#include <libusb.h>
#include "HIDCP2112.h"


// Values for bmRequestType in the Setup transaction's Data packet.
static const int CONTROL_REQUEST_TYPE_IN 				= LIBUSB_ENDPOINT_IN  | LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE;
static const int CONTROL_REQUEST_TYPE_OUT 				= LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE;
static const int CONTROL_REQUEST_TYPE_GET_DESCRIPTOR 	= LIBUSB_ENDPOINT_IN  | LIBUSB_RECIPIENT_INTERFACE;
static const int INTERRUPT_IN_ENDPOINT 					= LIBUSB_ENDPOINT_IN  | LIBUSB_RECIPIENT_INTERFACE;
static const int INTERRUPT_OUT_ENDPOINT 				= LIBUSB_ENDPOINT_OUT | LIBUSB_RECIPIENT_INTERFACE;

static const int INTERFACE = 0;
static const int TIMEOUT_MS = 5000;

#define RECV_BUFFER_SIZE	256
#define MAX_RECV_BYTES		64


void DumpBytes(uint8_t *data, size_t length);
void *ReadInterruptInThread(void *devh);


int verbose = 0;

libusb_context       *ctx    = NULL;
libusb_device_handle *handle = NULL;

pthread_mutex_t       recvLock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t       syncRoot = PTHREAD_MUTEX_INITIALIZER;
pthread_mutexattr_t   mta1;
pthread_mutexattr_t   mta2;
pthread_t recvThread;
BYTE recvBuffer[RECV_BUFFER_SIZE][MAX_RECV_BYTES];
BYTE bufferLength = 0;
bool running = 1;//TRUE;

// int main(int argc, char *argv[]) {
// 	char description[256];
// 	char string[256];
// 	int r, i;

// 	if (argc > 1 && !strcmp(argv[1], "-v"))
// 		verbose = 1;

		
		// BYTE partNum, version, direction, pushPull, special, clockDivider, latchValue;
		// HidCP2112_GetPartNumber(handle, &partNum, &version);
		// //HidCP2112_GetGpioConfig(handle, &direction, &pushPull, &special, &clockDivider);
		// //HidCP2112_SetGpioConfig(handle, 0xFF, 0x00, 0x00, 0x00);
		// //HidCP2112_GetGpioConfig(handle, &direction, &pushPull, &special, &clockDivider);
		// HidCP2112_GetGpioValues(handle, &latchValue);
		// //HidCP2112_SetGpioValues(handle, 0xF8, 0xFB);
		// //HidCP2112_GetGpioValues(handle, &latchValue);

		// uint32_t clockSpeed;
		// BYTE deviceAddress, autoSendRead, sclLowTimeout;
		// ushort writeTimeout, readTimeout, retryTime;
		// //HidCP2112_GetSMBusConfig(handle, &clockSpeed, &deviceAddress, &autoSendRead, &writeTimeout, &readTimeout, &sclLowTimeout, &retryTime);

		// BYTE targetAddr[16];
		// targetAddr[0] = 0x10;
		// HidCP2112_DataWriteReadRequest(handle, 0xAE, 32, 1, targetAddr);
		// //HidCP2112_DataReadRequest(handle, 0xAE, 16);
		// //HidCP2112_DataReadForceSend(handle, 32);

		// BYTE s0, s1;
		// ushort s2, s3;
		// BYTE status, length;
		// BYTE data[64];

		// do {
		// 	HidCP2112_TransferStatusRequest(handle);
		// 	usleep(100 * 1000); // 100ms
		//  	HidCP2112_TransferStatusResponse(handle, &s0, &s1, &s2, &s3);
		//  	//HidCP2112_DataReadResponse(handle, &status, &length, data);
		// } while (s0 != HID_SMBUS_S0_COMPLETE);

		// HidCP2112_DataReadForceSend(handle, 32);
		// usleep(100 * 1000); // 100ms
		// HidCP2112_DataReadResponse(handle, &status, &length, data);
		// //HidCP2112_DataReadResponse(handle, &status, &length, data);
		// //HidCP2112_DataReadResponse(handle, &status, &length, data);
	 	
	 // 	//HidCP2112_Reset(handle);

		// usleep(30 * 1000 * 1000);
//	return 0;
//}

int HidCP2112_Connect(ushort VID, ushort PID, HID_SMBUS_DEVICE device) {
	libusb_device **devs;
	libusb_device *cp2112;
	char description[256];
 	char string[256];
 	struct libusb_config_descriptor *config;
	struct libusb_device_descriptor desc;
	ssize_t cnt;
	int r, i;

	if (handle != NULL) {
		fprintf(stderr, BOLDRED "Device already initialized, disconnect first before connecting again." RESET "\n");
		return -1;
	}

	r = libusb_init(&ctx);
	if (r < 0)
		return r;

	libusb_set_debug(ctx, 3);

	cnt = libusb_get_device_list(ctx, &devs);
	if (cnt < 0)
		return (int) cnt;

	for (i = 0 ; devs[i] ; ++i) {
		if (libusb_open(devs[i], &handle) == LIBUSB_SUCCESS) {
			if (libusb_get_device_descriptor(devs[i], &desc) == 0) {
				if (libusb_get_string_descriptor_ascii(handle, desc.iManufacturer, string, sizeof(string)) > 0)
			        snprintf(description, sizeof(description), "%s - ", string);
				if (libusb_get_string_descriptor_ascii(handle, desc.iProduct, string, sizeof(string)) > 0)
					snprintf(description + strlen(description), sizeof(description) - strlen(description), "%s", string);

				if (desc.idVendor == VID && desc.idProduct == PID) {
					cp2112 = devs[i];
					printf("FOUND CP2112: Dev (bus %d, device %d): %04X:%04X : %s\n", libusb_get_bus_number(devs[i]), libusb_get_device_address(devs[i]), desc.idVendor, desc.idProduct, description);
					break;
				}
			}

			if (handle)
				libusb_close(handle);
			handle = NULL;
		}
	}

	libusb_free_device_list(devs, 1);

	if (handle) {
		if (libusb_kernel_driver_active(handle, 0)) {
			printf("Device busy, detaching...\n");
			libusb_detach_kernel_driver(handle, 0); 
  		} else 
  			printf("Device free from kernel.\n"); 

		libusb_claim_interface(handle, INTERFACE);

		//HidCP2112_Reset(handle);
		//return 0;

		pthread_mutexattr_init(&mta1);
		pthread_mutexattr_settype(&mta1, PTHREAD_MUTEX_RECURSIVE); /* or PTHREAD_MUTEX_RECURSIVE_NP */
		pthread_mutex_init(&recvLock, &mta1);
		pthread_mutexattr_init(&mta2);
		pthread_mutexattr_settype(&mta2, PTHREAD_MUTEX_RECURSIVE); /* or PTHREAD_MUTEX_RECURSIVE_NP */
		pthread_mutex_init(&syncRoot, &mta2);

		r = pthread_create(&recvThread, NULL, ReadInterruptInThread, (void *)handle);
		if (r) {
			fprintf(stderr, BOLDRED "return code from pthread_create(): %d" RESET "\n", r);
			return r;
		}

		usleep(3*1000*1000);
		pthread_mutex_lock(&recvLock);
		printf("Draining receive buffer. Size: %d\n", bufferLength);
		bufferLength = 0;
		pthread_mutex_unlock(&recvLock);

		device = (HID_SMBUS_DEVICE)handle;
		return 0;
	} else {
		fprintf(stderr, BOLDRED "Could not find CP2112 device on this system." RESET "\n");
		return -1;
	}
}

int HidCP2112_Disconnect() {

	if (!handle) {
		fprintf(stderr, BOLDRED "Cannot disconnect: No device connected." RESET "\n");
		return -1;
	}

	// stop receive thread
 	running = 0;//FALSE;
 	pthread_join(recvThread, NULL);

 	// release iterface and close device handle
	libusb_release_interface(handle, INTERFACE);
	libusb_close(handle);
	handle = NULL;

	// exit context
	libusb_exit(ctx);
	pthread_exit(NULL);

	return 0;
}

/**
 * Adds the provided message to the receive buffer.
 * This method is thread-safe.
 * \param[in] data   The data buffer to copy the message from.
 * \param[in] length The length of the provided data buffer.
 * \return Returns true if the message was successfully added to the buffer; false otherwise.
 */   	
bool AddToBuffer(BYTE *data, BYTE length) {
	int i = 0;
	pthread_mutex_lock(&recvLock);
	if (bufferLength == RECV_BUFFER_SIZE - 1) {
		fprintf(stderr, BOLDRED "Cannot receive message, buffer full." RESET);
		pthread_mutex_unlock(&recvLock);
		return 0;//FALSE;
	}
	// get next free index
	int index = bufferLength++;
	// copy data from data to receive buffer
	memcpy(recvBuffer[index], data, length);

	if (verbose)
		printf("New buffer size: %i\n", bufferLength);
	pthread_mutex_unlock(&recvLock);
	return 1;//TRUE;
}

/**
 * Gets the next message with the provided Id from the receive buffer.
 * This method is thread-safe.
 * \param[in]  reportId The Id of the message to get.
 * \param[out] data     The data buffer to copy the message to.
 * \param[in]  length   The length of the provided data buffer.
 * \return Returns true if a message was found; false otherwise.
 */   	
bool GetNextIdFromBuffer(BYTE reportId, BYTE *data, BYTE length) {
	int i = 0, index = -1;
	pthread_mutex_lock(&recvLock);

	// find index of first msg with requested id
	for (i = 0; i < bufferLength; i++) {
		BYTE *bufData = recvBuffer[i];
		if (bufData[0] == reportId) {
			index = i;
			break;
		}
	}

	// if it couldn't find one return false
	if (index < 0) {
		pthread_mutex_unlock(&recvLock);
		return 0;//FALSE;
	}

	// copy first found msg to provided data buffer, only copy the length requested
	for (i = 0; i < length; ++i)
		data[i] = recvBuffer[index][i];

	// shift remaining elements in buffer forward by 1
	for (i = index; i < RECV_BUFFER_SIZE - 1; ++i)
		memcpy(recvBuffer[i], recvBuffer[i + 1], MAX_RECV_BYTES);

	// decrement used buffer size
	bufferLength--;

	if (verbose)
		printf("New buffer size: %i\n", bufferLength);
	pthread_mutex_unlock(&recvLock);
	return 1;//TRUE;
}


void *ReadInterruptInThread(void *devh) {
	libusb_device_handle *device = (libusb_device_handle*)devh;
	int bytes_transferred, success;
	int i = 0;
	BYTE data[64];

	while (running) {
		//pthread_mutex_lock(&syncRoot);
		
		success = libusb_interrupt_transfer(
				device,
				INTERRUPT_IN_ENDPOINT,
				data,
				sizeof(data),
				&bytes_transferred,
				5000);
		
		//pthread_mutex_unlock(&syncRoot);

		if (success == LIBUSB_SUCCESS) {
			if (verbose) {
				//DumpBytes(data, sizeof(data));
				printf("HID SMBus Interrupt In: %u bytes transferred. ReportId: %02X\n", bytes_transferred, data[0]);
		 	}

		 	AddToBuffer(data, sizeof(data));
		}// else {
		//	fprintf(stderr, "ReadInterruptInThread: Error receiving interrupt report: %s (Bytes transferred: %d)\n", libusb_strerror(success), bytes_transferred);
		//}

		usleep(10 * 1000); // sleep for a sec to minimize lock contention
	}

	printf(BOLDGREEN "Receive thread stopped." RESET "\n");
}

void HidCP2112_Acquire_Lock() {
	pthread_mutex_lock(&syncRoot);
}

void HidCP2112_Release_Lock() {
	pthread_mutex_unlock(&syncRoot);
}

/**
 * AN495 - 4.1 - Reset Device
 * Report Id: 0x01
 * Direction: Feature Request Out
 * Parameters:
 *   Reset Type - Offset 1 - Size 1 - Value 0x01
 */
int HidCP2112_Reset(HID_SMBUS_DEVICE device) {
	int bytes_transferred;
	BYTE data_in[2];

	data_in[0] = HID_SMBUS_REPORT_ID_RESET;
	data_in[1] = 0x02;

	pthread_mutex_lock(&syncRoot);

	bytes_transferred = libusb_control_transfer(
			device,
			CONTROL_REQUEST_TYPE_OUT,
			HID_SET_REPORT,
			(HID_REPORT_TYPE_FEATURE << 8) | HID_SMBUS_REPORT_ID_RESET,
			INTERFACE,
			data_in,
			sizeof(data_in),
			TIMEOUT_MS);

	pthread_mutex_unlock(&syncRoot);

	if (bytes_transferred == -1) { // special case for reset, success is when the result is -1
		if (verbose) {
			DumpBytes(data_in, sizeof(data_in));
			printf("HID SMBus Reset Success.\n");
	 	}
	} else {
		fprintf(stderr, BOLDRED "HidCP2112_Reset: Error setting feature report. Bytes transferred: %d" RESET "\n", bytes_transferred);
		return bytes_transferred;
	}

	return LIBUSB_SUCCESS;
}

/**
 * AN495 - 4.2 - Get GPIO Configuration
 * Report Id: 0x02
 * Direction: Feature Request In
 * Parameters:
 *   Direction     - Offset 1 - Size 1 - Value 0=input 1=output
 *   Push-Pull     - Offset 2 - Size 1 - Value 0=open-drain 1=push-pull
 *   Special       - Offset 3 - Size 1 - Enables special functions of GPIO pins
 *   Clock Divider - Offset 4 - Size 1 - 0=48 MHz clock, other values output clock signal determined by equation
 */
int HidCP2112_GetGpioConfig(HID_SMBUS_DEVICE device, BYTE *direction, BYTE *pushPull, BYTE *special, BYTE *clockDivider) {
	int bytes_transferred;
	BYTE data_out[5];
 	*direction = 0;
 	*pushPull = 0;
 	*special = 0;
 	*clockDivider = 0;

	pthread_mutex_lock(&syncRoot);

	bytes_transferred = libusb_control_transfer(
			device,
			CONTROL_REQUEST_TYPE_IN,
			HID_GET_REPORT,
			(HID_REPORT_TYPE_FEATURE << 8) | HID_SMBUS_REPORT_ID_GPIO_CONFIG,
			INTERFACE,
			data_out,
			sizeof(data_out),
			TIMEOUT_MS);

	pthread_mutex_unlock(&syncRoot);

	if (bytes_transferred > 0) {
	 	*direction    = data_out[1];
	 	*pushPull     = data_out[2];
	 	*special      = data_out[3];
	 	*clockDivider = data_out[4];

		if (verbose) {
			DumpBytes(data_out, sizeof(data_out));
			printf("HID SMBus Get GPIO Config: ");
	 		printf("Direction: %02X  Push-Pull: %02X  Special: %02X  ClockDivider: %02X\n", data_out[1], data_out[2], data_out[3], data_out[4]);
	 	}
	} else {
		fprintf(stderr, BOLDRED "HidCP2112_GetGpioConfig: Error getting feature report. Bytes transferred: %d" RESET "\n", bytes_transferred);
		return bytes_transferred;
	}

	return LIBUSB_SUCCESS;
}

/**
 * AN495 - 4.2 - Set GPIO Configuration
 * Report Id: 0x02
 * Direction: Feature Request Out
 * Parameters:
 *   Direction     - Offset 1 - Size 1 - Value 0=input 1=output
 *   Push-Pull     - Offset 2 - Size 1 - Value 0=open-drain 1=push-pull
 *   Special       - Offset 3 - Size 1 - Enables special functions of GPIO pins
 *   Clock Divider - Offset 4 - Size 1 - 0=48 MHz clock, other values output clock signal determined by equation
 */
int HidCP2112_SetGpioConfig(HID_SMBUS_DEVICE device, BYTE direction, BYTE pushPull, BYTE special, BYTE clockDivider) {
	int bytes_transferred;
	BYTE data[5];

	data[0] = HID_SMBUS_REPORT_ID_GPIO_CONFIG;
	data[1] = direction;
	data[2] = pushPull;
	data[3] = special;
	data[4] = clockDivider;

	pthread_mutex_lock(&syncRoot);

	bytes_transferred = libusb_control_transfer(
			device,
			CONTROL_REQUEST_TYPE_OUT,
			HID_SET_REPORT,
			(HID_REPORT_TYPE_FEATURE << 8) | HID_SMBUS_REPORT_ID_GPIO_CONFIG,
			INTERFACE,
			data,
			sizeof(data),
			TIMEOUT_MS);

	pthread_mutex_unlock(&syncRoot);

	if (bytes_transferred > 0) {
		if (verbose) {
			DumpBytes(data, sizeof(data));
			printf("HID SMBus Set GPIO Config: ");
	 		printf("Direction: %02X  Push-Pull: %02X  Special: %02X  ClockDivider: %02X\n", data[1], data[2], data[3], data[4]);
	 	}
	} else {
		fprintf(stderr, BOLDRED "HidCP2112_GetGpioConfig: Error setting feature report. Bytes transferred: %d" RESET "\n", bytes_transferred);
		return bytes_transferred;
	}

	return LIBUSB_SUCCESS;
}

/**
 * AN495 - 4.3 - Get GPIO Values
 * Report Id: 0x03
 * Direction: Feature Request In
 * Parameters:
 *   Latch Value - Offset 1 - Size 2 - Current latch values (Note: docs say 2 bytes but evidence shows its only 1 byte)
 */
int HidCP2112_GetGpioValues(HID_SMBUS_DEVICE device, BYTE *latchValue) {
	int bytes_transferred;
	BYTE data[2];
 	*latchValue = 0;

	pthread_mutex_lock(&syncRoot);

	bytes_transferred = libusb_control_transfer(
			device,
			CONTROL_REQUEST_TYPE_IN,
			HID_GET_REPORT,
			(HID_REPORT_TYPE_FEATURE << 8) | HID_SMBUS_REPORT_ID_GET_GPIO,
			INTERFACE,
			data,
			sizeof(data),
			TIMEOUT_MS);

	pthread_mutex_unlock(&syncRoot);

	if (bytes_transferred > 0) {
	 	//*latchValue = (data[1] << 8) | data[2]; // docs say 2 bytes, leaving this here in case it turns out to be correct
		*latchValue = data[1];
		if (verbose) {
			DumpBytes(data, sizeof(data));
			printf("HID SMBus Get GPIO Values: ");
	 		printf("LatchValue: %02X\n", *latchValue);
	 	}
	} else {
		fprintf(stderr, BOLDRED "HidCP2112_GetGpioValues: Error getting feature report. Bytes transferred: %d" RESET "\n", bytes_transferred);
		return bytes_transferred;
	}

	return LIBUSB_SUCCESS;
}

/**
 * AN495 - 4.4 - Set GPIO Values
 * Report Id: 0x04
 * Direction: Feature Request Out
 * Parameters:
 *   Latch value - Offset 1 - Size 1 - Latch value
 *   Latch Mask  - Offset 2 - Size 1 - Pin to set to new latch value
 */
int HidCP2112_SetGpioValues(HID_SMBUS_DEVICE device, BYTE latchValue, BYTE latchMask) {
	int bytes_transferred;
	BYTE data[3];

	data[0] = HID_SMBUS_REPORT_ID_SET_GPIO;
	data[1] = latchValue;
	data[2] = latchMask;

	pthread_mutex_lock(&syncRoot);

	bytes_transferred = libusb_control_transfer(
			device,
			CONTROL_REQUEST_TYPE_OUT,
			HID_SET_REPORT,
			(HID_REPORT_TYPE_FEATURE << 8) | HID_SMBUS_REPORT_ID_SET_GPIO,
			INTERFACE,
			data,
			sizeof(data),
			TIMEOUT_MS);

	pthread_mutex_unlock(&syncRoot);

	if (bytes_transferred > 0) {
		if (verbose) {
			DumpBytes(data, sizeof(data));
			printf("HID SMBus Set GPIO Values: ");
	 		printf("Latch value: %02X  Latch Mask: %02X\n", data[1], data[2]);
	 	}
	} else {
		fprintf(stderr, BOLDRED "HidCP2112_SetGpioValues: Error setting feature report. Bytes transferred: %d" RESET "\n", bytes_transferred);
		return bytes_transferred;
	}

	return LIBUSB_SUCCESS;
}

/**
 * AN495 - 4.5 - Set GPIO Values
 * Report Id: 0x05
 * Direction: Feature Request In
 * Parameters:
 *   Part Number     - Offset 1 - Size 1 - Value 0x0C - Device Part Number
 *   Device Version  - Offset 2 - Size 1 - Value varies
 */
int HidCP2112_GetPartNumber(HID_SMBUS_DEVICE device, BYTE *partNumber, BYTE *version) {
	int bytes_transferred;
	int i = 0;
	BYTE data[3];
 	*partNumber = 0;
 	*version = 0;

	pthread_mutex_lock(&syncRoot);

	bytes_transferred = libusb_control_transfer(
			device,
			CONTROL_REQUEST_TYPE_IN,
			HID_GET_REPORT,
			(HID_REPORT_TYPE_FEATURE << 8) | HID_SMBUS_REPORT_ID_GET_VERSION,
			INTERFACE,
			data,
			sizeof(data),
			TIMEOUT_MS);

	pthread_mutex_unlock(&syncRoot);

	if (bytes_transferred > 0) {
	 	*partNumber = data[1];
	 	*version 	= data[2];

		if (verbose) {
			DumpBytes(data, sizeof(data));
			printf("HID SMBus Get Part Number: ");
	 		printf("Part Number: %02X  Version: %02X\n", data[1], data[2]);
	 	}
	} else {
		fprintf(stderr, BOLDRED "HidCP2112_GetPartNumber: Error getting feature report. Bytes transferred: %d" RESET "\n", bytes_transferred);
		return bytes_transferred;
	}

	return LIBUSB_SUCCESS;
}

/**
 * AN495 - 4.6 - Get SMBus Configuration
 * Report Id: 0x06
 * Direction: Feature Request In
 * Parameters:
 *   Clock Speed     - Offset 1  - Size 4 - Default Value 0x186A0 (100 KHz) - SMBus clock speed in Hz
 *   Device Address  - Offset 5  - Size 1 - Default 0x02   - Bits 7-1 make up device address (least significant bit is masked)
 *   Auto Send Read  - Offset 6  - Size 1 - Default 0x00   - Disabled / Enabled (0x01)
 *   Write Timeout   - Offset 7  - Size 2 - Default 0x0000 - No timeout - 0-1000ms timeout value
 *   Read Timeout    - Offset 9  - Size 2 - Default 0x0000 - No timeout - 0-1000ms timeout value
 *   SCL Low Timeout - Offset 11 - Size 1 - Default 0x00   - Disabled / Enabled (0x01)
 *   Retry Time      - Offset 12 - Size 2 - Default 0x0000 - No limit - 0-1000 retries
 */
int HidCP2112_GetSMBusConfig(HID_SMBUS_DEVICE device, uint32_t *clockSpeed, BYTE *deviceAddress, BYTE *autoSendRead, ushort *writeTimeout, ushort *readTimeout, BYTE *sclLowTimeout, ushort *retryTime) {
	int bytes_transferred;
	int i = 0;
	BYTE data[14];
 	*clockSpeed = 0;
 	*deviceAddress = 0;
 	*autoSendRead = 0;
 	*writeTimeout = 0;
 	*readTimeout = 0;
 	*sclLowTimeout = 0;
 	*retryTime = 0;

	pthread_mutex_lock(&syncRoot);

	bytes_transferred = libusb_control_transfer(
			device,
			CONTROL_REQUEST_TYPE_IN,
			HID_GET_REPORT,
			(HID_REPORT_TYPE_FEATURE << 8) | HID_SMBUS_REPORT_ID_SMBUS_CONFIG,
			INTERFACE,
			data,
			sizeof(data),
			TIMEOUT_MS);

	pthread_mutex_unlock(&syncRoot);

	if (bytes_transferred > 0) {
	 	*clockSpeed    = data[1] << 24 | data[2] << 16 | data[3] << 8 | data[4];
	 	*deviceAddress = data[5];
	 	*autoSendRead  = data[6];
	 	*writeTimeout  = data[7] << 8 | data[8];
	 	*readTimeout   = data[9] << 8 | data[10];
	 	*sclLowTimeout = data[11];
	 	*retryTime     = data[12] << 8 | data[13];

		if (verbose) {
			DumpBytes(data, sizeof(data));
			printf("HID SMBus Get SMBus Config: ");
	 		printf("ClockSpeed: %u DeviceAddress: %02X AutoSendRead: %02X WriteTimeout: %u ReadTimeout: %u SCL Low Timeout: %02X RetryTime: %u\n", *clockSpeed, *deviceAddress, *autoSendRead, *writeTimeout, *readTimeout, *sclLowTimeout, *retryTime);
	 	}
	} else {
		fprintf(stderr, BOLDRED "HidCP2112_GetSMBusConfig: Error getting feature report. Bytes transferred: %d" RESET "\n", bytes_transferred);
		return bytes_transferred;
	}

	return LIBUSB_SUCCESS;
}


/**
 * AN495 - 5.1 - Data Read Request
 * Report Id: 0x10
 * Direction: Interrupt Out
 * Parameters:
 *   Slave Address - Offset 1 - Size 1 - Must be between 0xF7-0x02. Least significant bit is r/w bit and must be zero.
 *   Length        - Offset 2 - Size 2 - Number of bytes (1-512 bytes) to read back.
 */
int HidCP2112_DataReadRequest(HID_SMBUS_DEVICE device, BYTE slaveAddress, ushort length) {
	int bytes_transferred, success;
	int i = 0;
	BYTE data[4];

	data[0] = HID_SMBUS_REPORT_ID_DATA_READ_REQ;
	data[1] = slaveAddress;
	data[2] = length >> 8;
	data[3] = length & 0xFF;

	pthread_mutex_lock(&syncRoot);

	success = libusb_interrupt_transfer(
			device,
			INTERRUPT_OUT_ENDPOINT,
			data,
			sizeof(data),
			&bytes_transferred,
			TIMEOUT_MS);

	pthread_mutex_unlock(&syncRoot);

	if (bytes_transferred > 0) {
		if (verbose) {
			DumpBytes(data, sizeof(data));
			printf("HID SMBus Data Read Request: ");
	 		printf("SlaveAddress: %02X Length: %u\n", slaveAddress, length);
	 	}
	} else {
		fprintf(stderr, BOLDRED "HidCP2112_DataReadRequest: Error sending interrupt report. Bytes transferred: %d" RESET "\n", bytes_transferred);
		return bytes_transferred;
	}

	return LIBUSB_SUCCESS;
}

/**
 * AN495 - 5.2 - Data Write Read Request
 * Report Id: 0x11
 * Direction: Interrupt Out
 * Parameters:
 *   Slave Address         - Offset 1 - Size 1 - Must be between 0xF7-0x02. Least significant bit is r/w bit and must be zero.
 *   Length                - Offset 2 - Size 2 - Number of bytes (1-512 bytes) to read back.
 *   Target Address Length - Offset 4 - Size 1  - Number of bytes in target address (from 0x01 to 0x10)
 *   Target Address        - Offset 5 - Size 16 - Address of device to be read.  The number of bytes in this field must match the number of bytes specified in the target address length above
 */
int HidCP2112_DataWriteReadRequest(HID_SMBUS_DEVICE device, BYTE slaveAddress, ushort length, BYTE targetAddrLength, BYTE *targetAddr) {
	int bytes_transferred, success;
	int i = 0;
	BYTE data[21];

	data[0] = HID_SMBUS_REPORT_ID_DATA_WRITE_READ_REQ;
	data[1] = slaveAddress;
	data[2] = length >> 8;
	data[3] = length & 0xFF;
	data[4] = targetAddrLength;
	// copy target addr
	for (i = 0; i < targetAddrLength; ++i)
		data[5+i] = targetAddr[i];

	pthread_mutex_lock(&syncRoot);

	success = libusb_interrupt_transfer(
			device,
			INTERRUPT_OUT_ENDPOINT,
			data,
			sizeof(data),
			&bytes_transferred,
			TIMEOUT_MS);

	pthread_mutex_unlock(&syncRoot);

	if (bytes_transferred > 0) {
		if (verbose) {
			DumpBytes(data, sizeof(data));
			printf("HID SMBus Data Write Read Request: ");
	 		printf("SlaveAddress: %02X Length: %u TargetAddrLength: %02X TargetAddr: ", slaveAddress, length, targetAddrLength);
	 		for (i = 0; i < targetAddrLength; ++i)
	 			printf("%02X ", targetAddr[i]);
	 		printf("\n");
	 	}
	} else {
		fprintf(stderr, BOLDRED "HidCP2112_DataWriteReadRequest: Error sending interrupt report. Bytes transferred: %d" RESET "\n", bytes_transferred);
		return bytes_transferred;
	}

	return LIBUSB_SUCCESS;
}

/**
 * AN495 - 5.3 - Data Read Force Send
 * Report Id: 0x12
 * Direction: Interrupt Out
 * Parameters:
 *   Length - Offset 1 - Size 2 - Number of valid data bytes
 */
int HidCP2112_DataReadForceSend(HID_SMBUS_DEVICE device, ushort length) {
	int bytes_transferred, success;
	int i = 0;
	BYTE data[3];

	data[0] = HID_SMBUS_REPORT_ID_DATA_READ_FORCE_SEND;
	data[1] = length >> 8;
	data[2] = length & 0xFF;

	//time_t lt = time(NULL);
	pthread_mutex_lock(&syncRoot);
	//int ltot = time(NULL) - lt;
	//printf("Took %ds to acquire lock.\n", ltot);
	
	//time_t t1 = time(NULL);
	success = libusb_interrupt_transfer(
			device,
			INTERRUPT_OUT_ENDPOINT,
			data,
			sizeof(data),
			&bytes_transferred,
			TIMEOUT_MS);

	//int tot = time(NULL) - t1;
	//printf("Took %ds to run.\n", tot);
	pthread_mutex_unlock(&syncRoot);

	if (bytes_transferred > 0) {
		if (verbose) {
			DumpBytes(data, sizeof(data));
			printf("HID SMBus Data Read Force Send: ");
	 		printf("Length: %u\n", length);
	 	}
	} else {
		fprintf(stderr, BOLDRED "HidCP2112_DataReadForceSend: Error sending interrupt report. Bytes transferred: %d" RESET "\n", bytes_transferred);
		return bytes_transferred;
	}

	return LIBUSB_SUCCESS;
}

/**
 * AN495 - 5.4 - Data Read Response
 * Report Id: 0x13
 * Direction: Interrupt In
 * Parameters:
 *   Status - Offset 1 - Size 1  - 0x00 = Idle, 0x01 = Busy, 0x02 = Complete, 0x03 = Complete with error
 *   Length - Offset 2 - Size 1  - Number of valid data bytes
 *   Data   - Offset 3 - Size 61 - Data being returned from SMBus slave device
 */
int HidCP2112_DataReadResponse(HID_SMBUS_DEVICE device, BYTE *status, BYTE *length, BYTE *dataRead) {
	int bytes_transferred, success;
	int i = 0, retries = 0;
	BYTE data[64];
	
	while (retries++ < 300) {
		if (GetNextIdFromBuffer(HID_SMBUS_REPORT_ID_DATA_READ_RESP, data, sizeof(data))) {
			*status = data[1];
			*length = data[2];
		 	for (i = 0; i < *length; ++i)
		 		dataRead[i] = data[3+i];
			
			if (verbose) {
				DumpBytes(data, *length+3);
				printf("HID SMBus Data Read Response: ");
		 		printf("Bytes Transferred: %u Status: " BOLDBLUE "%s" RESET " Length: %u DataRead: ", bytes_transferred, HidCP2112_Status0_Name(*status), *length);
		 		for (i = 0; i < *length; ++i)
		 			printf("%02X ", dataRead[i]);
		 		printf("\n");
		 	}

		 	return LIBUSB_SUCCESS;
		} else {
			usleep(10 * 1000); // 10ms
		}
	}

	fprintf(stderr, BOLDRED "HidCP2112_DataReadResponse: Error receiving interrupt report, timed out. Bytes transferred: %d" RESET "\n", bytes_transferred);
	return bytes_transferred;
}

/**
 * AN495 - 5.5 - Data Write
 * Report Id: 0x14
 * Direction: Interrupt Out
 * Parameters:
 *   Slave Address - Offset 1 - Size 1  - Must be between 0xF7-0x02. Least significant bit is r/w bit and must be zero.
 *   Length        - Offset 2 - Size 1  - Number of valid data bytes
 *   Data          - Offset 3 - Size 61 - Data being returned from the SMBus slave device
 */
int HidCP2112_DataWrite(HID_SMBUS_DEVICE device, BYTE slaveAddress, BYTE length, BYTE *dataWrite) {
	int bytes_transferred, success;
	int i = 0;
	BYTE data[64];

	data[0] = HID_SMBUS_REPORT_ID_DATA_WRITE;
	data[1] = slaveAddress;
	data[2] = length;
	// copy data
	for (i = 0; i < length; ++i)
		data[3+i] = dataWrite[i];

	pthread_mutex_lock(&syncRoot);

	success = libusb_interrupt_transfer(
			device,
			INTERRUPT_OUT_ENDPOINT,
			data,
			sizeof(data),
			&bytes_transferred,
			TIMEOUT_MS);

	pthread_mutex_unlock(&syncRoot);

	if (bytes_transferred > 0) {
		if (verbose) {
			DumpBytes(data, length+3);
			printf("HID SMBus Data Write: ");
	 		printf("SlaveAddress: %02X Length: %u DataWrite: ", slaveAddress, length);
	 		for (i = 0; i < length; ++i)
	 			printf("%02X ", dataWrite[i]);
	 		printf("\n");
	 	}
	} else {
		fprintf(stderr, BOLDRED "HidCP2112_DataWrite: Error sending interrupt report. Bytes transferred: %d" RESET "\n", bytes_transferred);
		return bytes_transferred;
	}

	return LIBUSB_SUCCESS;
}

/**
 * AN495 - 5.6 - Transfer Status Request
 * Report Id: 0x15
 * Direction: Interrupt Out
 * Parameters:
 *   Request - Offset 1 - Size 1  - Value 0x01 - Request SMBus transfer status
 */
int HidCP2112_TransferStatusRequest(HID_SMBUS_DEVICE device) {
	int bytes_transferred, success;
	int i = 0;
	BYTE data[2];

	data[0] = HID_SMBUS_REPORT_ID_TRANSFER_STATUS_REQ;
	data[1] = 0x01;

	pthread_mutex_lock(&syncRoot);

	success = libusb_interrupt_transfer(
			device,
			INTERRUPT_OUT_ENDPOINT,
			data,
			sizeof(data),
			&bytes_transferred,
			TIMEOUT_MS);

	pthread_mutex_unlock(&syncRoot);

	if (bytes_transferred > 0) {
		if (verbose) {
			DumpBytes(data, sizeof(data));
			printf("HID SMBus Transfer Status Request:\n");
	 	}
	} else {
		fprintf(stderr, BOLDRED "HidCP2112_TransferStatusRequest: Error sending interrupt report. Bytes transferred: %d" RESET "\n", bytes_transferred);
		return bytes_transferred;
	}

	return LIBUSB_SUCCESS;
}

/**
 * AN495 - 5.7 - Transfer Status Response
 * Report Id: 0x16
 * Direction: Interrupt In
 * Parameters:
 *   Status 0 - Offset 1 - Size 1 - 0x00 = Idle, 0x01 = Busy, 0x02 = Complete, 0x03 = Complete with error
 *   Status 1 - Offset 2 - Size 1 - Specific conditions based on Status 0
 *   Status 2 - Offset 3 - Size 2 - Number of retries before completing, being cancelled, or timing out
 *   Status 3 - Offset 5 - Size 2 - Number of received bytes
 */
int HidCP2112_TransferStatusResponse(HID_SMBUS_DEVICE device, BYTE *status0, BYTE *status1, ushort *status2, ushort *status3) {
	BYTE data[7];
	int retries = 0;

	while (retries++ < 300) {
		if (GetNextIdFromBuffer(HID_SMBUS_REPORT_ID_TRANSFER_STATUS_RESP, data, sizeof(data))) {
			*status0 = data[1];
			*status1 = data[2];
			*status2 = data[3] << 8 | data[4];
			*status3 = data[5] << 8 | data[6];
		
			if (verbose) {
				DumpBytes(data, 7);
				printf("HID SMBus Transfer Status Response: ");
		 		printf("Status0: " BOLDBLUE "%s" RESET " Status1: " BOLDBLUE "%s" RESET " Status2 (retries): %u Status3 (bytes): %u\n", HidCP2112_Status0_Name(*status0), HidCP2112_Status1_Name(*status0, *status1), *status2, *status3);
		 	}

			return LIBUSB_SUCCESS;
		} else {
			usleep(10 * 1000); // 10ms
		}
	}
	
	fprintf(stderr, BOLDRED "HidCP2112_TransferStatusResponse: Error receiving interrupt report from buffer, timed out." RESET "\n");
	return LIBUSB_ERROR_INVALID_PARAM;
}

/**
 * AN495 - 5.8 - Cancel Transfer
 * Report Id: 0x17
 * Direction: Interrupt Out
 * Parameters:
 *   Cancel - Offset 1 - Size 1  - Value 0x01 - Will cancel the current transfer.  All other values are ignored.
 */
int HidCP2112_CancelTransfer(HID_SMBUS_DEVICE device) {
	int bytes_transferred, success;
	int i = 0;
	BYTE data[2];

	data[0] = HID_SMBUS_REPORT_ID_CANCEL_TRANSFER;
	data[1] = 0x01;

	pthread_mutex_lock(&syncRoot);

	success = libusb_interrupt_transfer(
			device,
			INTERRUPT_OUT_ENDPOINT,
			data,
			sizeof(data),
			&bytes_transferred,
			TIMEOUT_MS);

	pthread_mutex_unlock(&syncRoot);

	if (bytes_transferred > 0) {
		if (verbose) {
			DumpBytes(data, sizeof(data));
			printf("HID SMBus Cancel Transfer Request:\n");
	 	}
	} else {
		fprintf(stderr, BOLDRED "HidCP2112_CancelTransfer: Error sending interrupt report. Bytes transferred: %d" RESET "\n", bytes_transferred);
		return bytes_transferred;
	}

	return LIBUSB_SUCCESS;
}

void DumpBytes(uint8_t *data, size_t length) {
	int i = 0;
	for (i = 0; i < length; i++)
		printf("%02X ", data[i]);
	printf("\n");
}