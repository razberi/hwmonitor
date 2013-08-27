
#ifndef HIDCP2112_H
#define HIDCP2112_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

// CP2112 Default Vendor Id and Product Id
#define CP2112_VID		0x10C4
#define CP2112_PID		0xEA90



typedef uint8_t BYTE;
typedef int 	HID_SMBUS_STATUS;
typedef void*   HID_SMBUS_DEVICE;
//typedef enum    { FALSE, TRUE } bool;
typedef int bool;
//#define FALSE 0
//#define TRUE  1


#define RESET   	"\033[0m"
#define BLACK   	"\033[30m"      		/* Black */
#define RED     	"\033[31m"      		/* Red */
#define GREEN   	"\033[32m"      		/* Green */
#define YELLOW  	"\033[33m"      		/* Yellow */
#define BLUE    	"\033[34m"      		/* Blue */
#define MAGENTA 	"\033[35m"      		/* Magenta */
#define CYAN    	"\033[36m"      		/* Cyan */
#define WHITE   	"\033[37m"      		/* White */
#define BOLDBLACK   "\033[1m\033[30m"   	/* Bold Black */
#define BOLDRED     "\033[1m\033[31m"   	/* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"   	/* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"   	/* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"   	/* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m"   	/* Bold Magenta */
#define BOLDCYAN    "\033[1m\033[36m"   	/* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"   	/* Bold White */


///////////////////////////////
// CP2112 Report IDs
///////////////////////////////

// Device Configuration (Feature Request)
#define HID_SMBUS_REPORT_ID_RESET					0x01
#define HID_SMBUS_REPORT_ID_GPIO_CONFIG				0x02
#define HID_SMBUS_REPORT_ID_GET_GPIO				0x03
#define HID_SMBUS_REPORT_ID_SET_GPIO				0x04
#define HID_SMBUS_REPORT_ID_GET_VERSION				0x05
#define HID_SMBUS_REPORT_ID_SMBUS_CONFIG			0x06

// Data Transfer (Interrupt Transfer)
#define HID_SMBUS_REPORT_ID_DATA_READ_REQ			0x10
#define HID_SMBUS_REPORT_ID_DATA_WRITE_READ_REQ		0x11
#define HID_SMBUS_REPORT_ID_DATA_READ_FORCE_SEND	0x12
#define HID_SMBUS_REPORT_ID_DATA_READ_RESP			0x13
#define HID_SMBUS_REPORT_ID_DATA_WRITE				0x14
#define HID_SMBUS_REPORT_ID_TRANSFER_STATUS_REQ		0x15
#define HID_SMBUS_REPORT_ID_TRANSFER_STATUS_RESP	0x16
#define HID_SMBUS_REPORT_ID_CANCEL_TRANSFER			0x17

// USB Customization (Feature Request)
#define HID_SMBUS_REPORT_ID_LOCK_BYTE				0x20
#define HID_SMBUS_REPORT_ID_USB_CONFIG				0x21
#define HID_SMBUS_REPORT_ID_MANUF_STRING			0x22
#define HID_SMBUS_REPORT_ID_PRODUCT_STRING			0x23
#define HID_SMBUS_REPORT_ID_SERIAL_STRING			0x24


///////////////////////////////////
// HID Class-Specific Requests values. See section 7.2 of the HID specifications 
///////////////////////////////////

#define HID_GET_REPORT                0x01 
#define HID_GET_IDLE                  0x02 
#define HID_GET_PROTOCOL              0x03 
#define HID_SET_REPORT                0x09 
#define HID_SET_IDLE                  0x0A 
#define HID_SET_PROTOCOL              0x0B 
#define HID_REPORT_TYPE_INPUT         0x01 
#define HID_REPORT_TYPE_OUTPUT        0x02 
#define HID_REPORT_TYPE_FEATURE       0x03 


/////////////////////////////////////////////////////////////////////////////
// Return Code Definitions
/////////////////////////////////////////////////////////////////////////////

// HID_SMBUS_STATUS
typedef int HID_SMBUS_STATUS;

// HID_SMBUS_STATUS Return Codes
#define HID_SMBUS_SUCCESS							0x00
#define	HID_SMBUS_DEVICE_NOT_FOUND					0x01
#define HID_SMBUS_INVALID_HANDLE					0x02
#define	HID_SMBUS_INVALID_DEVICE_OBJECT				0x03
#define	HID_SMBUS_INVALID_PARAMETER					0x04
#define	HID_SMBUS_INVALID_REQUEST_LENGTH			0x05

#define	HID_SMBUS_READ_ERROR						0x10
#define	HID_SMBUS_WRITE_ERROR						0x11
#define	HID_SMBUS_READ_TIMED_OUT					0x12
#define	HID_SMBUS_WRITE_TIMED_OUT					0x13
#define	HID_SMBUS_DEVICE_IO_FAILED					0x14
#define HID_SMBUS_DEVICE_ACCESS_ERROR				0x15
#define HID_SMBUS_DEVICE_NOT_SUPPORTED				0x16

#define HID_SMBUS_UNKNOWN_ERROR						0xFF

// HID_SMBUS_TRANSFER_S0
typedef BYTE HID_SMBUS_S0;

#define HID_SMBUS_S0_IDLE							0x00
#define HID_SMBUS_S0_BUSY							0x01
#define HID_SMBUS_S0_COMPLETE						0x02
#define HID_SMBUS_S0_ERROR							0x03

// HID_SMBUS_TRANSFER_S1
typedef BYTE HID_SMBUS_S1;

// HID_SMBUS_TRANSFER_S0 = HID_SMBUS_S0_BUSY
#define HID_SMBUS_S1_BUSY_ADDRESS_ACKED				0x00
#define HID_SMBUS_S1_BUSY_ADDRESS_NACKED			0x01
#define HID_SMBUS_S1_BUSY_READING					0x02
#define HID_SMBUS_S1_BUSY_WRITING					0x03

// HID_SMBUS_TRANSFER_S0 = HID_SMBUS_S0_ERROR
#define HID_SMBUS_S1_ERROR_TIMEOUT_NACK				0x00
#define HID_SMBUS_S1_ERROR_TIMEOUT_BUS_NOT_FREE		0x01
#define HID_SMBUS_S1_ERROR_ARB_LOST					0x02
#define HID_SMBUS_S1_ERROR_READ_INCOMPLETE			0x03
#define HID_SMBUS_S1_ERROR_WRITE_INCOMPLETE			0x04
#define HID_SMBUS_S1_ERROR_SUCCESS_AFTER_RETRY		0x05

typedef enum {
	EEPROM      = 0xAE,
	PoEControl1 = 0x58,
	PoEControl2 = 0x5A,
	PoEControl3 = 0x5C,
	PoEControl4 = 0x5E,
	PoEControl  = 0x5E,
	Switch      = 0x34
} Device;

typedef enum {
	GPIO_0 = 0x01,
	GPIO_1 = 0x02,
	GPIO_2 = 0x04,
	GPIO_3 = 0x08,
	GPIO_4 = 0x10,
	GPIO_5 = 0x20,
	GPIO_6 = 0x40,
	GPIO_7 = 0x80
} LatchMask;

typedef enum {
	ON  = 0x00,
	OFF = 0x01
} LatchValue;

typedef enum {
	GPIO_FUNCTION    = 0x00,
	SPECIAL_FUNCTION = 0x01
} GPIOFunction;

typedef enum {
	OPEN_DRAIN = 0x00,
	PUSH_PULL  = 0x01
} GPIOMode;

// Synchronization
void HidCP2112_LockSyncRoot();
void HidCP2112_UnlockSyncRoot();

int HidCP2112_Connect(ushort VID, ushort PID, HID_SMBUS_DEVICE device);
int HidCP2112_Disconnect();

// Control Feature Requests
int HidCP2112_Reset(HID_SMBUS_DEVICE device);
int HidCP2112_GetGpioConfig(HID_SMBUS_DEVICE device, BYTE *direction, BYTE *pushPull, BYTE *special, BYTE *clockDivider);
int HidCP2112_SetGpioConfig(HID_SMBUS_DEVICE device, BYTE direction, BYTE pushPull, BYTE special, BYTE clockDivider);
int HidCP2112_GetGpioValues(HID_SMBUS_DEVICE device, BYTE *latchValue);
int HidCP2112_SetGpioValues(HID_SMBUS_DEVICE device, BYTE latchValue, BYTE latchMask);
int HidCP2112_GetPartNumber(HID_SMBUS_DEVICE device, BYTE *partNumber, BYTE *version);
int HidCP2112_GetSMBusConfig(HID_SMBUS_DEVICE device, uint32_t *clockSpeed, BYTE *deviceAddress, BYTE *autoSendRead, ushort *writeTimeout, ushort *readTimeout, BYTE *sclLowTimeout, ushort *retryTime);

// Interrupt Transfer Reports
int HidCP2112_DataReadRequest(HID_SMBUS_DEVICE device, BYTE slaveAddress, ushort length);
int HidCP2112_DataWriteReadRequest(HID_SMBUS_DEVICE device, BYTE slaveAddress, ushort length, BYTE targetAddrLength, BYTE *targetAddr);
int HidCP2112_DataReadForceSend(HID_SMBUS_DEVICE device, ushort length);
int HidCP2112_DataReadResponse(HID_SMBUS_DEVICE device, BYTE *status, BYTE *length, BYTE *dataRead);
int HidCP2112_DataWrite(HID_SMBUS_DEVICE device, BYTE slaveAddress, BYTE length, BYTE *dataWrite);
int HidCP2112_TransferStatusRequest(HID_SMBUS_DEVICE device);
int HidCP2112_TransferStatusResponse(HID_SMBUS_DEVICE device, BYTE *status0, BYTE *status1, ushort *status2, ushort *status3);
int HidCP2112_CancelTransfer(HID_SMBUS_DEVICE device);

void HidCP2112_Acquire_Lock();
void HidCP2112_Release_Lock();

const char * HidCP2112_Status0_Name(HID_SMBUS_S0 s0) {
	switch (s0) {
		case HID_SMBUS_S0_IDLE:		return "HID_SMBUS_S0_IDLE";
		case HID_SMBUS_S0_BUSY:		return "HID_SMBUS_S0_BUSY";
		case HID_SMBUS_S0_COMPLETE:	return "HID_SMBUS_S0_COMPLETE";
		case HID_SMBUS_S0_ERROR:	return "HID_SMBUS_S0_ERROR";
	}

	return "**UNKNOWN**";
}

const char * HidCP2112_Status1_Name(HID_SMBUS_S0 s0, HID_SMBUS_S1 s1) {
	switch (s0) {
		case HID_SMBUS_S0_BUSY:
			switch (s1) {
				case HID_SMBUS_S1_BUSY_ADDRESS_ACKED:			return "HID_SMBUS_S1_BUSY_ADDRESS_ACKED";
				case HID_SMBUS_S1_BUSY_ADDRESS_NACKED:			return "HID_SMBUS_S1_BUSY_ADDRESS_NACKED";
				case HID_SMBUS_S1_BUSY_READING:					return "HID_SMBUS_S1_BUSY_READING";
				case HID_SMBUS_S1_BUSY_WRITING:					return "HID_SMBUS_S1_BUSY_WRITING";
			}
			break;
		case HID_SMBUS_S0_COMPLETE:
		case HID_SMBUS_S0_ERROR:
			switch (s1) {
				case HID_SMBUS_S1_ERROR_TIMEOUT_NACK:			return "HID_SMBUS_S1_ERROR_TIMEOUT_NACK";
				case HID_SMBUS_S1_ERROR_TIMEOUT_BUS_NOT_FREE:	return "HID_SMBUS_S1_ERROR_TIMEOUT_BUS_NOT_FREE";
				case HID_SMBUS_S1_ERROR_ARB_LOST:				return "HID_SMBUS_S1_ERROR_ARB_LOST";
				case HID_SMBUS_S1_ERROR_READ_INCOMPLETE:		return "HID_SMBUS_S1_ERROR_READ_INCOMPLETE";
				case HID_SMBUS_S1_ERROR_WRITE_INCOMPLETE:		return "HID_SMBUS_S1_ERROR_WRITE_INCOMPLETE";
				case HID_SMBUS_S1_ERROR_SUCCESS_AFTER_RETRY:	return "HID_SMBUS_S1_ERROR_SUCCESS_AFTER_RETRY";
			}
			break;
	}

	return "**UNKNOWN**";
}


#endif /* HIDCP2112.h */