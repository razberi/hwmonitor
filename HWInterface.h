
#ifndef HWINTERFACE_H
#define HWINTERFACE_H


typedef enum {
	Other,
	Razberi4Port,
	Razberi16Port
} Model;

typedef enum {
	On,
	Off
} FaultLED;

typedef enum {
	Green,
	Red
} StatusLED;

typedef enum {
	PORT_1 = 1,
	PORT_2,
	PORT_3,
	PORT_4,
	PORT_5,
	PORT_6,
	PORT_7,
	PORT_8,
	PORT_9,
	PORT_10,
	PORT_11,
	PORT_12,
	PORT_13,
	PORT_14,
	PORT_15,
	PORT_16,
	UPLINK_1,
	UPLINK_2,
	SWITCH_1,
	SWITCH_2,
	COM_X,
	DSP
} Port;


void GetModelAndSerial();
void GetLEDs();
void SetLEDs(FaultLED faultLed, StatusLED statusLed);


const char * Get_FaultLED_Name(FaultLED fled) {
	switch (fled) {
		case On:  return "On";
		case Off: return "Off";
	}

	return "Unknown";
}

const char * Get_StatusLED_Name(StatusLED sled) {
	switch (sled) {
		case Green: return "Green";
		case Red:   return "Red";
	}
	
	return "Unknown";
}

const char * Get_Model_Name(Model model) {
	switch (model) {
		case Other:         return "Other";
		case Razberi4Port:  return "Razberi4Port";
		case Razberi16Port: return "Razberi16Port";
	}
	
	return "Unknown";
}

#endif /* HWINTERFACE_H */