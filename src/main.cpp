#include <Arduino.h>
#include <RadioLib.h>
#include "protocol.h"

SX1262 radio = new Module(8, 14, 12, 13);

#define LORA_FREQ   915.0
#define LORA_BW     125.0
#define LORA_SF     9
#define LORA_CR     5
#define LORA_POWER  17

uint32_t txCount = 0;
uint32_t rxCount = 0;
volatile bool rxFlag = false;

static uint8_t rxBuf[MAX_PKT_SIZE];

void IRAM_ATTR setRxFlag() { rxFlag = true; }

// Frame format on serial link, both directions:
//   [0xAA][0x55][type_byte][len_lo][len_hi][...payload...][crc8]
// type_byte: 'R' = RECV (radio→Pi), 'S' = SEND (Pi→radio),
//            'I' = INFO/log line (radio→Pi, ASCII payload)

#define FRAME_START_1  0xAA
#define FRAME_START_2  0x55

uint8_t crc8(const uint8_t* data, size_t len) {
    uint8_t crc = 0;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc & 0x80) ? (crc << 1) ^ 0x07 : (crc << 1);
    }
    return crc;
}

void sendFrame(uint8_t type, const uint8_t* payload, uint16_t len) {
    Serial.write(FRAME_START_1);
    Serial.write(FRAME_START_2);
    Serial.write(type);
    Serial.write(len & 0xFF);
    Serial.write((len >> 8) & 0xFF);
    Serial.write(payload, len);
    Serial.write(crc8(payload, len));
}

void sendInfo(const char* msg) {
    sendFrame('I', (const uint8_t*)msg, strlen(msg));
}

// Also include RSSI/SNR with received frames
struct __attribute__((packed)) RxMeta {
    int16_t rssi;
    int16_t snr_x10;  // SNR * 10, so 7.5 dB = 75
};

void sendRxFrame(const uint8_t* pkt, uint16_t len, int16_t rssi, float snr) {
    uint8_t buf[sizeof(RxMeta) + MAX_PKT_SIZE];
    RxMeta meta = { rssi, (int16_t)(snr * 10) };
    memcpy(buf, &meta, sizeof(meta));
    memcpy(buf + sizeof(meta), pkt, len);
    sendFrame('R', buf, sizeof(meta) + len);
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    int state = radio.begin(LORA_FREQ, LORA_BW, LORA_SF, LORA_CR,
                            RADIOLIB_SX126X_SYNC_WORD_PRIVATE, LORA_POWER);
    if (state != RADIOLIB_ERR_NONE) {
        char err[32];
        snprintf(err, sizeof(err), "lora_init:%d", state);
        sendInfo(err);
        return;
    }
    
    radio.setDio1Action(setRxFlag);
    radio.startReceive();
    sendInfo("READY");
}

// Serial RX state machine (parses incoming SEND frames from Pi)
enum RxState { WAIT_S1, WAIT_S2, READ_TYPE, READ_LEN_LO, READ_LEN_HI, READ_PAYLOAD, READ_CRC };
RxState serialState = WAIT_S1;
uint8_t serialType;
uint16_t serialLen;
uint16_t serialRead;
uint8_t serialBuf[MAX_PKT_SIZE];

void processSerialByte(uint8_t b) {
    switch (serialState) {
        case WAIT_S1:
            if (b == FRAME_START_1) serialState = WAIT_S2;
            break;
        case WAIT_S2:
            serialState = (b == FRAME_START_2) ? READ_TYPE : WAIT_S1;
            break;
        case READ_TYPE:
            serialType = b; serialState = READ_LEN_LO;
            break;
        case READ_LEN_LO:
            serialLen = b; serialState = READ_LEN_HI;
            break;
        case READ_LEN_HI:
            serialLen |= (b << 8);
            if (serialLen > MAX_PKT_SIZE) { serialState = WAIT_S1; break; }
            serialRead = 0;
            serialState = (serialLen == 0) ? READ_CRC : READ_PAYLOAD;
            break;
        case READ_PAYLOAD:
            serialBuf[serialRead++] = b;
            if (serialRead >= serialLen) serialState = READ_CRC;
            break;
        case READ_CRC:
            if (b == crc8(serialBuf, serialLen)) {
                if (serialType == 'S') {
                    radio.clearDio1Action();
                    radio.standby();
                    int s = radio.transmit(serialBuf, serialLen);
                    radio.setDio1Action(setRxFlag);
                    radio.startReceive();
                    if (s == RADIOLIB_ERR_NONE) txCount++;
                }
            }
            serialState = WAIT_S1;
            break;
    }
}

void loop() {
    if (rxFlag) {
        rxFlag = false;
        size_t len = radio.getPacketLength();
        if (len > 0 && len <= MAX_PKT_SIZE) {
            int state = radio.readData(rxBuf, len);
            radio.startReceive();
            if (state == RADIOLIB_ERR_NONE) {
                rxCount++;
                sendRxFrame(rxBuf, len, (int16_t)radio.getRSSI(), radio.getSNR());
            }
        } else {
            radio.startReceive();
        }
    }
    
    while (Serial.available()) {
        processSerialByte(Serial.read());
    }
}
