#include <Arduino.h>
#include "helpers.h"
#include "sequence.h"
#include "radio.h"
#include "timer.h"

#define VERSION_MAJOR 0x01
#define VERSION_MINOR 0x03

#define SERIAL_BAUDRATE 115200 // UART baudrate
#define GLOBAL_TIMER_NUMBER (1)

#define DEFAULT_ADV_ACCESS_ADDR 0x8E89BED6 // Default Access Address for advertiment channels (37-39)
#define DEFAULT_ADV_CRC_INIT 0x555555
#define DEFAULT_INITIAL_CHANNEL 37
#define MAX_PKT_RETRIES 5 // Maximum times to retry a packet if ack handling is enabled
#define MAX_REQUEST_TIME 2000
#define MAX_PKTS_IN 12 // Maximum packets in the queue
#define HEAD_PADDING 5

#define LED_RED 12   // D22 -> P0.12
#define LED_GREEN 13 // D22 -> P1.09
#define LED_BLUE 22  // D22 -> P0.12
#define BSP_SELF_PINRESET_PIN NRF_GPIO_PIN_MAP(0, 19)
#define CHANNEL_LED NRF_GPIO_PIN_MAP(0, 6)
// Macros
#define led_ON(pin) digitalWrite(pin, 0)
#define led_OFF(pin) digitalWrite(pin, 1)

// ENUMs
enum SERIAL_COMMANDS
{
  CMD_DATA = 0xA7,                  // Used to receive or send packets in any radio channel
  CMD_DATA_TX = 0xBB,               // Used to receive empty pdus that were automatically transmitted
  CMD_JAMMING = 0x66,               // Enable or disable advertisement channels jamming (No device nearby can be discovered)
  CMD_FIFO_FULL = 0xA1,             // Indicates when tranmission data FIFO is full
  CMD_CHECKSUM_ERROR = 0xA8,        // Indicates serial reception error.
  CMD_CONFIG_AUTO_EMPTY_PDU = 0xA9, // Enable auto empty PDU response during connections (enabled by default)
  CMD_CONFIG_ACK = 0xAA,            // Enable handling of SN and NESN and auto retransmission
  CMD_CONFIG_LOG_TX = 0xCC,         // Enable handling of SN and NESN and auto retransmission
  CMD_BOOTLOADER_SEQ1 = 0xA6,       // Command to reset board in bootloader (sequence 1/2)
  CMD_BOOTLOADER_SEQ2 = 0xC7,       // Command to reset board in bootloader (sequence 2/2)
  CMD_LOG = 0x7F                    // Print logs through python driver library
};

enum BLE_ADV_TYPES
{
  //  Advertising channel PDU Header’s PDU Type field encoding
  BLE_ADV_IND = 0x00,           // Not used
  BLE_ADV_DIRECT_IND = 0x01,    // Not used
  BLE_ADV_NONCONN_IND = 0x02,   // Not used
  BLE_ADV_SCAN_REQUEST = 0x03,  // Used
  BLE_ADV_SCAN_RESPONSE = 0x04, // Not used
  BLE_ADV_CONNECT_REQ = 0x05,   // Used
  BLE_ADV_SCAN_IND = 0x06,      // Not used
};

enum BLE_DATA_LLID_TYPES
{
  //  LLIDs of data frames
  LL_DATA_PDU_FRAGMENT = 0x01, // Used (only to send empty PDUs)
  LL_DATA_PDU_START = 0x02,    // Not used
  LL_CONTROL_PDU = 0x03,       // Used
};

enum BLE_DATA_CONTROL_TYPES
{
  //  Opcodes of control LLID data PDUs
  LL_CONNECTION_UPDATE_REQ = 0x00, // Used
  LL_CHANNEL_MAP_REQ = 0x01,       // Used
  LL_TERMINATE_IND = 0x02,         // Not used
  LL_ENC_REQ = 0x03,               // Not used
  LL_ENC_RSP = 0x04,               // Not used
  LL_START_ENC_REQ = 0x05,         // Not used
  LL_START_ENC_RSP = 0x06,         // Not used
};

// Variables
uint8_t *rx_buffer;
uint8_t *tx_buffer;
uint8_t *current_tx_buffer = nullptr;
// Radio variables
uint8_t radio_channel;
uint32_t radio_access_address;
uint32_t radio_crc_init;
volatile uint8_t radio_data_mode = 0;            // Enable data channel hopping
volatile uint8_t radio_connection_requested = 0; // Notify when a connection is requested

uint8_t radio_data_enable_ack_flags = 1;      // Handle data header flags for SN and NESN and auto retransmission
uint8_t radio_data_enable_auto_empty_pdu = 1; // Auto send empty pdu during each connection event
uint8_t radio_data_tx_log_enable = 0;         // Log transmitted data back (useful to check what sn/nesn is used)
uint8_t radio_data_SN = 0;                    // Sequence Number (Master updates)
uint8_t radio_data_NESN = 0;                  // Next Expected Sequence Number (Slave computes)
// Connection flags
volatile uint8_t wait_end_of_conn_req = 0; // Indicate when to initiate connection window
volatile uint8_t data_to_send = 0;
volatile uint8_t data_to_send_retries = 0;
volatile uint16_t connEventCount = 0;
volatile uint8_t connection_update_requested = 0;
volatile uint8_t channel_update_requested = 0;
volatile uint32_t connetion_last_time;
volatile uint8_t packet_transmitted = 0;
SequenceGenerator channel_sequence;

// Variables for adv requests
uint8_t wait_buffer[16];
volatile uint8_t wait_buffer_len = 0;
volatile uint8_t wait_buffer_offset;
volatile uint8_t transmitting = 0;
volatile uint8_t packet_received = 0;
volatile uint8_t packet_received_size = 0;

// Modes
volatile uint8_t enable_jamming = 0;

// Empty PDU packet used to ACKs
uint8_t pkt_empty_pdu[] = {0x00, 0x00, 0x00, 0x00, 0xd, 0x0, 0x00, 0x00, 0x00};

// Misc
uint8_t log_buffer[32];
volatile uint8_t led_status = 1;

struct __attribute__((packed)) ble_packets_structure
{
  uint16_t size[MAX_PKTS_IN];
  uint8_t *pkt_buffer[MAX_PKTS_IN];
  uint8_t idx = 0;
} ble_packets;

// Main structure used during connection Master <-> Slave connection
// Received when BLE_ADV_CONNECT_REQ PDU is receiveed via serial
struct __attribute__((packed)) connection_parameters
{
  uint32_t access_address;
  uint32_t crc_init : 24;
  uint8_t window_size;
  uint16_t window_offset;
  uint16_t interval;
  uint16_t latency;
  uint16_t timeout; // Supervision Timeout not taken into account
  uint8_t channel_map[5];
  uint8_t hop_increment : 5;
  uint8_t sca : 3; // SCA - Sleep clock accuracy not taken into account
} connection;

struct __attribute__((packed)) connection_update_parameters
{
  uint8_t window_size;
  uint16_t window_offset;
  uint16_t interval;
  uint16_t latency;
  uint16_t timeout;
  uint16_t instant; // instant is compared with connEventCount if a connection update is sent
} connection_update;

struct __attribute__((packed)) channel_update_parameters
{
  uint8_t channel_map[5];
  uint16_t instant;
} channel_update;

/**
 * wait_bytes_in_radio
 * 
 * Answer a frame after certain bytes contained within the sent packet
 **/

void wait_bytes_in_radio(uint8_t *buffer, uint8_t src_offset, uint8_t dst_offset, uint8_t len)
{
  for (uint8_t i = 0; i < len; i++)
  {
    wait_buffer[i] = buffer[i + src_offset];
  }

  wait_buffer_offset = dst_offset;
  wait_buffer_len = len;
}

uint8_t check_bytes_in_radio()
{

  if (wait_buffer_len)
  {
    uint8_t len = wait_buffer_len;

    for (uint8_t i = 0; i < len; i++)
    {
      if (wait_buffer[i] != rx_buffer[i + wait_buffer_offset])
        return 0;
    }
    wait_buffer_len = 0;
    led_OFF(LED_BLUE);
    return 1;
  }
  return 0;
}

/* Serial low level functions */

void uart_write_data(uint8_t *src_array, uint16_t src_len)
{
  uint8_t checksum = 0;
  uint16_t i;

  src_array -= HEAD_PADDING; // for cmd + length
  src_array[0] = CMD_DATA;
  src_array[1] = src_len & 0xFF;
  src_array[2] = src_len >> 8;
  src_array[3] = connEventCount;
  src_array[4] = connEventCount >> 8;
  src_array += HEAD_PADDING;

  for (i = 0; i < src_len; i++)
  {
    checksum += src_array[i];
  }
  src_array[i] = checksum;
  Serial.write(src_array - HEAD_PADDING, HEAD_PADDING + src_len + 1);
}

void uart_write_data_tx(uint8_t *src_array, uint16_t src_len)
{
  uint8_t checksum = 0;
  uint16_t i;

  src_array -= HEAD_PADDING; // for cmd + length
  src_array[0] = CMD_DATA_TX;
  src_array[1] = src_len & 0xFF;
  src_array[2] = src_len >> 8;
  src_array[3] = connEventCount;
  src_array[4] = connEventCount >> 8;
  src_array += HEAD_PADDING;

  for (i = 0; i < src_len; i++)
  {
    checksum += src_array[i];
  }
  src_array[i] = checksum;
  Serial.write(src_array - HEAD_PADDING, HEAD_PADDING + src_len + 1);
}

void uart_log(String str)
{
  uint16_t len = str.length();
  log_buffer[0] = CMD_LOG;
  log_buffer[1] = len & 0xFF;
  log_buffer[2] = len >> 8;

  Serial.write(log_buffer, 3);
  Serial.print(str);
}

void change_adv_channel()
{
  // Don't change adv channel in data mode

  if (transmitting == 0)
  {
    nrf_gpio_pin_write(CHANNEL_LED, led_status);
    led_status = !led_status;

    radio_channel += 1;
    if (radio_channel > 39)
    {
      radio_channel = DEFAULT_INITIAL_CHANNEL;
    }

    radio_set_sniff(radio_channel, radio_access_address);
  }
}

void change_data_channel()
{
  current_tx_buffer = nullptr;
  uint32_t conn_interval;
  uint8_t instant_reached = 0;

  // Increment channel based on the hop interval

  if (connection_update_requested && (connEventCount == connection_update.instant))
  {
    connection_update_requested = 0;
    connection.interval = connection_update.interval;
    connection.window_offset = connection_update.window_offset;
    connection.timeout = connection.timeout;
    instant_reached = 1;
  }

  if (channel_update_requested && (connEventCount == channel_update.instant))
  {
    channel_update_requested = 0;
    memcpy((void *)connection.channel_map, (void *)channel_update.channel_map, 5);
    channel_sequence.updateChannelMap(connection.channel_map);
  }

  // Change connection interval dependending if this is a connection event or instant
  if (!instant_reached)
    conn_interval = connection.interval * 1250; // Normal connection event
  else
    conn_interval = (connection.window_offset * 1250) + 1250; // Instant (from connection or channel map update)

  // Update timing with the connection interval value or window offset during connection or channel map update
  if (conn_interval)
  {
    update_timer(conn_interval);
  }
  else
    update_timer(connection.interval * 1250);

  // Send BLE Empty PDU packet or data packet
  // Packet is sent only on normal connection event
  if ((!instant_reached) || (instant_reached && (conn_interval == 0)))
  {
    connEventCount += 1; // Increment event counter
    radio_channel = channel_sequence.getNextChannel();

    // Send data on every connection event
    if (data_to_send)
    {
      current_tx_buffer = tx_buffer;
      if (radio_data_enable_ack_flags)
      {
        if (data_to_send_retries <= MAX_PKT_RETRIES)
        {
          data_to_send_retries++;
        }
        else
        {
          data_to_send_retries = 0;
          data_to_send = 0;
        }
      }
    }
    // If no data to send, send empty PDU instead
    else if (radio_data_enable_auto_empty_pdu)
    {
      current_tx_buffer = pkt_empty_pdu + 4; // Skip access address
    }

    if (current_tx_buffer) // Do not send anything if empty pdu is to be sent, but radio_data_enable_auto_empty_pdu is 0
    {

      if (radio_data_enable_ack_flags)
      {
        // Update SN and NESN flags (enabled by default)
        bitWrite(current_tx_buffer[0], 3, radio_data_SN);
        bitWrite(current_tx_buffer[0], 2, radio_data_NESN);
      }
      else
      {
        data_to_send = 0;
      }

      transmitting = 1; // This indicates the radio interrupt that we are going to transmit something
      radio_send_custom(current_tx_buffer, radio_channel, connection.access_address, connection.crc_init);
      packet_transmitted = 1; // Flag to indicate we have transmitted a data or empty pdu
    }
  }

  nrf_gpio_pin_write(CHANNEL_LED, led_status);
  led_status = !led_status;
}

/**
 * nRF51822 RADIO handler.
 *
 * This handler is called whenever a RADIO event occurs (IRQ).
 **/

extern "C" void RADIO_IRQHandler(void)
{

  if (NRF_RADIO->EVENTS_READY)
  {
    NRF_RADIO->EVENTS_READY = 0;
    NRF_RADIO->TASKS_START = 1;
  }

  if (NRF_RADIO->EVENTS_END)
  {
    NRF_RADIO->EVENTS_END = 0;

    if (transmitting)
    {
      transmitting = 0;
      if (wait_end_of_conn_req) // After end of transmitted packet, schedule a connection window
      {
        // TODO: move this function to radio_connection_requested condition
        wait_end_of_conn_req = 0;
        radio_data_mode = 1;
        start_timer(change_data_channel, (connection.window_offset * 1250) + 1250 + 300);
        // Prepare channel sequence generator to follow connection
        connEventCount = 0; // event count is cleared, this is necessary to keep track of connection and channel map updates
        // TODO: flexible control over SN and NESN
        // radio_data_SN = 0;   // Reset SN
        // radio_data_NESN = 0; // Reset NESN
        radio_access_address = connection.access_address;
        radio_crc_init = connection.crc_init;
        channel_sequence.initialize(connection.channel_map);
        channel_sequence.setHopIncrement(connection.hop_increment);
        channel_sequence.resetConnection();
      }
      // uart_log("tx_to_rx");
      radio_tx_to_rx();
      return;
    }

    NRF_RADIO->TASKS_START = 1;
    // If CRC is valid
    if (NRF_RADIO->CRCSTATUS)
    {

      if (check_bytes_in_radio())
      {
        delayMicroseconds(90); // Aproximatelly 150us
        transmitting = 1;
        radio_send_custom(tx_buffer, radio_channel, radio_access_address, radio_crc_init);
        // packet_transmitted = 1;
        if (radio_connection_requested == 1) // if data mode is enabled, data channel hopping is scheduled as bellow
        {
          radio_connection_requested = 0;
          wait_end_of_conn_req = 1;
          stop_timer();
        }
      }

      // access address (4B) + header (2B) + payload (rx_buffer[1]B)
      uint16_t sz = ((rx_buffer[1] & 0b11111111) + 2);
      if (sz > 255)
      {
        return;
      }
      uint32_t crc = NRF_RADIO->RXCRC;
      // Adding crc to the end of RX buffer.
      rx_buffer[sz] = crc;
      rx_buffer[sz + 1] = crc >> 8;
      rx_buffer[sz + 2] = crc >> 16;
      sz += 4 + 3; // Access Address (4 Bytes) + CRC (3 Bytes)
      packet_received_size = sz;

      if (radio_data_mode && radio_data_enable_ack_flags)
      {

        // For data packets, read current SN and NESN flags
        uint8_t received_NESN = bitRead(rx_buffer[0], 2);
        if (received_NESN == radio_data_NESN) // Ignore duplicated packets
          return;
        data_to_send = 0;
        radio_data_NESN = received_NESN;
        radio_data_SN = radio_data_NESN;
      }

      if (radio_data_mode)
      {
        connetion_last_time = millis();
        led_ON(LED_GREEN);
      }

      packet_received = 1; // Flag to indicate when to send received packet through USB
    }
  }
}

void start_scanning(void)
{
  /* Sniffer is idling. */
  stop_timer();
  radio_data_mode = 0; // Disable data mode

  radio_access_address = DEFAULT_ADV_ACCESS_ADDR;
  radio_crc_init = DEFAULT_ADV_CRC_INIT;
  radio_channel = DEFAULT_INITIAL_CHANNEL;
  /* Start sniffing BLE packets on channel 37. */
  radio_set_sniff(radio_channel, radio_access_address);

  // Start scheduling advertisement channel changing (37-39)
  start_timer(change_adv_channel, 250000UL);

  led_OFF(LED_GREEN);
  led_OFF(LED_RED);
  led_OFF(LED_BLUE);
}

void handle_adv_pkt()
{
  uint8_t pdu_type = tx_buffer[0] & 0x0F;

  if (radio_data_mode)
  {
    radio_data_mode = 0;
    data_to_send = 0;
    start_scanning();
  }

  if (pdu_type == BLE_ADV_SCAN_REQUEST)
  {
    // Source Offset to compare: header (2B) + scanning addr (6B) = 8 (advertising addr)
    // Receiver packet Offset to compare: header (2B) = 2 (advertising addr)

    wait_bytes_in_radio(tx_buffer, 8, 2, 6); // Wait a packet from the target advertising address
    // uint8_t x[6] = {0xaa, 0x4b, 0xe1, 0xb4, 0x16, 0xd0};
    // wait_bytes_in_radio(x, 0, 2, 6); // Wait a packet from the target advertising address

    led_ON(LED_BLUE);
  }
  else if (pdu_type == BLE_ADV_CONNECT_REQ)
  {
    stop_timer();
    memcpy((void *)&connection, (void *)&tx_buffer[14], 22);

    wait_bytes_in_radio(tx_buffer, 8, 2, 6); // Wait a packet from the target advertising address
    if (connection.interval)
    {
      radio_connection_requested = 1; // Enable data mode (channel hopping will begin once after connect request is sent to the link slave)
      connetion_last_time = millis();
      led_ON(LED_BLUE);
    }
  }
  else
  {
    // transmitting = 1;
    // radio_send_custom(tx_buffer, radio_channel, radio_access_address, radio_crc_init);
    // TODO: allow packets to be sent immediatelly on adv. channel
    wait_bytes_in_radio(tx_buffer, 8, 2, 6);
    led_ON(LED_BLUE);
  }
}

void handle_data_pkt()
{
  uint8_t llid = tx_buffer[0] & 0x03;
  if (llid == LL_CONTROL_PDU)
  {
    uint8_t opcode = tx_buffer[2];
    // TODO: Place checks here to not handle invalid connection or channel map updates (used to verify if other device process them)
    switch (opcode)
    {
    case LL_CONNECTION_UPDATE_REQ:
      memcpy((void *)(&connection_update), (void *)(&tx_buffer[3]), 11); // Copy the parameters to connection_update
      connection_update_requested = 1;
      break;
    case LL_CHANNEL_MAP_REQ:
      memcpy((void *)&channel_update, (void *)&tx_buffer[3], 7); // Copy the parameters to channel_update
      channel_update_requested = 1;
      break;
    }
  }
  if (radio_data_mode) // Wait to send data packets only when radio is connected
  {
    data_to_send = 1;
    data_to_send_retries = 0;
  }
  else // Send packets immediately
  {
    // TODO: Check if this works correctly
    // transmitting = 1;
    // radio_send_custom(tx_buffer, radio_channel, radio_access_address, radio_crc_init);
  }
}

void setup()
{

  // Must configure Serial rts/cts for Nordic board
  pinMode(LED_RED, OUTPUT);
  pinMode(LED_GREEN, OUTPUT);
  pinMode(LED_BLUE, OUTPUT);
  led_OFF(LED_RED);
  led_OFF(LED_GREEN);
  led_OFF(LED_BLUE);

  // Configure P019, reset tied pin
  nrf_gpio_cfg_output(BSP_SELF_PINRESET_PIN);
  nrf_gpio_pin_set(BSP_SELF_PINRESET_PIN);

  // Configure channel indication LED
  nrf_gpio_cfg_output(CHANNEL_LED);
  nrf_gpio_pin_set(CHANNEL_LED);

  // Start global ms timer
  // timer.attachInterrupt(&global_timer_IRQ, 1000UL); // microseconds

  Serial.begin(SERIAL_BAUDRATE);
  Serial.setTimeout(10);

  // Initialize rx and tx buffer
  rx_buffer = (uint8_t *)malloc(260 + 3 + 4);
  rx_buffer += HEAD_PADDING + 4; // 5 + 4 bytes padding (uart header + access address)
  tx_buffer = (uint8_t *)malloc(260 + 3 + 4);
  tx_buffer += HEAD_PADDING + 4; // 5 + 4 bytes padding (uart header + access address)

  /* Put Radio in scanning mode */
  start_scanning();

  /* Process serial inquiries. */
}

void loop()
{
  uint8_t cmd;
  uint16_t cmd_len;
  uint8_t checksum;
  uint8_t *work_buffer;

  if (NRF_RADIO->EVENTS_READY)
  {
    NRF_RADIO->EVENTS_READY = 0;
    // NRF_RADIO->TASKS_START;
  }

  if (radio_data_tx_log_enable && packet_transmitted)
  {
    packet_transmitted = 0;
    uint8_t *p_buf = current_tx_buffer;

    if (p_buf == pkt_empty_pdu + 4) // If current_tx_buffer is not pointing to tx_buffer
    {
      *((uint32_t *)(p_buf - 4)) = radio_access_address; // Write access address
    }

    uint8_t tx_len = 4 + 2 + p_buf[1] + 3; // Access Address + header + pkt + crc
    // Adding crc to the end of TX buffer.
    uart_write_data_tx(p_buf - 4, tx_len); // Send transmitted packet via USB Serial
  }

  // If a packet is received in Radio Interrupt
  if (packet_received)
  {
    packet_received = 0;
    uart_write_data(rx_buffer - 4, packet_received_size); // Send packets via USB Serial
  }

  if (radio_data_mode)
  {
    uint32_t time = millis();
    if (time - connetion_last_time > (connection.timeout * 10))
    {
      led_OFF(LED_GREEN);
      led_ON(LED_RED);
    }
  }

  while (ble_packets.idx && !data_to_send && !transmitting)
  {
    memcpy(tx_buffer - 4, ble_packets.pkt_buffer[0], ble_packets.size[0] + 4); // Copy also access address to offset -4
    free(ble_packets.pkt_buffer[0]);
    // Shift all buffer pointers toward index 0
    for (uint8_t i = 0; i < ble_packets.idx - 1; i++)
    {
      ble_packets.pkt_buffer[i] = ble_packets.pkt_buffer[i + 1];
      ble_packets.size[i] = ble_packets.size[i + 1];
    }

    // Get a pointer to tx_buffer, but 4 positions earlier to get access address (aa)
    uint32_t *aa = (uint32_t *)(tx_buffer - 4);

    if (*aa == DEFAULT_ADV_ACCESS_ADDR)
      handle_adv_pkt(); // Handler adv packet according to PDU Type
    else
      handle_data_pkt();

    ble_packets.idx--;
  }

  while (Serial.available()) // If computer sent packet via USB Serial
  {
    cmd = Serial.read();

    switch (cmd) // Check first byte for command
    {
    case CMD_DATA: // All data commands is to be sent via BLE Radio
      if (enable_jamming)
        continue;
      Serial.readBytes((uint8_t *)&cmd_len, 2); // Get data length

      if (cmd_len < 270)
      {
        uint8_t *work_buffer = (uint8_t *)malloc(4 + cmd_len + 1); // Get aa (4B) + data (tx_buffer) + Checksum (1B)
        Serial.readBytes(work_buffer, cmd_len + 1);

        // Calculate checksum
        checksum = 0;
        for (int16_t i = 0; i < cmd_len; i++)
        {
          checksum += work_buffer[i];
        }
        // Verify received checksum against calculated checksum
        if (checksum == work_buffer[cmd_len])
        {
          if (ble_packets.idx <= MAX_PKTS_IN)
          {
            ble_packets.size[ble_packets.idx] = cmd_len;
            ble_packets.pkt_buffer[ble_packets.idx] = work_buffer;
            ble_packets.idx = ble_packets.idx + 1;
          }
          else
          {
            free(work_buffer);
            Serial.write(CMD_FIFO_FULL);
          }
        }
        else
        {
          // If a error is received, send a checksum error so the host can retransmit the packet;
          free(work_buffer);
          Serial.write(CMD_CHECKSUM_ERROR);
        }
      }
      break;
    case CMD_JAMMING: // WIP jamming feature
      uint8_t value;
      Serial.readBytes(&value, 1);
      if (value && !enable_jamming)
      {
        stop_timer();

        enable_jamming = 1;
        transmitting = 0;
        radio_data_mode = 0;
        data_to_send = 0;
        connection_update_requested = 0;
        channel_update_requested = 0;
        radio_connection_requested = 0;

        led_ON(LED_BLUE);
        led_ON(LED_RED);
        led_OFF(LED_GREEN);
        led_OFF(LED_CONN);
        // Empty queue of packets to be transmitted
        for (uint8_t i = 0; i < ble_packets.idx; i++)
        {
          free(ble_packets.pkt_buffer[i]);
        }
        ble_packets.idx = 0;
      }
      else if (!value && enable_jamming) // Only disable jamming once
      {
        enable_jamming = 0;
        transmitting = 0;
        NRF_RADIO->EVENTS_READY = 0;
        NRF_RADIO->EVENTS_END = 0;
        NRF_RADIO->TASKS_START = 0;
        data_to_send = 0;

        start_scanning();
      }

      break;
    case CMD_CONFIG_AUTO_EMPTY_PDU:
      Serial.readBytes(&radio_data_enable_auto_empty_pdu, 1);
      break;
    case CMD_CONFIG_ACK:
      Serial.readBytes(&radio_data_enable_ack_flags, 1);
      break;
    case CMD_CONFIG_LOG_TX:
      Serial.readBytes(&radio_data_tx_log_enable, 1);
      break;
    // Put the board in Bootloader mode
    case CMD_BOOTLOADER_SEQ1: // Bootloader sequence commands reboot the device in bootloader mode
      uint8_t seq;
      Serial.readBytes(&seq, 1);
      if (seq == CMD_BOOTLOADER_SEQ2)
        nrf_gpio_pin_clear(BSP_SELF_PINRESET_PIN); // Reset MCU in Bootloader
      break;
    }
  }

  if (enable_jamming && !transmitting) // Jamm advertisement channels
  {
    tx_buffer = pkt_empty_pdu + 4;
    transmitting = 1;
    radio_send_custom(tx_buffer, radio_channel, radio_access_address, radio_crc_init);
    (radio_channel >= 39 ? radio_channel = DEFAULT_INITIAL_CHANNEL : radio_channel += 1);
  }

  __SEV();
  __WFE();
}
