#include <WiFi.h>
#include <esp_now.h>
#include <esp_sleep.h>

// Constants for time conversions and sleep time
#define uS_TO_S_FACTOR 1000000  
#define TIME_TO_SLEEP  52       

// Threshold distance to determine parking spot occupancy
#define MIN_DISTANCE 50.0      

// Pins for ultrasonic sensor
#define ECHO_PIN 13  
#define TRIG_PIN 12  

// MAC address for the ESP-NOW receiver
const uint8_t broadcastAddress[] = {0x8C, 0xAA, 0xB5, 0x84, 0xFB, 0x90};
esp_now_peer_info_t peerInfo;

// Callback function for ESP-NOW sending status
void on_data_send(const uint8_t *mac_addr, esp_now_send_status_t status) {
  Serial.print("Send Status: ");
  Serial.println(status == ESP_NOW_SEND_SUCCESS ? "Success" : "Failure");
}

// Initialize ultrasonic sensor pins
void setup_ultrasonic_sensor() {
  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);
}

// Initialize WiFi for ESP-NOW
void setup_wifi() {
  WiFi.mode(WIFI_STA);
  if (esp_now_init() != ESP_OK) {
    Serial.println("Error initializing ESP-NOW");
    return;
  }
  WiFi.setTxPower(WIFI_POWER_2dBm); // Optional power adjustment
}

// Register the ESP-NOW receiver peer
void register_peer() {
  memcpy(peerInfo.peer_addr, broadcastAddress, 6);
  peerInfo.channel = 0;
  peerInfo.encrypt = false;
  if (esp_now_add_peer(&peerInfo) != ESP_OK) {
    Serial.println("Failed to add peer");
    return;
  }
}

// Register the ESP-NOW sending callback
void register_hooks() {
  esp_now_register_send_cb(on_data_send);
}

// Main setup function
void setup() {
  Serial.begin(115200);
  setup_ultrasonic_sensor();
  setup_wifi();
  register_peer();
  register_hooks();

  // Timer to wake up from deep sleep
  esp_sleep_enable_timer_wakeup(TIME_TO_SLEEP * uS_TO_S_FACTOR);
  Serial.println("Setup complete, device entering loop and will sleep after each cycle.");
}

// Read distance from the ultrasonic sensor
float read_distance() {
  digitalWrite(TRIG_PIN, HIGH);
  delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);

  unsigned long duration = pulseIn(ECHO_PIN, HIGH);
  float distance = duration / 58.0;
  return distance;
}

// Print parking status and timing information
void print_results(const char *statusMessage, unsigned long reading_time, unsigned long transmission_time) {
  Serial.print("Parking Spot Status: ");
  Serial.println(statusMessage);
  Serial.println("Time spent reading the HC-SR04: " + String(reading_time));
  Serial.println("Time spent transmitting via wifi: " + String(transmission_time));
}

// Main loop function
void loop() {
  unsigned long initial_t = micros(); // Time at start of loop

  float distance = read_distance(); // Get distance from sensor
  unsigned long reading_time = micros() - initial_t; // Calculate reading time

  // Determine parking spot status based on distance
  const char* statusMessage = distance < MIN_DISTANCE ? "OCCUPIED" : "FREE";
  esp_now_send(broadcastAddress, (uint8_t *)statusMessage, strlen(statusMessage) + 1);

  unsigned long transmission_time = micros() - (initial_t + reading_time); // Calculate transmission time

  print_results(statusMessage, reading_time, transmission_time);

  Serial.println("Entering deep sleep mode");
  esp_deep_sleep_start(); // Enter deep sleep for energy saving
}
