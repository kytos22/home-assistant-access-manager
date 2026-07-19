#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

#include "esphome/core/log.h"
#include "esphome/core/preferences.h"

class FingerprintNameStore {
 public:
  static constexpr int MIN_SLOT = 1;
  static constexpr int MAX_SLOT = 50;
  static constexpr size_t MAX_NAME_BYTES = 48;
  static constexpr size_t MAX_FINGER_BYTES = 24;

  struct Identity {
    std::string name;
    std::string finger;
    bool valid() const { return !name.empty(); }
  };

  static FingerprintNameStore &instance() {
    static FingerprintNameStore store;
    return store;
  }

  bool set(int slot, const std::string &name, const std::string &finger) {
    if (!valid_slot_(slot) || name.empty()) return false;
    Record record{};
    record.version = RECORD_VERSION;
    const size_t name_length = std::min(name.size(), MAX_NAME_BYTES);
    std::memcpy(record.name, name.data(), name_length);
    record.name[name_length] = '\0';
    const size_t finger_length = std::min(finger.size(), MAX_FINGER_BYTES);
    std::memcpy(record.finger, finger.data(), finger_length);
    record.finger[finger_length] = '\0';
    return preference_(slot).save(&record);
  }

  Identity get(int slot) const {
    if (!valid_slot_(slot)) return {};
    Record record{};
    if (!preference_(slot).load(&record) || record.version != RECORD_VERSION) return {};
    record.name[MAX_NAME_BYTES] = '\0';
    record.finger[MAX_FINGER_BYTES] = '\0';
    return {std::string(record.name), std::string(record.finger)};
  }

  static std::string finger_label(const std::string &finger) {
    if (finger == "left_thumb") return "Left thumb";
    if (finger == "left_index") return "Left index";
    if (finger == "left_middle") return "Left middle";
    if (finger == "left_ring") return "Left ring";
    if (finger == "left_pinky") return "Left little finger";
    if (finger == "right_thumb") return "Right thumb";
    if (finger == "right_index") return "Right index";
    if (finger == "right_middle") return "Right middle";
    if (finger == "right_ring") return "Right ring";
    if (finger == "right_pinky") return "Right little finger";
    return "";
  }

  bool erase(int slot) {
    if (!valid_slot_(slot)) return false;
    Record record{};
    record.version = RECORD_VERSION;
    return preference_(slot).save(&record);
  }

  void clear() {
    for (int slot = MIN_SLOT; slot <= MAX_SLOT; slot++) erase(slot);
  }

 private:
  struct Record {
    uint8_t version;
    char name[MAX_NAME_BYTES + 1];
    char finger[MAX_FINGER_BYTES + 1];
  };

  static constexpr uint8_t RECORD_VERSION = 2;
  static constexpr uint32_t PREFERENCE_KEY = 0x46504E00;
  static bool valid_slot_(int slot) { return slot >= MIN_SLOT && slot <= MAX_SLOT; }
  static esphome::ESPPreferenceObject preference_(int slot) {
    return esphome::global_preferences->make_preference<Record>(PREFERENCE_KEY ^ slot);
  }
};
