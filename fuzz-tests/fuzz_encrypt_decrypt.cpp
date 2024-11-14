#include <assert.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <fstream>
#include <iostream>
#include <string.h>
#include <filesystem>

extern "C" {
  #include "config.h"
  #include "libcrypt.h"
  #include "libchecksum.h"
  #include "libutils.h"
}

// One-time initialization tasks
FUZZ_TEST_SETUP() {
  // No specific one-time setup required for this fuzz test
}

// Entry point for the fuzzing harness
FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider
  FuzzedDataProvider fdp(data, size);
  std::string password = fdp.ConsumeBytesAsString(fdp.ConsumeIntegralInRange(0, 512));
  std::string unencrypted_file_name = fdp.ConsumeBytesAsString(fdp.ConsumeIntegralInRange(0, 100));
  std::string encrypted_file_name = fdp.ConsumeBytesAsString(fdp.ConsumeIntegralInRange(0, 100));

  std::fstream myFile;
  myFile.open(unencrypted_file_name, std::ios::out);

  if (!myFile) {
      return;
  }

  myFile << fdp.ConsumeRemainingBytesAsString() << std::endl;
  myFile.close();


  encrypt_file(password.c_str(), unencrypted_file_name.c_str(), encrypted_file_name.c_str());
  decrypt_file(password.c_str(), encrypted_file_name.c_str(), NULL);

}
