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

static const std::filesystem::path TEST_OUTPUT_DIR = "test-output";
// One-time initialization tasks
FUZZ_TEST_SETUP() {
  if (!std::filesystem::exists(TEST_OUTPUT_DIR)) {
      // Directory does not exist, create it
      if (!std::filesystem::create_directory(TEST_OUTPUT_DIR)) {
          std::cerr << "Test dir did not exist and failed to create it. Dir was supposed to be: " << TEST_OUTPUT_DIR<<std::endl;
      }
  }
}

void deleteFile(const char* fileToDelete) {
  try {
    if (!std::filesystem::remove(fileToDelete))
      std::cerr << "Did not find file to delete: " << fileToDelete<<std::endl;

  }
  catch(const std::filesystem::filesystem_error& err) {
     std::cout << "Filesystem error deleting file: " << err.what() << '\n';
  }
}

// Entry point for the fuzzing harness
FUZZ_TEST(const uint8_t *data, size_t size) {
  // Initialize FuzzedDataProvider // Directory does not exist, create it
  FuzzedDataProvider fdp(data, size);
  std::string password = fdp.ConsumeBytesAsString(fdp.ConsumeIntegralInRange(0, 512));
  std::string unencrypted_file_name = fdp.ConsumeBytesAsString(fdp.ConsumeIntegralInRange(0, 100));
  std::string encrypted_file_name = fdp.ConsumeBytesAsString(fdp.ConsumeIntegralInRange(0, 100));
  char* re_unencrypted_file_full_path;

  // std::string unencrypted_file_name = "unencrypted_file_name";
  // std::string encrypted_file_name = "encrypted_file_name";

  std::filesystem::path unencrypted_file_full_path = TEST_OUTPUT_DIR / unencrypted_file_name;
  std::filesystem::path encrypted_file_full_path = TEST_OUTPUT_DIR /  encrypted_file_name;

  // std::cerr << "Unencrypted file name: " << unencrypted_file_full_path<<std::endl;
  // std::cerr << "Encrypted file name: " << encrypted_file_full_path<<std::endl;
  std::fstream myFile;
  myFile.open(unencrypted_file_full_path, std::ios::out);

  if (!myFile) {
      return;
  }

  myFile << fdp.ConsumeRemainingBytesAsString() << std::endl;
  myFile.close();

  myFile.open(encrypted_file_full_path, std::ios::out);

  if (!myFile) {
      return;
  }
  myFile.close();


  encrypt_file(password.c_str(), unencrypted_file_full_path.c_str(), encrypted_file_name.c_str());
  decrypt_file(password.c_str(), encrypted_file_full_path.c_str(), re_unencrypted_file_full_path);

  deleteFile(unencrypted_file_full_path.c_str());  
  deleteFile(encrypted_file_full_path.c_str());
  //deleteFile(re_unencrypted_file_full_path);
}


