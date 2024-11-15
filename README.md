# JLock-Encryption-Fuzzing

Fuzzing setup for JLock-Encryption project.

Fuzz test creates and deletes files that are necesary as inputs for the function to test.
The fuzzer might create files with characters that cause the deletion functions to fail. To clear up the folder afterwards run:
```sh
git clean -fdx
```

To run the fuzz test execute:
```sh
cifuzz run
```

or 

```sh
cifuzz run fuzz_encrypt_decrypt
```

to generate the code coverage you can run 
```sh
cifuzz coverage
```

or if you want to have the output in the lcov format and saved in a lcov.info file run:

```sh
cifuzz coverage -f lcov -o lcov.info
```