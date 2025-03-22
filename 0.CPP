#include <iostream>
#include <fstream>
#include <openssl/rand.h>

int main() {
    // Define the size of the random data
    const int data_size = 1024;  // 1 KB of random data

    // Allocate a buffer to hold the random data
    unsigned char buffer[data_size];

    // Generate random bytes
    if (RAND_bytes(buffer, data_size) != 1) {
        std::cerr << "Error generating random data" << std::endl;
        return 1;
    }

    // Open the output file to write the random data
    std::ofstream outfile("testfile.bin", std::ios::binary);
    if (!outfile) {
        std::cerr << "Error opening file for writing" << std::endl;
        return 1;
    }

    // Write the random data to the file
    outfile.write(reinterpret_cast<char*>(buffer), data_size);
    
    // Close the file
    outfile.close();

    std::cout << "Test file created successfully!" << std::endl;
    
    return 0;
}
