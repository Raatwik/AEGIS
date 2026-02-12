#include <iostream>
#include <string>
#include <vector>

int main() {
    // 1. Handshake with Python
    std::cout << "AEGIS_CORE_READY" << std::endl;

    std::string line;
    while (std::getline(std::cin, line)) {
        // Logic: Python sends "RATE:5|ENTROPY:7.2|TRAP:0"
        // We just log it and acknowledge.
        // In a real version, C++ would handle kernel-level blocking here.
        
        // Simple heuristic check for logging
        if (line.find("TRAP:1") != std::string::npos) {
             std::cout << "CRITICAL_THREAT_DETECTED" << std::endl;
        } else {
             std::cout << "ACK" << std::endl;
        }
    }
    return 0;
}