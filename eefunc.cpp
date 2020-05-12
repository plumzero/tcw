
#include "eefunc.h"

void* print_string(void* args)
{
    (void) args;
    char* p;
    int count = 0;
    while (1) {
        std::cout << "=========================================>" << std::endl;
        if (++count > 5) {
            free(p);
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    return nullptr;
}