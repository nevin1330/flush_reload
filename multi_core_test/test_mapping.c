// created by nevin
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

void *map_gnupg() {
    int fd = open("/home/ev/genkin/flush_reload/gnupg-install/bin/gpg", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return NULL;
    }
    
    void *map = mmap(NULL, 0x200000,  // Map 2MB to cover the entire binary
                    PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    return map;
}

int main() {
    void *target = map_gnupg();
    if (!target) {
        printf("Failed to map GnuPG\n");
        return 1;
    }
    
    printf("GnuPG mapped at: %p\n", target);
    printf("Target address (base + 0x81330): %p\n", target + 0x81330);
    
    // Check if the target address is within the mapped region
    size_t page_size = sysconf(_SC_PAGESIZE);
    printf("Page size: %zu bytes\n", page_size);
    printf("Mapped region: %p to %p\n", target, target + page_size);
    
    // Try to read from the target address
    unsigned char *addr = (unsigned char *)(target + 0x81330);
    printf("Attempting to read from target address...\n");
    
    // Check if address is within mapped region (now 2MB)
    if (addr >= (unsigned char *)target && addr < (unsigned char *)target + 0x200000) {
        printf("Target address is within mapped region\n");
        printf("Value at target: 0x%02x\n", *addr);
    } else {
        printf("ERROR: Target address is OUTSIDE mapped region!\n");
        printf("This will cause a segmentation fault\n");
    }
    
    munmap(target, 0x200000);
    return 0;
}
